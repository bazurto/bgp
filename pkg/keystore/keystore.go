// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type KeyType bool

const (
	PrivateKey KeyType = true
	PublicKey  KeyType = false
)

func (kt KeyType) String() string {
	if kt {
		return "private"
	}
	return "public"
}

// KeyInfo represents metadata about a key
type KeyInfo struct {
	Name    string
	Email   string
	Date    time.Time
	KeyType KeyType
	KeyID   string
	Bytes   []byte
}

func (ki *KeyInfo) String() string {
	return fmt.Sprintf("%s <%s> %s %s", ki.Name, ki.Email, ki.KeyType, ki.KeyID)
}

// Keystore manages cryptographic keys
type Keystore struct {
	Path string
}

// New creates a new keystore instance
func New(path string) *Keystore {
	return &Keystore{Path: path}
}

// EnsureExists creates the keystore directory if it doesn't exist
func (ks *Keystore) EnsureExists() error {
	return os.MkdirAll(ks.Path, 0755)
}

// LoadPrivateKey loads a private key from a PEM-encoded file, supporting both RSA and EC keys
func LoadPrivateKey(privBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(privBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	// Try parsing as PKCS#1
	if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privKey, nil
	}

	// Try parsing as PKCS#8
	privKeyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	switch key := privKeyIface.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// LoadPublicKey loads a public key from a PEM-encoded file, supporting both RSA and EC keys
func LoadPublicKey(pubBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pubBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Try parsing as PKCS#1
	if pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pubKey, nil
	}

	// Try parsing as PKIX
	pubKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := pubKeyIface.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

// PrivateKeyToBytes exports a private key to a PEM-encoded file
func PrivateKeyToBytes(key any) ([]byte, error) {
	var privBytes []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		privBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	privFile := bytes.NewBuffer(nil)
	if err := pem.Encode(privFile, privBlock); err != nil {
		return nil, fmt.Errorf("failed to write private key to file: %w", err)
	}
	return privFile.Bytes(), nil
}

// PublicKeyToBytes exports a public key to a PEM-encoded file
func PublicKeyToBytes(key any) ([]byte, error) {
	var pubBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PublicKey:
		pubBytes = x509.MarshalPKCS1PublicKey(k)
	case *ecdsa.PublicKey:
		pubBytes, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC public key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}

	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pubFile := bytes.NewBuffer(nil)
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return nil, fmt.Errorf("failed to write public key to file: %w", err)
	}
	return pubFile.Bytes(), nil
}

type Curve string

const (
	CurveNone Curve = ""
	CurveP224 Curve = "P-224"
	CurveP256 Curve = "P-256"
	CurveP384 Curve = "P-384"
	CurveP521 Curve = "P-521"
)

type Algorithm string

const (
	RSAAlgorithm Algorithm = "rsa"
	ECAlgorithm  Algorithm = "ec"
)

// GenerateKeyPair generates a new RSA or EC key pair and returns the private and public keys
func GenerateKeyPair(algorithm Algorithm, curve Curve) (any, any, error) {
	var privKey any
	var pubKey any
	var err error

	switch algorithm {
	case RSAAlgorithm:
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		pubKey = privKey.(*rsa.PrivateKey).Public()
	case ECAlgorithm:
		var ecCurve elliptic.Curve
		switch curve {
		case CurveP256:
			ecCurve = elliptic.P256()
		case CurveP384:
			ecCurve = elliptic.P384()
		case CurveP521:
			ecCurve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
		privKey, err = ecdsa.GenerateKey(ecCurve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate EC key pair: %w", err)
		}
		pubKey = privKey.(*ecdsa.PrivateKey).Public()
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return privKey, pubKey, nil
}

func GenPublicKeyFromPrivate(privKey any) (any, error) {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// GenerateKeyID generates a fingerprint for a public key
func GenerateKeyID(pubKey any) string {
	var keyBytes []byte

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		keyBytes = x509.MarshalPKCS1PublicKey(pubKey)
	case *ecdsa.PublicKey:
		keyBytes, _ = x509.MarshalPKIXPublicKey(pubKey)
	default:
		return "unknown"
	}

	hash := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", hash[:8]) // First 8 bytes as hex
}

// SaveKeyPair saves the private and public keys to files in the keystore
func (ks *Keystore) SaveKeyPair(privKey any, pubKey any, name, email string) (*KeyInfo, *KeyInfo, error) {
	if err := ks.EnsureExists(); err != nil {
		return nil, nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	pubKi := KeyInfo{
		Name:    name,
		Email:   email,
		Date:    time.Now(),
		KeyType: false,
		KeyID:   GenerateKeyID(pubKey),
		Bytes:   nil,
	}

	privKi := KeyInfo{
		Name:    name,
		Email:   email,
		Date:    time.Now(),
		KeyType: true,
		KeyID:   pubKi.KeyID,
		Bytes:   nil,
	}
	if b, err := PrivateKeyToBytes(privKey); err != nil {
		return nil, nil, fmt.Errorf("failed to export private key: %w", err)
	} else {
		privKi.Bytes = b
	}

	if b, err := PublicKeyToBytes(pubKey); err != nil {
		return nil, nil, fmt.Errorf("failed to export public key: %w", err)
	} else {
		pubKi.Bytes = b
	}

	if err := ks.writeKeyFile(privKi); err != nil {
		return nil, nil, fmt.Errorf("failed to save private key: %w", err)
	}
	if err := ks.writeKeyFile(pubKi); err != nil {
		return nil, nil, fmt.Errorf("failed to save public key: %w", err)
	}

	return &privKi, &pubKi, nil
}

// FindLatestPrivateKey finds the most recent private key for the given name/email
func (ks *Keystore) FindLatestPrivateKey(name, email string) (*KeyInfo, error) {
	return ks.GetLatestKeyForOwner(name, email, false)
}

// FindPublicKeyByRecipient finds a public key for the given recipient
func (ks *Keystore) FindPublicKeyByRecipient(recipient string) (*KeyInfo, error) {
	var key *KeyInfo
	err := ks.CollectKeyInfo(func(ki KeyInfo) error {
		if ki.KeyType == PrivateKey {
			return nil // skip private keys
		}
		if ki.Name != recipient && ki.Email != recipient {
			return nil
		}

		if key == nil {
			key = &ki
		} else {
			if key.Date.Before(ki.Date) {
				key = &ki
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if key == nil {
		return nil, fmt.Errorf("no key found for %s or <%s>", recipient, recipient)
	}

	return key, nil

}

// GetAllPrivateKeys returns all private key files in the keystore
func (ks *Keystore) GetAllPrivateKeys() ([]KeyInfo, error) {
	var keys []KeyInfo
	err := ks.CollectKeyInfo(func(ki KeyInfo) error {
		if ki.KeyType {
			keys = append(keys, ki)
		}
		return nil
	})
	return keys, err
}

func (ks *Keystore) CollectKeyInfoAll() ([]KeyInfo, error) {
	var keys []KeyInfo
	err := ks.CollectKeyInfo(func(ki KeyInfo) error {
		keys = append(keys, ki)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return keys, nil
}

// CollectKeyInfo iterates over all keys in the keystore and calls the yield function with each KeyInfo.
// If yield returns io.EOF, iteration stops.
func (ks *Keystore) CollectKeyInfo(yield func(KeyInfo) error) error {
	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			jsonKeyPath := filepath.Join(ks.Path, info.Name())
			b, err := os.ReadFile(jsonKeyPath)
			if err != nil {
				return nil // Skip unreadable files
			}
			var keyInfo KeyInfo
			if err := json.Unmarshal(b, &keyInfo); err != nil {
				return nil // Skip invalid JSON files
			}

			if err := yield(keyInfo); err != nil {
				return err // io.EOF to stop iteration
			}
		}
		return nil
	})
	return err
}

// FindKeyByID returns the filename for the given key ID, searching both public and private keys
func (ks *Keystore) FindKeyByID(keyID string, kt KeyType) (*KeyInfo, error) {
	if kt == PrivateKey {
		privateKey := filepath.Join(ks.Path, fmt.Sprintf("%s_private.json", keyID))
		return ks.readKeyFile(privateKey)
	}
	publicKey := filepath.Join(ks.Path, fmt.Sprintf("%s_public.json", keyID))
	return ks.readKeyFile(publicKey)
}

// ImportKey imports a key file (public or private) into the keystore
//
// If name or email are provided, they override the values in the key file.
// name or email are optional
func (ks *Keystore) ImportKey(keyFile, name, email string) error {
	return ks.importKey(keyFile, name, email)
}

func (ks *Keystore) importKey(keyFile, name, email string) error {
	var ki KeyInfo
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("error reading key file: %w", err)
	}

	//
	// check to see if it is a PEM file (private or public)
	//
	if privKey, err := LoadPrivateKey(b); err == nil {
		ki.KeyType = PrivateKey
		ki.Bytes = b
		pubKey, err := GenPublicKeyFromPrivate(privKey)
		if err != nil {
			return fmt.Errorf("error deriving public key from private key: %w", err)
		}
		ki.KeyID = GenerateKeyID(pubKey)
		ki.Date = time.Now()
		ki.Name = name
		ki.Email = email
		return ks.writeKeyFile(ki)
	} else if pubKey, err := LoadPublicKey(b); err == nil {
		ki.KeyType = PublicKey
		ki.Bytes = b
		ki.KeyID = GenerateKeyID(pubKey)
		ki.Date = time.Now()
		ki.Name = name
		ki.Email = email
		return ks.writeKeyFile(ki)
	}

	//
	// JSON bgp encode key file
	//
	if err := json.Unmarshal(b, &ki); err != nil {
		return fmt.Errorf("error parsing key file: %w", err)
	}

	if ki.KeyType == PrivateKey {
		if _, err := LoadPrivateKey(ki.Bytes); err != nil {
			return fmt.Errorf("error loading private key from %s: %w", keyFile, err)
		}

	} else {
		if _, err := LoadPublicKey(ki.Bytes); err != nil {
			return fmt.Errorf("error loading public key from %s: %w", keyFile, err)
		}
	}

	if err := ks.EnsureExists(); err != nil {
		return fmt.Errorf("error creating keystore directory: %w", err)
	}

	if name != "" {
		ki.Name = name
	}
	if email != "" {
		ki.Email = email
	}

	return ks.writeKeyFile(ki)
}

func (ks *Keystore) readKeyFile(file string) (*KeyInfo, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var ki KeyInfo
	if err := json.Unmarshal(b, &ki); err != nil {
		return nil, err
	}
	return &ki, nil
}

func (ks *Keystore) writeKeyFile(ki KeyInfo) error {
	var destFilename string
	var mode os.FileMode = 0644
	if ki.KeyType == PrivateKey {
		destFilename = filepath.Join(ks.Path, fmt.Sprintf("%s_private.json", ki.KeyID))
		mode = 0600
	} else {
		destFilename = filepath.Join(ks.Path, fmt.Sprintf("%s_public.json", ki.KeyID))
	}

	f, err := os.OpenFile(destFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("error writing key to keystore: %w", err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(ki); err != nil {
		return fmt.Errorf("error encoding key to keystore: %w", err)
	}
	return nil
}

// Export exports a key with metadata headers including name, email, and key ID
func (ks *Keystore) Export(ki KeyInfo, outPath string) error {
	if outPath == "" || outPath == "-" {
		if err := json.NewEncoder(os.Stdout).Encode(ki); err != nil {
			return fmt.Errorf("failed to write key to stdout: %w", err)
		}
		return nil
	}

	var perm os.FileMode = 0644
	if ki.KeyType {
		perm = 0600
	}

	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("error exporting key %s: %w", outPath, err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(ki); err != nil {
		return fmt.Errorf("failed to write key to %s: %w", outPath, err)
	}

	return nil
}

// GetLatestKeyForOwner returns the most recent key file path for a given owner and key type
func (ks *Keystore) GetLatestKeyForOwner(name, email string, keyType KeyType) (*KeyInfo, error) {
	var key *KeyInfo
	err := ks.CollectKeyInfo(func(ki KeyInfo) error {
		if name != "" && ki.Name != name {
			return nil // skip
		}

		if email != "" && ki.Email != email {
			return nil // skip
		}

		if keyType && !ki.KeyType {
			return nil // skip
		} else if !keyType && ki.KeyType {
			return nil // skip
		}

		if key == nil {
			key = &ki
		} else {
			if key.Date.Before(ki.Date) {
				key = &ki
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if key == nil {
		if email == "" {
			email = "*"
		}
		if name == "" {
			name = "*"
		}
		return nil, fmt.Errorf("no key found for %s <%s>", name, email)
	}

	return key, nil
}

// Remove removes a key file from the keystore
func (ks *Keystore) Remove(ki KeyInfo) error {
	if err := ks.EnsureExists(); err != nil {
		return err
	}
	p := filepath.Join(ks.Path, fmt.Sprintf("%s_%s.json", ki.KeyID, ki.KeyType.String()))
	return os.Remove(p)
}
