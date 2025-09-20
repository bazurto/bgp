package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GetDefaultKeystorePath returns the default keystore path for the current user
func GetDefaultKeystorePath() string {
	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home directory can't be determined
		return filepath.Join(".", ".bpg", "keystore")
	}
	
	return filepath.Join(homeDir, ".bpg", "keystore")
}

// KeyInfo represents metadata about a key
type KeyInfo struct {
	Name      string
	Email     string
	Date      string
	Filename  string
	IsPrivate bool
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
func LoadPrivateKey(filename string) (interface{}, error) {
	privBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(privBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	// Try parsing as PKCS#1
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
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
func LoadPublicKey(filename string) (interface{}, error) {
	pubBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pubBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Try parsing as PKCS#1
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return pubKey, nil
	}

	// Try parsing as PKCS#8
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

// ExportPrivateKey exports a private key to a PEM-encoded file
func ExportPrivateKey(key interface{}, filename string) error {
	var privBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal EC private key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported private key type")
	}

	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	privFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	err = pem.Encode(privFile, privBlock)
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	return nil
}

// ExportPublicKey exports a public key to a PEM-encoded file
func ExportPublicKey(key interface{}, filename string) error {
	var pubBytes []byte
	var err error

	switch k := key.(type) {
	case *rsa.PublicKey:
		pubBytes = x509.MarshalPKCS1PublicKey(k)
	case *ecdsa.PublicKey:
		pubBytes, err = x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal EC public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pubFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	err = pem.Encode(pubFile, pubBlock)
	if err != nil {
		return fmt.Errorf("failed to write public key to file: %w", err)
	}

	return nil
}

// GenerateKeyPair generates a new RSA or EC key pair and returns the private and public keys
func GenerateKeyPair(algorithm, curve, name, email string) (interface{}, interface{}, error) {
	var privKey interface{}
	var pubKey interface{}
	var err error

	switch algorithm {
	case "rsa":
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		pubKey = privKey.(*rsa.PrivateKey).Public()
	case "ec":
		var ecCurve elliptic.Curve
		switch curve {
		case "P-256":
			ecCurve = elliptic.P256()
		case "P-384":
			ecCurve = elliptic.P384()
		case "P-521":
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

// ParseKeyFilename extracts metadata from key filename
func ParseKeyFilename(filename string) (*KeyInfo, error) {
	// Expected format: name_email_date_type.pem
	nameWithoutExt := strings.TrimSuffix(filename, ".pem")
	parts := strings.Split(nameWithoutExt, "_")

	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid key filename format: %s", filename)
	}

	name := parts[0]
	dateIndex := len(parts) - 2
	date := parts[dateIndex]
	emailParts := parts[1:dateIndex]
	email := strings.Join(emailParts, "_")
	isPrivate := strings.Contains(filename, "private")

	return &KeyInfo{
		Name:      name,
		Email:     email,
		Date:      date,
		Filename:  filename,
		IsPrivate: isPrivate,
	}, nil
}

// GenerateKeyID generates a fingerprint for a public key
func GenerateKeyID(publicKey interface{}) string {
	var keyBytes []byte

	switch pubKey := publicKey.(type) {
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
func (ks *Keystore) SaveKeyPair(privKey interface{}, pubKey interface{}, name, email string) error {
	if err := ks.EnsureExists(); err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	privFilename := filepath.Join(ks.Path, fmt.Sprintf("%s_%s_%s_private.pem", name, email, time.Now().Format("20060102")))
	pubFilename := filepath.Join(ks.Path, fmt.Sprintf("%s_%s_%s_public.pem", name, email, time.Now().Format("20060102")))

	err := ExportPrivateKey(privKey, privFilename)
	if err != nil {
		return fmt.Errorf("failed to export private key: %w", err)
	}

	err = ExportPublicKey(pubKey, pubFilename)
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	return nil
}

// FindLatestPrivateKey finds the most recent private key for the given name/email
func (ks *Keystore) FindLatestPrivateKey(name, email string) (string, error) {
	var latestKey *KeyInfo

	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") && strings.Contains(info.Name(), "private") {
			keyInfo, err := ParseKeyFilename(info.Name())
			if err != nil {
				return nil // Skip invalid filenames
			}

			if keyInfo.Name == name && keyInfo.Email == email {
				if latestKey == nil || keyInfo.Date > latestKey.Date {
					latestKey = keyInfo
				}
			}
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if latestKey == nil {
		return "", fmt.Errorf("no private key found for %s <%s>", name, email)
	}

	return filepath.Join(ks.Path, latestKey.Filename), nil
}

// FindPublicKeyByRecipient finds a public key for the given recipient
func (ks *Keystore) FindPublicKeyByRecipient(recipient string) (string, error) {
	var foundKey string

	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") && strings.Contains(info.Name(), "public") {
			if strings.Contains(info.Name(), recipient) {
				foundKey = path
				return filepath.SkipDir // Stop searching once found
			}
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if foundKey == "" {
		return "", fmt.Errorf("no public key found for recipient: %s", recipient)
	}

	return foundKey, nil
}

// GetAllPrivateKeys returns all private key files in the keystore
func (ks *Keystore) GetAllPrivateKeys() ([]string, error) {
	var keys []string

	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") && strings.Contains(info.Name(), "private") {
			keys = append(keys, path)
		}
		return nil
	})

	return keys, err
}

// CollectKeyInfo gathers information about all keys in the keystore
func (ks *Keystore) CollectKeyInfo() ([]KeyInfo, error) {
	var keys []KeyInfo

	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") {
			keyInfo, err := ParseKeyFilename(info.Name())
			if err != nil {
				return nil // Skip invalid filenames
			}
			keys = append(keys, *keyInfo)
		}
		return nil
	})

	return keys, err
}

// ImportPublicKey imports a public key file into the keystore
func (ks *Keystore) ImportPublicKey(keyFile, name, email string) (string, error) {
	// Check if source key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return "", fmt.Errorf("key file does not exist: %s", keyFile)
	}

	// Verify it's a valid public key
	_, err := LoadPublicKey(keyFile)
	if err != nil {
		return "", fmt.Errorf("error loading public key from %s: %w", keyFile, err)
	}

	// Ensure keystore directory exists
	if err := ks.EnsureExists(); err != nil {
		return "", fmt.Errorf("error creating keystore directory: %w", err)
	}

	// Copy to keystore with standardized name
	destFilename := filepath.Join(ks.Path, fmt.Sprintf("%s_%s_%s_public.pem", name, email, time.Now().Format("20060102")))

	// Read source file
	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("error reading key file: %w", err)
	}

	// Write to destination
	err = ioutil.WriteFile(destFilename, keyData, 0644)
	if err != nil {
		return "", fmt.Errorf("error writing key to keystore: %w", err)
	}

	return destFilename, nil
}
