// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

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
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GetDefaultKeystorePath returns the default keystore path for the current user
func GetDefaultKeystorePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".bgp", "keystore")
	}
	return filepath.Join(homeDir, ".bgp", "keystore")
}

// KeyInfo represents metadata about a key
type KeyInfo struct {
	Name      string
	Email     string
	Date      string
	Filename  string
	IsPrivate bool
	KeyID     string
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
	privBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

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
func LoadPublicKey(filename string) (interface{}, error) {
	pubBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

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

	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}

	privFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privFile.Close()

	if err := pem.Encode(privFile, privBlock); err != nil {
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

	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}

	pubFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, pubBlock); err != nil {
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

	if err := ExportPrivateKey(privKey, privFilename); err != nil {
		return fmt.Errorf("failed to export private key: %w", err)
	}

	if err := ExportPublicKey(pubKey, pubFilename); err != nil {
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

		// Skip the trash directory entirely
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
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

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
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

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
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

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") {
			keyInfo, err := ParseKeyFilename(info.Name())
			if err != nil {
				return nil // Skip invalid filenames
			}
			// compute key ID if possible
			keyPath := filepath.Join(ks.Path, info.Name())
			if keyInfo != nil {
				if keyInfo.IsPrivate {
					if privKey, err := LoadPrivateKey(keyPath); err == nil {
						switch pk := privKey.(type) {
						case *rsa.PrivateKey:
							keyInfo.KeyID = GenerateKeyID(&pk.PublicKey)
						case *ecdsa.PrivateKey:
							keyInfo.KeyID = GenerateKeyID(&pk.PublicKey)
						}
					}
				} else {
					if pubKey, err := LoadPublicKey(keyPath); err == nil {
						keyInfo.KeyID = GenerateKeyID(pubKey)
					}
				}
			}

			keys = append(keys, *keyInfo)
		}
		return nil
	})

	return keys, err
}

// FindKeyByID returns the filename for the given key ID, searching both public and private keys
func (ks *Keystore) FindKeyByID(keyID string) (string, error) {
	var found string
	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".pem") {
			return nil
		}
		keyInfo, err := ParseKeyFilename(info.Name())
		if err != nil {
			return nil
		}
		keyPath := filepath.Join(ks.Path, info.Name())
		if keyInfo.IsPrivate {
			if privKey, err := LoadPrivateKey(keyPath); err == nil {
				switch pk := privKey.(type) {
				case *rsa.PrivateKey:
					if GenerateKeyID(&pk.PublicKey) == keyID {
						found = keyPath
						return filepath.SkipDir
					}
				case *ecdsa.PrivateKey:
					if GenerateKeyID(&pk.PublicKey) == keyID {
						found = keyPath
						return filepath.SkipDir
					}
				}
			}
		} else {
			if pubKey, err := LoadPublicKey(keyPath); err == nil {
				if GenerateKeyID(pubKey) == keyID {
					found = keyPath
					return filepath.SkipDir
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("no key found with id: %s", keyID)
	}
	return found, nil
}

// ImportPublicKey imports a public key file into the keystore
func (ks *Keystore) ImportPublicKey(keyFile, name, email string) (string, error) {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return "", fmt.Errorf("key file does not exist: %s", keyFile)
	}

	if _, err := LoadPublicKey(keyFile); err != nil {
		return "", fmt.Errorf("error loading public key from %s: %w", keyFile, err)
	}

	if err := ks.EnsureExists(); err != nil {
		return "", fmt.Errorf("error creating keystore directory: %w", err)
	}

	destFilename := filepath.Join(ks.Path, fmt.Sprintf("%s_%s_%s_public.pem", name, email, time.Now().Format("20060102")))

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("error reading key file: %w", err)
	}

	if err := os.WriteFile(destFilename, keyData, 0644); err != nil {
		return "", fmt.Errorf("error writing key to keystore: %w", err)
	}

	return destFilename, nil
}

// ImportPrivateKey imports a private key file into the keystore
func (ks *Keystore) ImportPrivateKey(keyFile, name, email string) (string, error) {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return "", fmt.Errorf("key file does not exist: %s", keyFile)
	}

	if _, err := LoadPrivateKey(keyFile); err != nil {
		return "", fmt.Errorf("error loading private key from %s: %w", keyFile, err)
	}

	if err := ks.EnsureExists(); err != nil {
		return "", fmt.Errorf("error creating keystore directory: %w", err)
	}

	destFilename := filepath.Join(ks.Path, fmt.Sprintf("%s_%s_%s_private.pem", name, email, time.Now().Format("20060102")))

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("error reading key file: %w", err)
	}

	if err := os.WriteFile(destFilename, keyData, 0600); err != nil {
		return "", fmt.Errorf("error writing key to keystore: %w", err)
	}

	return destFilename, nil
}

// ExportKey copies a key from the keystore or absolute path to an output path, or writes to stdout when outPath is empty
func (ks *Keystore) ExportKey(keyPath, outPath string) (string, error) {
	src := keyPath
	if !filepath.IsAbs(src) {
		if _, err := os.Stat(src); os.IsNotExist(err) {
			src = filepath.Join(ks.Path, keyPath)
		}
	}

	if _, err := os.Stat(src); os.IsNotExist(err) {
		return "", fmt.Errorf("key file does not exist: %s", src)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}

	if outPath == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			return "", fmt.Errorf("failed to write key to stdout: %w", err)
		}
		return "-", nil
	}

	perm := 0644
	if strings.Contains(strings.ToLower(src), "private") {
		perm = 0600
	}

	if err := os.WriteFile(outPath, data, os.FileMode(perm)); err != nil {
		return "", fmt.Errorf("failed to write key to %s: %w", outPath, err)
	}

	return outPath, nil
}

// GetLatestKeyForOwner returns the most recent key file path for a given owner and key type
func (ks *Keystore) GetLatestKeyForOwner(name, email string, wantPrivate bool) (string, error) {
	var latestKey *KeyInfo

	err := filepath.Walk(ks.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip trash directory
		if info.IsDir() && info.Name() == ".trash" {
			return filepath.SkipDir
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".pem") {
			return nil
		}

		isPriv := strings.Contains(info.Name(), "private")
		if wantPrivate != isPriv {
			return nil
		}

		keyInfo, err := ParseKeyFilename(info.Name())
		if err != nil {
			return nil
		}

		if keyInfo.Name == name && keyInfo.Email == email {
			if latestKey == nil || keyInfo.Date > latestKey.Date {
				latestKey = keyInfo
			}
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if latestKey == nil {
		t := "public"
		if wantPrivate {
			t = "private"
		}
		return "", fmt.Errorf("no %s key found for %s <%s>", t, name, email)
	}

	return filepath.Join(ks.Path, latestKey.Filename), nil
}

// MoveToTrash moves the specified file into a .trash subdirectory inside the keystore
func (ks *Keystore) MoveToTrash(srcPath string) (string, error) {
	if err := ks.EnsureExists(); err != nil {
		return "", err
	}

	trashDir := filepath.Join(ks.Path, ".trash")
	if err := os.MkdirAll(trashDir, 0700); err != nil {
		return "", err
	}

	base := filepath.Base(srcPath)
	dest := filepath.Join(trashDir, base)

	if _, err := os.Stat(dest); err == nil {
		dest = filepath.Join(trashDir, fmt.Sprintf("%s.%d", base, time.Now().Unix()))
	}

	if err := os.Rename(srcPath, dest); err != nil {
		return "", err
	}

	return dest, nil
}

// PurgeTrash removes files in the .trash directory older than daysOld days.
func (ks *Keystore) PurgeTrash(daysOld int) error {
	trashDir := filepath.Join(ks.Path, ".trash")
	if _, err := os.Stat(trashDir); os.IsNotExist(err) {
		return nil
	}

	now := time.Now()
	return filepath.Walk(trashDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if daysOld <= 0 {
			return os.Remove(path)
		}
		if now.Sub(info.ModTime()) > time.Duration(daysOld)*24*time.Hour {
			return os.Remove(path)
		}
		return nil
	})
}

// If destination exists, append a timestamp
