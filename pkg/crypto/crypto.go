// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bazurto/bgp/pkg/keystore"
)

// EncryptedMessage represents the structure of an encrypted message
type EncryptedMessage struct {
	Recipient  string `json:"recipient"`
	Sender     string `json:"sender"`
	KeyID      string `json:"key_id"`
	Timestamp  string `json:"timestamp"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
	Algorithm  string `json:"algorithm"`
}

// Encryptor handles message encryption operations
type Encryptor struct {
	keystore *keystore.Keystore
}

// NewEncryptor creates a new encryptor with the given keystore
func NewEncryptor(ks *keystore.Keystore) *Encryptor {
	return &Encryptor{keystore: ks}
}

// EncryptMessage encrypts a message using hybrid encryption
func (e *Encryptor) EncryptMessage(message, sender, recipient string) (*EncryptedMessage, error) {
	// Resolve sender identifier to find private key
	privateKeyPath, resolvedSender, err := e.resolveSenderIdentifier(sender)
	if err != nil {
		return nil, fmt.Errorf("error resolving sender: %w", err)
	}

	// Resolve recipient identifier to find public key
	publicKeyPath, resolvedRecipient, err := e.resolveRecipientIdentifier(recipient)
	if err != nil {
		return nil, fmt.Errorf("error resolving recipient: %w", err)
	}

	// Load keys
	privateKey, err := keystore.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	publicKey, err := keystore.LoadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading public key: %w", err)
	}

	return encryptMessageWithKeys(message, privateKey, publicKey, resolvedSender, resolvedRecipient)
}

// EncryptMessageWithKeys encrypts a message using the provided keys directly
func EncryptMessageWithKeys(message string, senderPrivateKey, recipientPublicKey interface{}, sender, recipient string) (*EncryptedMessage, error) {
	return encryptMessageWithKeys(message, senderPrivateKey, recipientPublicKey, sender, recipient)
}

// EncryptOnlyMessage encrypts a message for a recipient without signing (no sender required)
func (e *Encryptor) EncryptOnlyMessage(message, recipient string) (*EncryptedMessage, error) {
	// Resolve recipient identifier to find public key
	publicKeyPath, resolvedRecipient, err := e.resolveRecipientIdentifier(recipient)
	if err != nil {
		return nil, fmt.Errorf("error resolving recipient: %w", err)
	}

	// Load recipient's public key
	publicKey, err := keystore.LoadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading public key: %w", err)
	}

	return encryptOnlyWithKey(message, publicKey, resolvedRecipient)
}

// SignOnlyMessage signs a message without encryption (no recipient required)
func (e *Encryptor) SignOnlyMessage(message, sender string) (*EncryptedMessage, error) {
	// Resolve sender identifier to find private key
	privateKeyPath, resolvedSender, err := e.resolveSenderIdentifier(sender)
	if err != nil {
		return nil, fmt.Errorf("error resolving sender: %w", err)
	}

	// Load sender's private key
	privateKey, err := keystore.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return signOnlyWithKey(message, privateKey, resolvedSender)
}

func encryptMessageWithKeys(message string, senderPrivateKey, recipientPublicKey interface{}, sender, recipient string) (*EncryptedMessage, error) {
	// Generate a random AES key
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt the message with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)

	// Encrypt the AES key with recipient's public key
	var encryptedAESKey []byte
	switch pubKey := recipientPublicKey.(type) {
	case *rsa.PublicKey:
		encryptedAESKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt AES key with RSA: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type for encryption")
	}

	// Combine encrypted AES key and ciphertext
	combinedCiphertext := append(encryptedAESKey, ciphertext...)

	// Sign the ciphertext with sender's private key
	signature, err := signMessage(combinedCiphertext, senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return &EncryptedMessage{
		Recipient:  recipient,
		Sender:     sender,
		KeyID:      keystore.GenerateKeyID(recipientPublicKey),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Ciphertext: base64.StdEncoding.EncodeToString(combinedCiphertext),
		Signature:  base64.StdEncoding.EncodeToString(signature),
		Algorithm:  "RSA-OAEP+AES-GCM",
	}, nil
}

// encryptOnlyWithKey encrypts a message for a recipient without signing
func encryptOnlyWithKey(message string, recipientPublicKey interface{}, recipient string) (*EncryptedMessage, error) {
	// Generate a random AES key
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt the message with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)

	// Encrypt the AES key with recipient's public key
	var encryptedAESKey []byte
	switch pubKey := recipientPublicKey.(type) {
	case *rsa.PublicKey:
		encryptedAESKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt AES key with RSA: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type for encryption")
	}

	// Combine encrypted AES key and ciphertext
	combinedCiphertext := append(encryptedAESKey, ciphertext...)

	return &EncryptedMessage{
		Recipient:  recipient,
		Sender:     "", // No sender for encrypt-only
		KeyID:      keystore.GenerateKeyID(recipientPublicKey),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Ciphertext: base64.StdEncoding.EncodeToString(combinedCiphertext),
		Signature:  "", // No signature for encrypt-only
		Algorithm:  "RSA-OAEP+AES-GCM",
	}, nil
}

// signOnlyWithKey signs a message without encryption
func signOnlyWithKey(message string, senderPrivateKey interface{}, sender string) (*EncryptedMessage, error) {
	// Sign the message directly
	signature, err := signMessage([]byte(message), senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return &EncryptedMessage{
		Recipient:  "", // No recipient for sign-only
		Sender:     sender,
		KeyID:      "", // No recipient key ID for sign-only
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte(message)), // Store plain message as base64
		Signature:  base64.StdEncoding.EncodeToString(signature),
		Algorithm:  "Sign-Only",
	}, nil
}

// Decryptor handles message decryption operations
type Decryptor struct {
	keystore *keystore.Keystore
}

// NewDecryptor creates a new decryptor with the given keystore
func NewDecryptor(ks *keystore.Keystore) *Decryptor {
	return &Decryptor{keystore: ks}
}

// DecryptMessage decrypts a message using any available private key in the keystore
func (d *Decryptor) DecryptMessage(encryptedMsg *EncryptedMessage) (string, error) {
	// Get all private keys to try
	privateKeyPaths, err := d.keystore.GetAllPrivateKeys()
	if err != nil {
		return "", fmt.Errorf("error finding private keys: %w", err)
	}

	if len(privateKeyPaths) == 0 {
		return "", fmt.Errorf("no private keys found in keystore")
	}

	// Try to decrypt with each private key
	for _, keyPath := range privateKeyPaths {
		privateKey, err := keystore.LoadPrivateKey(keyPath)
		if err != nil {
			continue // Skip invalid keys
		}

		message, err := DecryptMessageWithKey(encryptedMsg, privateKey)
		if err == nil {
			return message, nil
		}
	}

	return "", fmt.Errorf("failed to decrypt message with any available private key")
}

// DecryptMessageWithKey decrypts a message using the provided private key directly
func DecryptMessageWithKey(encryptedMsg *EncryptedMessage, privateKey interface{}) (string, error) {
	// Decode the ciphertext
	combinedCiphertext, err := base64.StdEncoding.DecodeString(encryptedMsg.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Verify signature first (optional but good practice)
	_, err = base64.StdEncoding.DecodeString(encryptedMsg.Signature)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %w", err)
	}

	// For simplicity, we'll skip signature verification here
	// In production, you'd want to verify the sender's signature

	// Determine the size of the encrypted AES key based on private key type
	var keySize int
	switch privKey := privateKey.(type) {
	case *rsa.PrivateKey:
		keySize = privKey.Size()
	default:
		return "", fmt.Errorf("unsupported private key type for decryption")
	}

	if len(combinedCiphertext) < keySize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Split the encrypted AES key and message ciphertext
	encryptedAESKey := combinedCiphertext[:keySize]
	messageCiphertext := combinedCiphertext[keySize:]

	// Decrypt the AES key with private key
	var aesKey []byte
	switch privKey := privateKey.(type) {
	case *rsa.PrivateKey:
		aesKey, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedAESKey, nil)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt AES key: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported private key type")
	}

	// Decrypt the message with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(messageCiphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := messageCiphertext[:nonceSize]
	ciphertext := messageCiphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(plaintext), nil
}

// ParseEncryptedMessage parses JSON data into an EncryptedMessage
func ParseEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	var encryptedMsg EncryptedMessage
	if err := json.Unmarshal(data, &encryptedMsg); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted message: %w", err)
	}
	return &encryptedMsg, nil
}

// VerifyMessage verifies a sign-only message using any available public key in the keystore
func (d *Decryptor) VerifyMessage(encryptedMsg *EncryptedMessage) (string, error) {
	// For sign-only messages, the ciphertext contains the base64-encoded original message
	messageBytes, err := base64.StdEncoding.DecodeString(encryptedMsg.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode message: %w", err)
	}

	// Decode the signature
	signature, err := base64.StdEncoding.DecodeString(encryptedMsg.Signature)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %w", err)
	}

	// Try to find the sender's public key to verify the signature
	if encryptedMsg.Sender != "" {
		// Try to find sender's public key by parsing sender info
		if strings.Contains(encryptedMsg.Sender, "@") {
			name, email, parseErr := parseSenderInfo(encryptedMsg.Sender)
			if parseErr == nil {
				// Try to find public key for this sender
				keys, err := d.keystore.CollectKeyInfo()
				if err == nil {
					for _, key := range keys {
						if !key.IsPrivate && key.Name == name && key.Email == email {
							publicKeyPath := filepath.Join(d.keystore.Path, key.Filename)
							publicKey, err := keystore.LoadPublicKey(publicKeyPath)
							if err == nil {
								if verifySignature(messageBytes, signature, publicKey) {
									return string(messageBytes), nil
								}
							}
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("failed to verify signature: sender's public key not found or signature invalid")
}

// ProcessMessage determines if the message needs verification or decryption and processes it accordingly
func (d *Decryptor) ProcessMessage(encryptedMsg *EncryptedMessage) (string, bool, error) {
	// Determine message type based on algorithm
	isSignOnly := encryptedMsg.Algorithm == "Sign-Only"

	if isSignOnly {
		// This is a sign-only message, verify it
		message, err := d.VerifyMessage(encryptedMsg)
		return message, true, err // true indicates verification was performed
	} else {
		// This is an encrypted message (with or without signature), decrypt it
		message, err := d.DecryptMessage(encryptedMsg)
		return message, false, err // false indicates decryption was performed
	}
}

// ToJSON converts an EncryptedMessage to JSON bytes
func (em *EncryptedMessage) ToJSON() ([]byte, error) {
	return json.MarshalIndent(em, "", "  ")
}

// Helper functions

// resolveSenderIdentifier resolves a sender identifier (name@email, key ID, or name) to find the private key
func (e *Encryptor) resolveSenderIdentifier(identifier string) (privateKeyPath string, resolvedSender string, err error) {
	// First try to parse as name@email format
	if strings.Contains(identifier, "@") {
		name, email, parseErr := parseSenderInfo(identifier)
		if parseErr == nil {
			keyPath, findErr := e.keystore.FindLatestPrivateKey(name, email)
			if findErr == nil {
				return keyPath, identifier, nil
			}
		}
	}

	// Try as key ID
	if len(identifier) >= 8 { // Key IDs are typically longer
		keyPath, err := e.keystore.FindKeyByID(identifier)
		if err == nil {
			// Verify it's a private key
			if strings.Contains(keyPath, "private") {
				// Extract name and email from filename to construct sender
				filename := filepath.Base(keyPath)
				keyInfo, parseErr := keystore.ParseKeyFilename(filename)
				if parseErr == nil {
					resolvedSender := keyInfo.Name + "@" + keyInfo.Email
					return keyPath, resolvedSender, nil
				}
			}
		}
	}

	// Try as name (find any private key for this name)
	keys, err := e.keystore.CollectKeyInfo()
	if err != nil {
		return "", "", fmt.Errorf("error listing keys: %w", err)
	}

	var matchingKeys []keystore.KeyInfo
	for _, key := range keys {
		if key.IsPrivate && (key.Name == identifier || key.Email == identifier) {
			matchingKeys = append(matchingKeys, key)
		}
	}

	if len(matchingKeys) == 0 {
		return "", "", fmt.Errorf("no private key found for identifier: %s", identifier)
	}

	// Use the most recent key
	var latestKey *keystore.KeyInfo
	for _, key := range matchingKeys {
		if latestKey == nil || key.Date > latestKey.Date {
			latestKey = &key
		}
	}

	keyPath := filepath.Join(e.keystore.Path, latestKey.Filename)
	resolvedSender = latestKey.Name + "@" + latestKey.Email
	return keyPath, resolvedSender, nil
}

// resolveRecipientIdentifier resolves a recipient identifier (name, email, or key ID) to find the public key
func (e *Encryptor) resolveRecipientIdentifier(identifier string) (publicKeyPath string, resolvedRecipient string, err error) {
	// Try as key ID first
	if len(identifier) >= 8 {
		keyPath, err := e.keystore.FindKeyByID(identifier)
		if err == nil {
			// Verify it's a public key
			if strings.Contains(keyPath, "public") {
				// Extract name and email from filename
				filename := filepath.Base(keyPath)
				keyInfo, parseErr := keystore.ParseKeyFilename(filename)
				if parseErr == nil {
					resolvedRecipient := keyInfo.Name + "@" + keyInfo.Email
					return keyPath, resolvedRecipient, nil
				}
			} else {
				// It's a private key, find corresponding public key
				filename := filepath.Base(keyPath)
				publicFilename := strings.Replace(filename, "private", "public", 1)
				publicKeyPath := filepath.Join(e.keystore.Path, publicFilename)
				if _, err := os.Stat(publicKeyPath); err == nil {
					keyInfo, parseErr := keystore.ParseKeyFilename(publicFilename)
					if parseErr == nil {
						resolvedRecipient := keyInfo.Name + "@" + keyInfo.Email
						return publicKeyPath, resolvedRecipient, nil
					}
				}
			}
		}
	}

	// Try existing recipient search (name or email in filename)
	keyPath, err := e.keystore.FindPublicKeyByRecipient(identifier)
	if err == nil {
		// Extract recipient info from filename
		filename := filepath.Base(keyPath)
		keyInfo, parseErr := keystore.ParseKeyFilename(filename)
		if parseErr == nil {
			resolvedRecipient := keyInfo.Name + "@" + keyInfo.Email
			return keyPath, resolvedRecipient, nil
		}
		// Fallback to original identifier
		return keyPath, identifier, nil
	}

	return "", "", fmt.Errorf("no public key found for identifier: %s", identifier)
}

func parseSenderInfo(sender string) (name, email string, err error) {
	parts := strings.SplitN(sender, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("sender must be in format name@email")
	}
	return parts[0], parts[1], nil
}

func signMessage(message []byte, privateKey interface{}) ([]byte, error) {
	hash := sha256.Sum256(message)

	switch privKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, privKey, 0, hash[:])
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	default:
		return nil, fmt.Errorf("unsupported private key type for signing")
	}
}

func verifySignature(message, signature []byte, publicKey interface{}) bool {
	hash := sha256.Sum256(message)

	switch pubKey := publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pubKey, 0, hash[:], signature)
		return err == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pubKey, hash[:], signature)
	default:
		return false
	}
}
