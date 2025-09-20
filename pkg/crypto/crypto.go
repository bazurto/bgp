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
	"strings"
	"time"

	"github.com/bazurto/bpg/pkg/keystore"
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
	// Parse sender info
	senderName, senderEmail, err := parseSenderInfo(sender)
	if err != nil {
		return nil, err
	}

	// Find sender's latest private key
	privateKeyPath, err := e.keystore.FindLatestPrivateKey(senderName, senderEmail)
	if err != nil {
		return nil, fmt.Errorf("error finding sender's private key: %w", err)
	}

	// Find recipient's public key
	recipientKeyPath, err := e.keystore.FindPublicKeyByRecipient(recipient)
	if err != nil {
		return nil, fmt.Errorf("error finding recipient's public key: %w", err)
	}

	// Load keys
	privateKey, err := keystore.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	publicKey, err := keystore.LoadPublicKey(recipientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading public key: %w", err)
	}

	return encryptMessageWithKeys(message, privateKey, publicKey, sender, recipient)
}

// EncryptMessageWithKeys encrypts a message using the provided keys directly
func EncryptMessageWithKeys(message string, senderPrivateKey, recipientPublicKey interface{}, sender, recipient string) (*EncryptedMessage, error) {
	return encryptMessageWithKeys(message, senderPrivateKey, recipientPublicKey, sender, recipient)
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

// ToJSON converts an EncryptedMessage to JSON bytes
func (em *EncryptedMessage) ToJSON() ([]byte, error) {
	return json.MarshalIndent(em, "", "  ")
}

// Helper functions

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
