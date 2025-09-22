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
	"io"
	"os"
	"strings"
	"time"

	"github.com/bazurto/bgp/pkg/keystore"
)

// EncryptedMessage represents the structure of an encrypted message
type EncryptedMessage struct {
	To         string `json:"to,omitempty"`
	From       string `json:"from,omitempty"`
	Timestamp  string `json:"time,omitempty"`
	Algorithm  string `json:"alg,omitempty"`
	Ciphertext string `json:"cipher,omitempty"`
	Signature  string `json:"sig,omitempty"`
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
func (e *Encryptor) EncryptMessage(message, from, to string) (*EncryptedMessage, error) {
	// Resolve sender identifier to find private key
	fromKi, err := e.resolveKeyWithIdentifier(from, keystore.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Resolve recipient identifier to find public key
	toKi, err := e.resolveKeyWithIdentifier(to, keystore.PublicKey)
	if err != nil {
		return nil, err
	}

	// Load keys
	privateKey, err := keystore.LoadPrivateKey(fromKi.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	publicKey, err := keystore.LoadPublicKey(toKi.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading public key: %w", err)
	}

	return encryptMessageWithKeys(message, privateKey, publicKey, fromKi, toKi)
}

// EncryptMessageWithKeys encrypts a message using the provided keys directly
func EncryptMessageWithKeys(message string, senderPrivateKey, recipientPublicKey interface{}, fromKi, toKi *keystore.KeyInfo) (*EncryptedMessage, error) {
	return encryptMessageWithKeys(message, senderPrivateKey, recipientPublicKey, fromKi, toKi)
}

// EncryptOnlyMessage encrypts a message for a recipient without signing (no sender required)
func (e *Encryptor) EncryptOnlyMessage(message, to string) (*EncryptedMessage, error) {
	// Resolve recipient identifier to find public key
	toKi, err := e.resolveKeyWithIdentifier(to, keystore.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error resolving recipient: %w", err)
	}

	// Load recipient's public key
	publicKey, err := keystore.LoadPublicKey(toKi.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading public key: %w", err)
	}

	return encryptOnlyWithKey(message, publicKey, toKi)
}

// SignOnlyMessage signs a message without encryption (no recipient required)
func (e *Encryptor) SignOnlyMessage(message, sender string) (*EncryptedMessage, error) {
	// Resolve sender identifier to find private key
	privKi, err := e.resolveKeyWithIdentifier(sender, keystore.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error resolving sender: %w", err)
	}

	// Load sender's private key
	privateKey, err := keystore.LoadPrivateKey(privKi.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error loading private key: %w", err)
	}

	return signOnlyWithKey(message, privateKey, privKi)
}

func encryptMessageWithKeys(message string, senderPrivateKey, recipientPublicKey interface{}, sender, recipient *keystore.KeyInfo) (*EncryptedMessage, error) {
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

	senderPubKey, err := keystore.GenPublicKeyFromPrivate(senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key from private key: %w", err)
	}

	return &EncryptedMessage{
		To:         keystore.GenerateKeyID(recipientPublicKey),
		From:       keystore.GenerateKeyID(senderPubKey),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Algorithm:  "RSA-OAEP+AES-GCM",
		Ciphertext: base64.StdEncoding.EncodeToString(combinedCiphertext),
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// encryptOnlyWithKey encrypts a message for a recipient without signing
func encryptOnlyWithKey(
	message string,
	recipientPublicKey any,
	toKi *keystore.KeyInfo,
) (*EncryptedMessage, error) {
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
		To:         toKi.KeyID,
		From:       "", // No sender for encrypt-only
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Algorithm:  "RSA-OAEP+AES-GCM",
		Ciphertext: base64.StdEncoding.EncodeToString(combinedCiphertext),
		Signature:  "", // No signature for encrypt-only
	}, nil
}

// signOnlyWithKey signs a message without encryption
func signOnlyWithKey(message string, fromPrivateKey any, privKi *keystore.KeyInfo) (*EncryptedMessage, error) {
	// Sign the message directly
	signature, err := signMessage([]byte(message), fromPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return &EncryptedMessage{
		To:         "", // No recipient for sign-only
		From:       privKi.KeyID,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Algorithm:  "Sign-Only",
		Ciphertext: base64.StdEncoding.EncodeToString([]byte(message)), // Store plain message as base64
		Signature:  base64.StdEncoding.EncodeToString(signature),
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
func (d *Decryptor) DecryptMessage(encryptedMsg *EncryptedMessage) (string, bool, error) {

	// If it's a sign-only message, just verify
	var err error
	verified := false
	var verifiedMsg string
	if encryptedMsg.From != "" {
		verifiedMsg, err = d.VerifyMessage(encryptedMsg)
		if err != nil {
			return "", false, err
		}
		verified = true
	}

	//
	if encryptedMsg.To == "" {
		// Sign-only message already verified
		return verifiedMsg, verified, nil
	}

	// Get all private keys to try
	privateKeyPaths, err := d.keystore.GetAllPrivateKeys()
	if err != nil {
		return "", false, fmt.Errorf("error finding private keys: %w", err)
	}

	if len(privateKeyPaths) == 0 {
		return "", false, fmt.Errorf("no private keys found in keystore")
	}

	// Try to decrypt with each private key
	for _, ki := range privateKeyPaths {
		privateKey, err := keystore.LoadPrivateKey(ki.Bytes)
		if err != nil {
			continue // Skip invalid keys
		}

		message, err := d.DecryptMessageWithKey(encryptedMsg, privateKey)
		if err == nil {
			return message, verified, nil
		}
	}

	return "", false, fmt.Errorf("failed to decrypt message with any available private key")
}

// DecryptMessageWithKey decrypts a message using the provided private key directly
func (d *Decryptor) DecryptMessageWithKey(
	encryptedMsg *EncryptedMessage,
	privateKey any,
) (string, error) {
	// Decode the ciphertext
	combinedCiphertext, err := base64.StdEncoding.DecodeString(encryptedMsg.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

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

	// Try to find public key for this sender
	var msg string
	err = d.keystore.CollectKeyInfo(func(ki keystore.KeyInfo) error {
		if ki.KeyType == keystore.PrivateKey { // skip private keys
			return nil
		}
		if ki.KeyID != encryptedMsg.From {
			return nil
		}

		publicKey, err := keystore.LoadPublicKey(ki.Bytes)
		if err != nil {
			return err
		}
		if verifySignature(messageBytes, signature, publicKey) {
			msg = string(messageBytes)
			return io.EOF // stop iteration
		}
		return fmt.Errorf("signature verification failed")
	})
	if err != nil && err != io.EOF {
		return "", err
	} else if err == nil {
		return "", fmt.Errorf("public key not found or signature invalid")
	}
	return msg, nil
}

// ToJSON converts an EncryptedMessage to JSON bytes
func (em *EncryptedMessage) ToJSON() ([]byte, error) {
	return json.Marshal(em)
}

// resolveKeyWithIdentifier resolves a sender identifier (name@email, key ID, or name) to find the private key
func (e *Encryptor) resolveKeyWithIdentifier(
	identifier string,
	keyType keystore.KeyType,
) (*keystore.KeyInfo, error) {
	var matchingKeys []keystore.KeyInfo
	err := e.keystore.CollectKeyInfo(func(ki keystore.KeyInfo) error {
		if ki.KeyType != keyType {
			return nil
		}

		if ki.KeyID == identifier {
			matchingKeys = append(matchingKeys, ki)
			return io.EOF // stop, we got it by id
		}

		if ki.Email == identifier || ki.Name == identifier {
			matchingKeys = append(matchingKeys, ki)
			return nil
		}

		if ki.Name == identifier {
			matchingKeys = append(matchingKeys, ki)
			return nil
		}

		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("error finding %s key: %s: %w", keyType, identifier, err)
	}

	if len(matchingKeys) == 0 {
		return nil, fmt.Errorf("no %s key found for identifier: %s", keyType, identifier)
	}

	// Use the most recent key
	var latestKey *keystore.KeyInfo
	for _, key := range matchingKeys {
		if latestKey == nil || latestKey.Date.Before(key.Date) {
			latestKey = &key
		}
	}

	if latestKey == nil {
		return nil, fmt.Errorf("no %s key found for identifier: %s", keyType, identifier)
	}
	return latestKey, nil
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
