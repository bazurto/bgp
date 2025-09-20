// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

// Package bpg provides a high-level API for cryptographic operations
package bpg

import (
	"github.com/bazurto/bpg/pkg/crypto"
	"github.com/bazurto/bpg/pkg/keystore"
)

// Client provides a high-level interface for encryption/decryption operations
type Client struct {
	keystore  *keystore.Keystore
	encryptor *crypto.Encryptor
	decryptor *crypto.Decryptor
}

// NewClient creates a new bpg client with the specified keystore path
func NewClient(keystorePath string) *Client {
	ks := keystore.New(keystorePath)
	return &Client{
		keystore:  ks,
		encryptor: crypto.NewEncryptor(ks),
		decryptor: crypto.NewDecryptor(ks),
	}
}

// NewClientWithDefaultPath creates a new bpg client with the default keystore path
func NewClientWithDefaultPath() *Client {
	return NewClient(keystore.GetDefaultKeystorePath())
}

// Encrypt encrypts a message from sender to recipient
func (c *Client) Encrypt(message, sender, recipient string) (*crypto.EncryptedMessage, error) {
	return c.encryptor.EncryptMessage(message, sender, recipient)
}

// Decrypt decrypts an encrypted message using available private keys
func (c *Client) Decrypt(encryptedMsg *crypto.EncryptedMessage) (string, error) {
	return c.decryptor.DecryptMessage(encryptedMsg)
}

// DecryptJSON decrypts an encrypted message from JSON data
func (c *Client) DecryptJSON(jsonData []byte) (string, error) {
	encryptedMsg, err := crypto.ParseEncryptedMessage(jsonData)
	if err != nil {
		return "", err
	}
	return c.decryptor.DecryptMessage(encryptedMsg)
}

// GenerateKeyPair generates a new key pair and saves it to the keystore
func (c *Client) GenerateKeyPair(algorithm, curve, name, email string) error {
	privKey, pubKey, err := keystore.GenerateKeyPair(algorithm, curve, name, email)
	if err != nil {
		return err
	}
	return c.keystore.SaveKeyPair(privKey, pubKey, name, email)
}

// ImportPublicKey imports a public key into the keystore
func (c *Client) ImportPublicKey(keyFile, name, email string) (string, error) {
	return c.keystore.ImportPublicKey(keyFile, name, email)
}

// ListKeys returns information about all keys in the keystore
func (c *Client) ListKeys() ([]keystore.KeyInfo, error) {
	return c.keystore.CollectKeyInfo()
}

// GetKeystore returns the underlying keystore for advanced operations
func (c *Client) GetKeystore() *keystore.Keystore {
	return c.keystore
}

// GetEncryptor returns the underlying encryptor for advanced operations
func (c *Client) GetEncryptor() *crypto.Encryptor {
	return c.encryptor
}

// GetDecryptor returns the underlying decryptor for advanced operations
func (c *Client) GetDecryptor() *crypto.Decryptor {
	return c.decryptor
}
