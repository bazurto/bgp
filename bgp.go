// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

package bgp

import (
	"fmt"
	"io"

	"github.com/bazurto/bgp/pkg/crypto"
	"github.com/bazurto/bgp/pkg/keystore"
)

type EncryptArgs struct {
	To   string
	From string
	Msg  string
}

func EncryptCommand(
	keystoreDir string,
	args EncryptArgs,
) (string, error) {

	recipient := args.To
	sender := args.From
	messageText := args.Msg

	// Require at least one of -from or -to flags
	if recipient == "" && sender == "" {
		return "", fmt.Errorf("must specify at least one of recipient or sender")
	}

	// Encrypt the message based on available flags
	var encryptedMsg *crypto.EncryptedMessage
	var err error

	// Create keystore and encryptor
	ks := keystore.New(keystoreDir)
	encryptor := crypto.NewEncryptor(ks)

	if sender != "" && recipient != "" {
		// Both flags provided: sign and encrypt
		encryptedMsg, err = encryptor.EncryptMessage(messageText, sender, recipient)
	} else if recipient != "" {
		// Only recipient provided: encrypt-only (no signing)
		encryptedMsg, err = encryptor.EncryptOnlyMessage(messageText, recipient)
	} else {
		// Only sender provided: sign-only (no encryption)
		encryptedMsg, err = encryptor.SignOnlyMessage(messageText, sender)
	}

	if err != nil {
		return "", err
	}

	// Output encrypted message as JSON
	jsonBytes, err := encryptedMsg.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to serialize encrypted message: %v", err)
	}

	return string(jsonBytes), nil
}

func DecryptCommand(
	keystoreDir string,
	input io.Reader,
) (string, bool, error) {
	// Read encrypted message from file or stdin
	var inputData []byte
	var err error

	inputData, err = io.ReadAll(input)
	if err != nil {
		return "", false, fmt.Errorf("failed to read input: %w", err)
	}

	if len(inputData) == 0 {
		return "", false, fmt.Errorf("no input data provided")
	}

	// Parse encrypted message
	encryptedMsg, err := crypto.ParseEncryptedMessage(inputData)
	if err != nil {
		return "", false, err
	}

	// Create keystore and decryptor
	ks := keystore.New(keystoreDir)
	decryptor := crypto.NewDecryptor(ks)

	// Process the message (decrypt or verify based on type)
	message, wasVerified, err := decryptor.DecryptMessage(encryptedMsg)
	if err != nil {
		return "", false, err
	}

	return message, wasVerified, nil
}

type KeygenArgs struct {
	Name      string
	Email     string
	Algorithm keystore.Algorithm
	Curve     keystore.Curve
}

func KeygenCommand(
	keystoreDir string,
	args KeygenArgs,
) (*keystore.KeyInfo, *keystore.KeyInfo, error) {
	algorithm := args.Algorithm
	curve := args.Curve
	name := args.Name
	email := args.Email
	if algorithm == "" {
		algorithm = keystore.RSAAlgorithm
	}

	if curve == "" {
		curve = keystore.CurveP256
	}

	if name == "" || email == "" {
		return nil, nil, fmt.Errorf("both name and email are required")
	}

	// Generate key pair
	privKey, pubKey, err := keystore.GenerateKeyPair(algorithm, curve)
	if err != nil {
		return nil, nil, err
	}

	// Create keystore and save keys
	ks := keystore.New(keystoreDir)
	return ks.SaveKeyPair(privKey, pubKey, name, email)
}

type ImportArgs struct {
	KeyFile string
	Name    string
	Email   string
}

func ImportCommand(
	keystoreDir string,
	args ImportArgs,
) error {
	keyFile := args.KeyFile
	name := args.Name
	email := args.Email
	// Require key file
	if keyFile == "" {
		return fmt.Errorf("key is required")
	}
	ks := keystore.New(keystoreDir)
	return ks.ImportKey(keyFile, name, email)
}

func ListKeysCommand(keystoreDir string) (map[string][]keystore.KeyInfo, error) {
	// Create keystore and collect key info
	ks := keystore.New(keystoreDir)
	keys, err := ks.CollectKeyInfoAll()
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in keystore: %s", keystoreDir)
	}

	// Group keys by owner (name + email)
	keysByOwner := make(map[string][]keystore.KeyInfo)
	for _, key := range keys {
		owner := fmt.Sprintf("%s <%s>", key.Name, key.Email)
		keysByOwner[owner] = append(keysByOwner[owner], key)
	}

	return keysByOwner, nil
}

func ListKeysSimpleCommand(keystoreDir string) ([]keystore.KeyInfo, error) {
	// Create keystore and collect key info
	ks := keystore.New(keystoreDir)
	return ks.CollectKeyInfoAll()
}

type ExportArgs struct {
	ID         string
	Name       string
	Email      string
	KeyType    keystore.KeyType
	OutputFile string
}

func ExportKeyCommand(
	keystoreDir string,
	args ExportArgs,
) error {
	id := args.ID
	name := args.Name
	email := args.Email
	keyType := args.KeyType
	out := args.OutputFile

	ks := keystore.New(keystoreDir)
	var err error

	// Resolve key by id if provided
	var matchedKey *keystore.KeyInfo
	if id != "" {
		// When using Key ID, we need to find the specific key type (private vs public)
		// Default to public key unless -private is specified
		keys, err := ks.CollectKeyInfoAll()
		if err != nil {
			return err
		}

		for _, key := range keys {
			if key.KeyID == id {
				// If we want private key and this is private, or if we want public key and this is public
				if keyType == key.KeyType {
					matchedKey = &key
					break
				}
			}
		}

		if matchedKey == nil {
			return fmt.Errorf("no %s key found with id: %s", keyType.String(), id)
		}
	} else if name != "" && email != "" {
		ki, err := ks.GetLatestKeyForOwner(name, email, keyType)
		if err != nil {
			return fmt.Errorf("error resolving key for owner: %w", err)
		}
		matchedKey = ki
	} else {
		return fmt.Errorf("must specify either id or both name and email")
	}

	err = ks.Export(*matchedKey, out)
	if err != nil {
		return err
	}
	return nil
}

type DeleteArgs struct {
	ID      string
	Name    string
	Email   string
	KeyType keystore.KeyType
}

func DeleteKeyCommand(
	keystoreDir string,
	args DeleteArgs,
) error {
	id := args.ID
	name := args.Name
	email := args.Email
	wantPrivate := args.KeyType

	ks := keystore.New(keystoreDir)

	// Resolve key by id if provided
	var resolvedKey *keystore.KeyInfo
	if id != "" {
		ki, err := ks.FindKeyByID(id, wantPrivate)
		if err != nil {
			return err
		}
		resolvedKey = ki
	}

	// If keyPath not provided, try resolving by owner name/email and type
	if resolvedKey == nil {
		if name == "" || email == "" {
			return fmt.Errorf("must specify either id or both name and email")
		}

		var err error
		if wantPrivate == keystore.PrivateKey {
			resolvedKey, err = ks.GetLatestKeyForOwner(name, email, keystore.PrivateKey)
		} else {
			resolvedKey, err = ks.GetLatestKeyForOwner(name, email, keystore.PublicKey)
		}
		if err != nil {
			return fmt.Errorf("error resolving key for owner: %w", err)
		}
	}

	return ks.Remove(*resolvedKey)
}
