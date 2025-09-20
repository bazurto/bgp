package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadPrivateKey loads a private key from a PEM-encoded file, supporting both RSA and EC keys.
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

// LoadPublicKey loads a public key from a PEM-encoded file, supporting both RSA and EC keys.
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

// LoadKeysFromDirectory loads all private and public keys from a directory.
func LoadKeysFromDirectory(dir string) (map[string]interface{}, map[string]interface{}, error) {
	privKeys := make(map[string]interface{})
	pubKeys := make(map[string]interface{})

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pem") {
			if strings.Contains(info.Name(), "private") {
				key, err := LoadPrivateKey(path)
				if err != nil {
					return fmt.Errorf("failed to load private key from %s: %w", path, err)
				}
				privKeys[info.Name()] = key
			} else if strings.Contains(info.Name(), "public") {
				key, err := LoadPublicKey(path)
				if err != nil {
					return fmt.Errorf("failed to load public key from %s: %w", path, err)
				}
				pubKeys[info.Name()] = key
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return privKeys, pubKeys, nil
}

// ExportPrivateKey exports a private key to a PEM-encoded file.
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

// ExportPublicKey exports a public key to a PEM-encoded file.
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

// GenerateKeyPair generates a new RSA or EC key pair and returns the private and public keys.
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

// SaveKeyPair saves the private and public keys to files in the keystore directory.
func SaveKeyPair(privKey interface{}, pubKey any, name, email string) error {
	// Ensure keystore directory exists
	err := os.MkdirAll("keystore", 0755)
	if err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	privFilename := fmt.Sprintf("keystore/%s_%s_%s_private.pem", name, email, time.Now().Format("20060102"))
	pubFilename := fmt.Sprintf("keystore/%s_%s_%s_public.pem", name, email, time.Now().Format("20060102"))

	err = ExportPrivateKey(privKey, privFilename)
	if err != nil {
		return fmt.Errorf("failed to export private key: %w", err)
	}

	err = ExportPublicKey(pubKey, pubFilename)
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	return nil
}

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

// KeyInfo represents metadata about a key
type KeyInfo struct {
	Name      string
	Email     string
	Date      string
	Filename  string
	IsPrivate bool
}

// ParseKeyFilename extracts metadata from key filename
func ParseKeyFilename(filename string) (*KeyInfo, error) {
	// Expected format: name_email_date_type.pem
	nameWithoutExt := strings.TrimSuffix(filename, ".pem")
	parts := strings.Split(nameWithoutExt, "_")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid key filename format: %s", filename)
	}

	// Handle email addresses with @ symbol by finding the last 2 parts as date and type
	name := parts[0]
	isPrivate := strings.Contains(filename, "private")

	// The last part is the type (private/public), second to last is date
	dateIndex := len(parts) - 2
	date := parts[dateIndex]

	// Everything between name and date is the email
	emailParts := parts[1:dateIndex]
	email := strings.Join(emailParts, "_")

	return &KeyInfo{
		Name:      name,
		Email:     email,
		Date:      date,
		Filename:  filename,
		IsPrivate: isPrivate,
	}, nil
}

// FindLatestPrivateKey finds the most recent private key for the given name/email
func FindLatestPrivateKey(keystoreDir, name, email string) (string, error) {
	var latestKey *KeyInfo

	err := filepath.Walk(keystoreDir, func(path string, info os.FileInfo, err error) error {
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

	return filepath.Join(keystoreDir, latestKey.Filename), nil
}

// FindPublicKeyByRecipient finds a public key for the given recipient
func FindPublicKeyByRecipient(keystoreDir, recipient string) (string, error) {
	var foundKey string

	err := filepath.Walk(keystoreDir, func(path string, info os.FileInfo, err error) error {
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
func GetAllPrivateKeys(keystoreDir string) ([]string, error) {
	var keys []string

	err := filepath.Walk(keystoreDir, func(path string, info os.FileInfo, err error) error {
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

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "encrypt":
		encryptCommand()
	case "decrypt":
		decryptCommand()
	case "keygen":
		keygenCommand()
	case "import-key":
		importKeyCommand()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: crypt <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  encrypt    Encrypt a message")
	fmt.Println("  decrypt    Decrypt a message")
	fmt.Println("  keygen     Generate a new key pair")
	fmt.Println("  import-key Import a public key")
	fmt.Println()
	fmt.Println("Use 'crypt <command> -h' for command-specific help")
}

func encryptCommand() {
	encryptFlags := flag.NewFlagSet("encrypt", flag.ExitOnError)
	recipient := encryptFlags.String("to", "", "Recipient identifier (name or email)")
	message := encryptFlags.String("message", "", "Message to encrypt")
	sender := encryptFlags.String("from", "", "Sender identifier (name@email)")
	keystoreDir := encryptFlags.String("keystore", "keystore", "Path to keystore directory")

	encryptFlags.Usage = func() {
		fmt.Println("Usage: crypt encrypt -to <recipient> -message <message> -from <sender>")
		fmt.Println()
		fmt.Println("Options:")
		encryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  crypt encrypt -to john@example.com -message 'Hello World' -from myname@example.com")
		fmt.Println("  echo 'Secret message' | crypt encrypt -to alice -from bob@company.com")
	}

	encryptFlags.Parse(os.Args[2:])

	if *recipient == "" || *sender == "" {
		encryptFlags.Usage()
		os.Exit(1)
	}

	// Read message from stdin if not provided
	var messageText string
	if *message == "" {
		messageBytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
		messageText = strings.TrimSpace(string(messageBytes))
	} else {
		messageText = *message
	}

	if messageText == "" {
		fmt.Fprintf(os.Stderr, "No message provided\n")
		encryptFlags.Usage()
		os.Exit(1)
	}

	// Parse sender info
	senderParts := strings.SplitN(*sender, "@", 2)
	if len(senderParts) != 2 {
		fmt.Fprintf(os.Stderr, "Sender must be in format name@email\n")
		os.Exit(1)
	}
	senderName, senderEmail := senderParts[0], senderParts[1]

	// Find sender's latest private key
	privateKeyPath, err := FindLatestPrivateKey(*keystoreDir, senderName, senderEmail)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding sender's private key: %v\n", err)
		os.Exit(1)
	}

	// Find recipient's public key
	recipientKeyPath, err := FindPublicKeyByRecipient(*keystoreDir, *recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding recipient's public key: %v\n", err)
		os.Exit(1)
	}

	// Load keys
	privateKey, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
		os.Exit(1)
	}

	publicKey, err := LoadPublicKey(recipientKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", err)
		os.Exit(1)
	}

	// Encrypt the message
	encryptedMsg, err := EncryptMessage(messageText, privateKey, publicKey, *sender, *recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting message: %v\n", err)
		os.Exit(1)
	}

	// Output encrypted message as JSON
	jsonBytes, err := json.MarshalIndent(encryptedMsg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling encrypted message: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonBytes))
}

// EncryptMessage encrypts a message using hybrid encryption
func EncryptMessage(message string, senderPrivateKey, recipientPublicKey interface{}, sender, recipient string) (*EncryptedMessage, error) {
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
	signature, err := SignMessage(combinedCiphertext, senderPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return &EncryptedMessage{
		Recipient:  recipient,
		Sender:     sender,
		KeyID:      GenerateKeyID(recipientPublicKey),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Ciphertext: base64.StdEncoding.EncodeToString(combinedCiphertext),
		Signature:  base64.StdEncoding.EncodeToString(signature),
		Algorithm:  "RSA-OAEP+AES-GCM",
	}, nil
}

// SignMessage signs a message with the given private key
func SignMessage(message []byte, privateKey interface{}) ([]byte, error) {
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

func decryptCommand() {
	decryptFlags := flag.NewFlagSet("decrypt", flag.ExitOnError)
	keystoreDir := decryptFlags.String("keystore", "keystore", "Path to keystore directory")
	inputFile := decryptFlags.String("input", "", "Input file containing encrypted message (default: stdin)")

	decryptFlags.Usage = func() {
		fmt.Println("Usage: crypt decrypt [options]")
		fmt.Println()
		fmt.Println("Options:")
		decryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  crypt decrypt < encrypted_message.json")
		fmt.Println("  crypt decrypt -input encrypted_message.json")
		fmt.Println("  echo '{\"encrypted\":\"data\"}' | crypt decrypt")
	}

	decryptFlags.Parse(os.Args[2:])

	// Read encrypted message from file or stdin
	var inputData []byte
	var err error

	if *inputFile != "" {
		inputData, err = ioutil.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		inputData, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	if len(inputData) == 0 {
		fmt.Fprintf(os.Stderr, "No input data provided\n")
		decryptFlags.Usage()
		os.Exit(1)
	}

	// Parse encrypted message
	var encryptedMsg EncryptedMessage
	if err := json.Unmarshal(inputData, &encryptedMsg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing encrypted message: %v\n", err)
		os.Exit(1)
	}

	// Get all private keys to try
	privateKeyPaths, err := GetAllPrivateKeys(*keystoreDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding private keys: %v\n", err)
		os.Exit(1)
	}

	if len(privateKeyPaths) == 0 {
		fmt.Fprintf(os.Stderr, "No private keys found in keystore\n")
		os.Exit(1)
	}

	// Try to decrypt with each private key
	var decryptedMessage string
	var successful bool

	for _, keyPath := range privateKeyPaths {
		privateKey, err := LoadPrivateKey(keyPath)
		if err != nil {
			continue // Skip invalid keys
		}

		message, err := DecryptMessage(&encryptedMsg, privateKey)
		if err == nil {
			decryptedMessage = message
			successful = true
			break
		}
	}

	if !successful {
		fmt.Fprintf(os.Stderr, "Failed to decrypt message with any available private key\n")
		os.Exit(1)
	}

	fmt.Print(decryptedMessage)
}

// DecryptMessage decrypts a message using the provided private key
func DecryptMessage(encryptedMsg *EncryptedMessage, privateKey interface{}) (string, error) {
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

func keygenCommand() {
	keygenFlags := flag.NewFlagSet("keygen", flag.ExitOnError)
	algorithm := keygenFlags.String("alg", "rsa", "Algorithm (rsa or ec)")
	curve := keygenFlags.String("curve", "P-256", "EC curve (P-256, P-384, P-521)")
	name := keygenFlags.String("name", "", "Key owner name")
	email := keygenFlags.String("email", "", "Key owner email")
	keystoreDir := keygenFlags.String("keystore", "keystore", "Path to keystore directory")

	keygenFlags.Usage = func() {
		fmt.Println("Usage: crypt keygen -name <name> -email <email> [options]")
		fmt.Println()
		fmt.Println("Options:")
		keygenFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  crypt keygen -name john -email john@example.com")
		fmt.Println("  crypt keygen -name alice -email alice@company.com -alg ec -curve P-384")
	}

	keygenFlags.Parse(os.Args[2:])

	if *name == "" || *email == "" {
		keygenFlags.Usage()
		os.Exit(1)
	}

	// Generate key pair
	privKey, pubKey, err := GenerateKeyPair(*algorithm, *curve, *name, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	// Ensure keystore directory exists
	err = os.MkdirAll(*keystoreDir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore directory: %v\n", err)
		os.Exit(1)
	}

	// Save key pair to keystore
	privFilename := filepath.Join(*keystoreDir, fmt.Sprintf("%s_%s_%s_private.pem", *name, *email, time.Now().Format("20060102")))
	pubFilename := filepath.Join(*keystoreDir, fmt.Sprintf("%s_%s_%s_public.pem", *name, *email, time.Now().Format("20060102")))

	err = ExportPrivateKey(privKey, privFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}

	err = ExportPublicKey(pubKey, pubFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key pair generated successfully:\n")
	fmt.Printf("  Private key: %s\n", privFilename)
	fmt.Printf("  Public key:  %s\n", pubFilename)
	fmt.Printf("  Key ID:      %s\n", GenerateKeyID(pubKey))
}

func importKeyCommand() {
	importFlags := flag.NewFlagSet("import-key", flag.ExitOnError)
	keyFile := importFlags.String("key", "", "Path to public key file to import")
	name := importFlags.String("name", "", "Name for the imported key owner")
	email := importFlags.String("email", "", "Email for the imported key owner")
	keystoreDir := importFlags.String("keystore", "keystore", "Path to keystore directory")

	importFlags.Usage = func() {
		fmt.Println("Usage: crypt import-key -key <keyfile> -name <name> -email <email>")
		fmt.Println()
		fmt.Println("Options:")
		importFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  crypt import-key -key alice_public.pem -name alice -email alice@company.com")
		fmt.Println("  crypt import-key -key /path/to/public.key -name john -email john@example.com")
	}

	importFlags.Parse(os.Args[2:])

	if *keyFile == "" || *name == "" || *email == "" {
		importFlags.Usage()
		os.Exit(1)
	}

	// Check if source key file exists
	if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Key file does not exist: %s\n", *keyFile)
		os.Exit(1)
	}

	// Verify it's a valid public key
	_, err := LoadPublicKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading public key from %s: %v\n", *keyFile, err)
		os.Exit(1)
	}

	// Ensure keystore directory exists
	err = os.MkdirAll(*keystoreDir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore directory: %v\n", err)
		os.Exit(1)
	}

	// Copy to keystore with standardized name
	destFilename := filepath.Join(*keystoreDir, fmt.Sprintf("%s_%s_%s_public.pem", *name, *email, time.Now().Format("20060102")))

	// Read source file
	keyData, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}

	// Write to destination
	err = ioutil.WriteFile(destFilename, keyData, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key to keystore: %v\n", err)
		os.Exit(1)
	}

	// Load the key to get its ID
	publicKey, _ := LoadPublicKey(destFilename)
	keyID := GenerateKeyID(publicKey)

	fmt.Printf("Public key imported successfully:\n")
	fmt.Printf("  File: %s\n", destFilename)
	fmt.Printf("  Owner: %s <%s>\n", *name, *email)
	fmt.Printf("  Key ID: %s\n", keyID)
}
