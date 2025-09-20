package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bazurto/bpg/pkg/crypto"
	"github.com/bazurto/bpg/pkg/keystore"
)

func main() {
	// Global flags
	var keystoreDir string

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Parse global keystore flag if present
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-keystore" && i+1 < len(args) {
			keystoreDir = args[i+1]
			// Remove the flag and its value from args
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	// Set default keystore if not provided
	if keystoreDir == "" {
		keystoreDir = keystore.GetDefaultKeystorePath()
	}

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	// Update os.Args to remove the processed global flags
	os.Args = append([]string{os.Args[0], command}, args[1:]...)

	switch command {
	case "encrypt":
		encryptCommand(keystoreDir)
	case "decrypt":
		decryptCommand(keystoreDir)
	case "keygen":
		keygenCommand(keystoreDir)
	case "import-key":
		importKeyCommand(keystoreDir)
	case "list-keys":
		listKeysCommand(keystoreDir)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: bpg [global-options] <command> [command-options]")
	fmt.Println()
	fmt.Println("Global Options:")
	fmt.Println("  -keystore <dir>  Path to keystore directory (default: ~/.bpg/keystore)")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  encrypt    Encrypt a message")
	fmt.Println("  decrypt    Decrypt a message")
	fmt.Println("  keygen     Generate a new key pair")
	fmt.Println("  import-key Import a public key")
	fmt.Println("  list-keys  List all keys in keystore")
	fmt.Println()
	fmt.Println("Use 'bpg <command> -h' for command-specific help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  bpg -keystore /path/to/keys encrypt -to alice -message 'Hello' -from bob@test.com")
	fmt.Println("  bpg list-keys")
	fmt.Println("  bpg -keystore ./mykeys keygen -name john -email john@example.com")
}

func encryptCommand(keystoreDir string) {
	encryptFlags := flag.NewFlagSet("encrypt", flag.ExitOnError)
	recipient := encryptFlags.String("to", "", "Recipient identifier (name or email)")
	message := encryptFlags.String("message", "", "Message to encrypt")
	sender := encryptFlags.String("from", "", "Sender identifier (name@email)")

	encryptFlags.Usage = func() {
		fmt.Println("Usage: bpg encrypt -to <recipient> -message <message> -from <sender>")
		fmt.Println()
		fmt.Println("Options:")
		encryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bpg encrypt -to john@example.com -message 'Hello World' -from myname@example.com")
		fmt.Println("  echo 'Secret message' | bpg encrypt -to alice -from bob@company.com")
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

	// Create keystore and encryptor
	ks := keystore.New(keystoreDir)
	encryptor := crypto.NewEncryptor(ks)

	// Encrypt the message
	encryptedMsg, err := encryptor.EncryptMessage(messageText, *sender, *recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting message: %v\n", err)
		os.Exit(1)
	}

	// Output encrypted message as JSON
	jsonBytes, err := encryptedMsg.ToJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling encrypted message: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonBytes))
}

func decryptCommand(keystoreDir string) {
	decryptFlags := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inputFile := decryptFlags.String("input", "", "Input file containing encrypted message (default: stdin)")

	decryptFlags.Usage = func() {
		fmt.Println("Usage: bpg decrypt [options]")
		fmt.Println()
		fmt.Println("Options:")
		decryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bpg decrypt < encrypted_message.json")
		fmt.Println("  bpg decrypt -input encrypted_message.json")
		fmt.Println("  echo '{\"encrypted\":\"data\"}' | bpg decrypt")
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
	encryptedMsg, err := crypto.ParseEncryptedMessage(inputData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing encrypted message: %v\n", err)
		os.Exit(1)
	}

	// Create keystore and decryptor
	ks := keystore.New(keystoreDir)
	decryptor := crypto.NewDecryptor(ks)

	// Decrypt the message
	message, err := decryptor.DecryptMessage(encryptedMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting message: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(message)
}

func keygenCommand(keystoreDir string) {
	keygenFlags := flag.NewFlagSet("keygen", flag.ExitOnError)
	algorithm := keygenFlags.String("alg", "rsa", "Algorithm (rsa or ec)")
	curve := keygenFlags.String("curve", "P-256", "EC curve (P-256, P-384, P-521)")
	name := keygenFlags.String("name", "", "Key owner name")
	email := keygenFlags.String("email", "", "Key owner email")

	keygenFlags.Usage = func() {
		fmt.Println("Usage: bpg keygen -name <name> -email <email> [options]")
		fmt.Println()
		fmt.Println("Options:")
		keygenFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bpg keygen -name john -email john@example.com")
		fmt.Println("  bpg keygen -name alice -email alice@company.com -alg ec -curve P-384")
	}

	keygenFlags.Parse(os.Args[2:])

	if *name == "" || *email == "" {
		keygenFlags.Usage()
		os.Exit(1)
	}

	// Generate key pair
	privKey, pubKey, err := keystore.GenerateKeyPair(*algorithm, *curve, *name, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	// Create keystore and save keys
	ks := keystore.New(keystoreDir)
	err = ks.SaveKeyPair(privKey, pubKey, *name, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving key pair: %v\n", err)
		os.Exit(1)
	}

	// Generate output paths for display
	privFilename := filepath.Join(keystoreDir, fmt.Sprintf("%s_%s_%s_private.pem", *name, *email, time.Now().Format("20060102")))
	pubFilename := filepath.Join(keystoreDir, fmt.Sprintf("%s_%s_%s_public.pem", *name, *email, time.Now().Format("20060102")))

	fmt.Printf("Key pair generated successfully:\n")
	fmt.Printf("  Private key: %s\n", privFilename)
	fmt.Printf("  Public key:  %s\n", pubFilename)
	fmt.Printf("  Key ID:      %s\n", keystore.GenerateKeyID(pubKey))
}

func importKeyCommand(keystoreDir string) {
	importFlags := flag.NewFlagSet("import-key", flag.ExitOnError)
	keyFile := importFlags.String("key", "", "Path to public key file to import")
	name := importFlags.String("name", "", "Name for the imported key owner")
	email := importFlags.String("email", "", "Email for the imported key owner")

	importFlags.Usage = func() {
		fmt.Println("Usage: bpg import-key -key <keyfile> -name <name> -email <email>")
		fmt.Println()
		fmt.Println("Options:")
		importFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bpg import-key -key alice_public.pem -name alice -email alice@company.com")
		fmt.Println("  bpg import-key -key /path/to/public.key -name john -email john@example.com")
	}

	importFlags.Parse(os.Args[2:])

	if *keyFile == "" || *name == "" || *email == "" {
		importFlags.Usage()
		os.Exit(1)
	}

	// Create keystore and import key
	ks := keystore.New(keystoreDir)
	destFilename, err := ks.ImportPublicKey(*keyFile, *name, *email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error importing key: %v\n", err)
		os.Exit(1)
	}

	// Load the key to get its ID
	publicKey, _ := keystore.LoadPublicKey(destFilename)
	keyID := keystore.GenerateKeyID(publicKey)

	fmt.Printf("Public key imported successfully:\n")
	fmt.Printf("  File: %s\n", destFilename)
	fmt.Printf("  Owner: %s <%s>\n", *name, *email)
	fmt.Printf("  Key ID: %s\n", keyID)
}

func listKeysCommand(keystoreDir string) {
	listFlags := flag.NewFlagSet("list-keys", flag.ExitOnError)
	showPrivate := listFlags.Bool("private", false, "Show private keys")
	showPublic := listFlags.Bool("public", false, "Show public keys")
	verbose := listFlags.Bool("v", false, "Verbose output with key IDs and file paths")

	listFlags.Usage = func() {
		fmt.Println("Usage: bpg list-keys [options]")
		fmt.Println()
		fmt.Println("Options:")
		listFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bpg list-keys                    # Show all keys")
		fmt.Println("  bpg list-keys -private           # Show only private keys")
		fmt.Println("  bpg list-keys -public            # Show only public keys")
		fmt.Println("  bpg list-keys -v                 # Show verbose information")
	}

	listFlags.Parse(os.Args[2:])

	// If neither private nor public is specified, show both
	if !*showPrivate && !*showPublic {
		*showPrivate = true
		*showPublic = true
	}

	// Create keystore and collect key info
	ks := keystore.New(keystoreDir)
	keys, err := ks.CollectKeyInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading keystore: %v\n", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Printf("No keys found in keystore: %s\n", keystoreDir)
		return
	}

	// Group keys by owner (name + email)
	keysByOwner := make(map[string][]keystore.KeyInfo)
	for _, key := range keys {
		owner := fmt.Sprintf("%s <%s>", key.Name, key.Email)
		keysByOwner[owner] = append(keysByOwner[owner], key)
	}

	fmt.Printf("Keys in keystore: %s\n\n", keystoreDir)

	for owner, ownerKeys := range keysByOwner {
		fmt.Printf("Owner: %s\n", owner)

		for _, key := range ownerKeys {
			if (key.IsPrivate && *showPrivate) || (!key.IsPrivate && *showPublic) {
				keyType := "Public"
				if key.IsPrivate {
					keyType = "Private"
				}

				if *verbose {
					// Load key to get ID
					keyPath := filepath.Join(keystoreDir, key.Filename)
					var keyID string
					if key.IsPrivate {
						if privKey, err := keystore.LoadPrivateKey(keyPath); err == nil {
							// For private key, get the public key to generate ID
							switch pk := privKey.(type) {
							case *rsa.PrivateKey:
								keyID = keystore.GenerateKeyID(&pk.PublicKey)
							case *ecdsa.PrivateKey:
								keyID = keystore.GenerateKeyID(&pk.PublicKey)
							default:
								keyID = "unknown"
							}
						} else {
							keyID = "error"
						}
					} else {
						if pubKey, err := keystore.LoadPublicKey(keyPath); err == nil {
							keyID = keystore.GenerateKeyID(pubKey)
						} else {
							keyID = "error"
						}
					}

					fmt.Printf("  %s Key: %s (Key ID: %s)\n", keyType, key.Date, keyID)
					fmt.Printf("    File: %s\n", key.Filename)
				} else {
					fmt.Printf("  %s Key: %s\n", keyType, key.Date)
				}
			}
		}
		fmt.Println()
	}
}
