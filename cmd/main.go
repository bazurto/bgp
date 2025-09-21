// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
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

	// Allow quick help: bgp -h or bgp --help
	if len(os.Args) >= 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printUsage()
		os.Exit(0)
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
	case "import":
		importCommand(keystoreDir)
	case "export":
		exportKeyCommand(keystoreDir)
	case "list":
		listKeysCommand(keystoreDir)
	case "list-keys":
		fmt.Fprintln(os.Stderr, "Warning: 'list-keys' is deprecated; use 'list' instead")
		listKeysCommand(keystoreDir)
	case "delete":
		deleteKeyCommand(keystoreDir)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: bgp [global-options] <command> [command-options]")
	fmt.Println()
	fmt.Println("Global Options:")
	fmt.Println("  -keystore <dir>  Path to keystore directory (default: ~/.bgp/keystore)")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  encrypt    Encrypt a message")
	fmt.Println("  decrypt    Decrypt a message")
	fmt.Println("  keygen     Generate a new key pair")
	fmt.Println("  import     Import a public or private key (auto-detected)")
	fmt.Println("  export     Export a key (public or private) from the keystore or path")
	fmt.Println("  list       List all keys in keystore")
	fmt.Println("  delete     Delete a key from the keystore (by id, key path, or owner)")
	fmt.Println()
	fmt.Println("Use 'bgp <command> -h' for command-specific help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  bgp -keystore /path/to/keys encrypt -to alice -message 'Hello' -from bob@test.com")
	fmt.Println("  bgp list")
	fmt.Println("  bgp -keystore ./mykeys keygen -name john -email john@example.com")
	fmt.Println("  bgp import -key /path/to/private.pem -name alice -email alice@example.com")
	fmt.Println("  bgp export -key alice_alice@example.com_20250920_public.pem -out /tmp/alice_pub.pem")
	fmt.Println("  bgp delete -id <KEYID>")
	fmt.Println("  bgp delete -name alice -email alice@example.com -private")
}

func encryptCommand(keystoreDir string) {
	encryptFlags := flag.NewFlagSet("encrypt", flag.ExitOnError)
	recipient := encryptFlags.String("to", "", "Recipient identifier (name or email)")
	message := encryptFlags.String("message", "", "Message to encrypt")
	sender := encryptFlags.String("from", "", "Sender identifier (name@email)")

	encryptFlags.Usage = func() {
		fmt.Println("Usage: bgp encrypt -to <recipient> -message <message> -from <sender>")
		fmt.Println()
		fmt.Println("Options:")
		encryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp encrypt -to john@example.com -message 'Hello World' -from myname@example.com")
		fmt.Println("  echo 'Secret message' | bgp encrypt -to alice -from bob@company.com")
	}

	if err := encryptFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing encrypt flags: %v\n", err)
		os.Exit(1)
	}

	if *recipient == "" || *sender == "" {
		encryptFlags.Usage()
		os.Exit(1)
	}

	// Read message from stdin if not provided
	var messageText string
	if *message == "" {
		messageBytes, err := io.ReadAll(os.Stdin)
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
		fmt.Println("Usage: bgp decrypt [options]")
		fmt.Println()
		fmt.Println("Options:")
		decryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp decrypt < encrypted_message.json")
		fmt.Println("  bgp decrypt -input encrypted_message.json")
		fmt.Println("  echo '{\"encrypted\":\"data\"}' | bgp decrypt")
	}

	if err := decryptFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing decrypt flags: %v\n", err)
		os.Exit(1)
	}

	// Read encrypted message from file or stdin
	var inputData []byte
	var err error

	if *inputFile != "" {
		inputData, err = os.ReadFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
	} else {
		inputData, err = io.ReadAll(os.Stdin)
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
		fmt.Println("Usage: bgp keygen -name <name> -email <email> [options]")
		fmt.Println()
		fmt.Println("Options:")
		keygenFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp keygen -name john -email john@example.com")
		fmt.Println("  bgp keygen -name alice -email alice@company.com -alg ec -curve P-384")
	}

	if err := keygenFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing keygen flags: %v\n", err)
		os.Exit(1)
	}

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

func importCommand(keystoreDir string) {
	importFlags := flag.NewFlagSet("import", flag.ExitOnError)
	keyFile := importFlags.String("key", "", "Path to key file to import (public or private)")
	name := importFlags.String("name", "", "Name for the key owner")
	email := importFlags.String("email", "", "Email for the key owner")

	importFlags.Usage = func() {
		fmt.Println("Usage: bgp import -key <keyfile> -name <name> -email <email>")
		fmt.Println()
		fmt.Println("Options:")
		importFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp import -key alice_public.pem -name alice -email alice@company.com")
		fmt.Println("  bgp import -key /path/to/private.pem -name john -email john@example.com")
	}

	if err := importFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing import flags: %v\n", err)
		os.Exit(1)
	}

	if *keyFile == "" || *name == "" || *email == "" {
		importFlags.Usage()
		os.Exit(1)
	}

	ks := keystore.New(keystoreDir)

	// Try to detect public key first
	if _, err := keystore.LoadPublicKey(*keyFile); err == nil {
		dest, err := ks.ImportPublicKey(*keyFile, *name, *email)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error importing public key: %v\n", err)
			os.Exit(1)
		}
		pubKey, _ := keystore.LoadPublicKey(dest)
		fmt.Printf("Public key imported successfully:\n")
		fmt.Printf("  File: %s\n", dest)
		fmt.Printf("  Owner: %s <%s>\n", *name, *email)
		fmt.Printf("  Key ID: %s\n", keystore.GenerateKeyID(pubKey))
		return
	}

	// If not a public key, try private
	if _, err := keystore.LoadPrivateKey(*keyFile); err == nil {
		dest, err := ks.ImportPrivateKey(*keyFile, *name, *email)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error importing private key: %v\n", err)
			os.Exit(1)
		}
		privKey, _ := keystore.LoadPrivateKey(dest)
		var keyID string
		switch pk := privKey.(type) {
		case *rsa.PrivateKey:
			keyID = keystore.GenerateKeyID(&pk.PublicKey)
		case *ecdsa.PrivateKey:
			keyID = keystore.GenerateKeyID(&pk.PublicKey)
		default:
			keyID = "unknown"
		}
		fmt.Printf("Private key imported successfully:\n")
		fmt.Printf("  File: %s\n", dest)
		fmt.Printf("  Owner: %s <%s>\n", *name, *email)
		fmt.Printf("  Key ID: %s\n", keyID)
		return
	}

	fmt.Fprintf(os.Stderr, "Error: provided file is not a recognized public or private key: %s\n", *keyFile)
	os.Exit(1)
}

func listKeysCommand(keystoreDir string) {
	listFlags := flag.NewFlagSet("list", flag.ExitOnError)
	showPrivate := listFlags.Bool("private", false, "Show private keys")
	showPublic := listFlags.Bool("public", false, "Show public keys")
	verbose := listFlags.Bool("v", false, "Verbose output: include file paths (Key IDs are shown by default)")

	listFlags.Usage = func() {
		fmt.Println("Usage: bgp list [options]")
		fmt.Println()
		fmt.Println("Options:")
		listFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp list                    # Show all keys")
		fmt.Println("  bgp list -private           # Show only private keys")
		fmt.Println("  bgp list -public            # Show only public keys")
		fmt.Println("  bgp list -v                 # Show file paths in addition to Key IDs")
	}

	if err := listFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing list flags: %v\n", err)
		os.Exit(1)
	}

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

				// Key ID is shown by default
				keyID := key.KeyID
				if keyID == "" {
					keyID = "unknown"
				}
				fmt.Printf("  %s Key: %s (Key ID: %s)\n", keyType, key.Date, keyID)
				if *verbose {
					fmt.Printf("    File: %s\n", key.Filename)
				}
			}
		}
		fmt.Println()
	}
}

// ...existing code...

func exportKeyCommand(keystoreDir string) {
	exportFlags := flag.NewFlagSet("export", flag.ExitOnError)
	id := exportFlags.String("id", "", "Key ID to export (as shown with -v on list-keys)")
	keyPath := exportFlags.String("key", "", "Key filename in keystore or absolute path")
	out := exportFlags.String("out", "", "Output path (empty = stdout)")
	name := exportFlags.String("name", "", "Owner name (use with -email to select key)")
	email := exportFlags.String("email", "", "Owner email (use with -name to select key)")
	wantPrivate := exportFlags.Bool("private", false, "Select private key")

	exportFlags.Usage = func() {
		fmt.Println("Usage: bgp export -key <keyfile> [-out <outpath>]")
		fmt.Println()
		fmt.Println("Options:")
		exportFlags.PrintDefaults()
	}

	if err := exportFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing export flags: %v\n", err)
		os.Exit(1)
	}

	ks := keystore.New(keystoreDir)

	// Resolve key by id if provided
	resolvedKey := *keyPath
	if *id != "" {
		found, err := ks.FindKeyByID(*id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding key by id: %v\n", err)
			os.Exit(1)
		}
		resolvedKey = found
	}

	// If keyPath not provided, try resolving by owner name/email and type
	if resolvedKey == "" {
		if *name == "" || *email == "" {
			exportFlags.Usage()
			os.Exit(1)
		}

		// determine requested type: default to public if neither specified
		priv := *wantPrivate
		// if neither private nor public were requested, default to public (i.e. priv=false)

		var err error
		if priv {
			resolvedKey, err = ks.GetLatestKeyForOwner(*name, *email, true)
		} else {
			resolvedKey, err = ks.GetLatestKeyForOwner(*name, *email, false)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key for owner: %v\n", err)
			os.Exit(1)
		}
	}

	dest, err := ks.ExportKey(resolvedKey, *out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting key: %v\n", err)
		os.Exit(1)
	}

	if dest == "-" {
		// already written to stdout
		return
	}
	fmt.Printf("Key exported to: %s\n", dest)
}

func deleteKeyCommand(keystoreDir string) {
	deleteFlags := flag.NewFlagSet("delete", flag.ExitOnError)
	id := deleteFlags.String("id", "", "Key ID to delete (as shown with -v on list)")
	keyPath := deleteFlags.String("key", "", "Key filename in keystore or absolute path to delete")
	name := deleteFlags.String("name", "", "Owner name (use with -email to select key)")
	email := deleteFlags.String("email", "", "Owner email (use with -name to select key)")
	wantPrivate := deleteFlags.Bool("private", false, "Select private key to delete")
	yes := deleteFlags.Bool("yes", false, "Skip confirmation prompt and delete immediately")
	purge := deleteFlags.Bool("purge", false, "Permanently remove the file instead of moving to trash")
	dryRun := deleteFlags.Bool("dry-run", false, "Show what would be deleted/moved without making changes")

	deleteFlags.Usage = func() {
		fmt.Println("Usage: bgp delete [options]")
		fmt.Println()
		fmt.Println("Options:")
		deleteFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp delete -id <KEYID>")
		fmt.Println("  bgp delete -name alice -email alice@example.com -private")
	}

	if err := deleteFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing delete flags: %v\n", err)
		os.Exit(1)
	}

	ks := keystore.New(keystoreDir)

	// Resolve key by id if provided
	resolvedKey := *keyPath
	if *id != "" {
		found, err := ks.FindKeyByID(*id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding key by id: %v\n", err)
			os.Exit(1)
		}
		resolvedKey = found
	}

	// If keyPath not provided, try resolving by owner name/email and type
	if resolvedKey == "" {
		if *name == "" || *email == "" {
			deleteFlags.Usage()
			os.Exit(1)
		}

		// determine requested type: default to public if neither specified
		priv := *wantPrivate
		// default to public when both flags are false (i.e. priv remains false)

		var err error
		if priv {
			resolvedKey, err = ks.GetLatestKeyForOwner(*name, *email, true)
		} else {
			resolvedKey, err = ks.GetLatestKeyForOwner(*name, *email, false)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key for owner: %v\n", err)
			os.Exit(1)
		}
	}

	// Dry-run: show action and return (do this before interactive confirmation)
	if *dryRun {
		if *purge {
			fmt.Printf("Would permanently delete: %s\n", resolvedKey)
		} else {
			fmt.Printf("Would move to trash: %s\n", resolvedKey)
		}
		return
	}

	// Confirm deletion unless -yes provided
	if !*yes {
		fmt.Fprintf(os.Stderr, "About to delete key: %s\n", resolvedKey)
		fmt.Fprintf(os.Stderr, "Are you sure? (y/N): ")
		var resp string
		if _, err := fmt.Scanln(&resp); err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Failed to read confirmation: %v\n", err)
			os.Exit(1)
		}
		resp = strings.TrimSpace(strings.ToLower(resp))
		if resp != "y" && resp != "yes" {
			fmt.Println("Aborted.")
			return
		}
	}

	// Delete or move to trash
	if *purge {
		if err := os.Remove(resolvedKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting key file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Permanently deleted: %s\n", resolvedKey)
		return
	}

	// Move to .trash inside keystore
	moved, err := ks.MoveToTrash(resolvedKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error moving key to trash: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Moved to trash: %s\n", moved)
}
