// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2025 RH America LLC <info@rhamerica.com>

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bazurto/bgp"
	"github.com/bazurto/bgp/pkg/keystore"
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

	if keystoreDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error determining home directory: %v\n", err)
			os.Exit(1)
		}
		keystoreDir = filepath.Join(homeDir, ".bgp", "keystore")
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
	fmt.Println("  decrypt    Decrypt a message or verify a signature")
	fmt.Println("  keygen     Generate a new key pair")
	fmt.Println("  import     Import a public or private key (auto-detected)")
	fmt.Println("  export     Export a key (public or private) from the keystore or path")
	fmt.Println("  list       List all keys in keystore")
	fmt.Println("  delete     Delete a key from the keystore (by id, key path, or owner)")
	fmt.Println()
	fmt.Println("Use 'bgp <command> -h' for command-specific help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  bgp -keystore /path/to/keys encrypt -to alice -message 'Hello' -from bob@test.com  # Sign and encrypt")
	fmt.Println("  bgp -keystore /path/to/keys encrypt -to alice -message 'Hello'                     # Encrypt only")
	fmt.Println("  bgp -keystore /path/to/keys encrypt -from bob@test.com -message 'Hello'            # Sign only")
	fmt.Println("  bgp list")
	fmt.Println("  bgp -keystore ./mykeys keygen -name john -email john@example.com")
	fmt.Println("  bgp import -key exported_key.pem                    # Use embedded metadata")
	fmt.Println("  bgp export -name alice -email alice@example.com -out /tmp/alice_pub.pem")
	fmt.Println("  bgp delete -id <KEYID>")
	fmt.Println("  bgp delete -name alice -email alice@example.com -private")
}

func encryptCommand(keystoreDir string) {
	encryptFlags := flag.NewFlagSet("encrypt", flag.ExitOnError)
	recipient := encryptFlags.String("to", "", "Recipient identifier (name, email, or key ID)")
	message := encryptFlags.String("message", "", "Message to encrypt")
	sender := encryptFlags.String("from", "", "Sender identifier (name@email, name, email, or key ID)")

	encryptFlags.Usage = func() {
		fmt.Println("Usage: bgp encrypt [-to <recipient>] [-from <sender>] [-message <message>]")
		fmt.Println()
		fmt.Println("At least one of -to or -from must be provided:")
		fmt.Println("  -to only     : Encrypt message for recipient (no signing)")
		fmt.Println("  -from only   : Sign message with sender key (no encryption)")
		fmt.Println("  -to & -from  : Both encrypt for recipient and sign with sender")
		fmt.Println()
		fmt.Println("Options:")
		encryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp encrypt -to john@example.com -message 'Hello World' -from myname@example.com  # Sign and encrypt")
		fmt.Println("  bgp encrypt -to alice -message 'Secret data'                                      # Encrypt only (by name)")
		fmt.Println("  bgp encrypt -to alice@example.com -message 'Secret data'                         # Encrypt only (by email)")
		fmt.Println("  bgp encrypt -to 420c338469ddc6c0 -message 'Secret data'                          # Encrypt only (by key ID)")
		fmt.Println("  bgp encrypt -from bob@company.com -message 'Signed message'                       # Sign only (by name@email)")
		fmt.Println("  bgp encrypt -from bob -message 'Signed message'                                   # Sign only (by name)")
		fmt.Println("  bgp encrypt -from 420c338469ddc6c0 -message 'Signed message'                      # Sign only (by key ID)")
		fmt.Println("  echo 'Secret message' | bgp encrypt -to alice -from bob@company.com               # From stdin")
	}

	if err := encryptFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing encrypt flags: %v\n", err)
		os.Exit(1)
	}

	// Require at least one of -from or -to flags
	if *recipient == "" && *sender == "" {
		fmt.Fprintf(os.Stderr, "Error: At least one of -from or -to flags must be provided\n")
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

	enc, err := bgp.EncryptCommand(keystoreDir, bgp.EncryptArgs{To: *recipient, Msg: messageText, From: *sender})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting message: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(string(enc))
}

func decryptCommand(keystoreDir string) {
	decryptFlags := flag.NewFlagSet("decrypt", flag.ExitOnError)
	inputFile := decryptFlags.String("input", "", "Input file containing encrypted message (default: stdin)")

	decryptFlags.Usage = func() {
		fmt.Println("Usage: bgp decrypt [options]")
		fmt.Println()
		fmt.Println("Automatically detects message type and performs the appropriate operation:")
		fmt.Println("  - Encrypted messages: Decrypts the message")
		fmt.Println("  - Sign-only messages: Verifies the signature and outputs the original message")
		fmt.Println()
		fmt.Println("Options:")
		decryptFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp decrypt < encrypted_message.json       # Decrypt an encrypted message")
		fmt.Println("  bgp decrypt < signed_message.json          # Verify a signed message")
		fmt.Println("  bgp decrypt -input message.json            # Process message from file")
		fmt.Println("  echo '{\"algorithm\":\"Sign-Only\"}' | bgp decrypt  # Verify from stdin")
	}

	if err := decryptFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing decrypt flags: %v\n", err)
		os.Exit(1)
	}

	// Read encrypted message from file or stdin
	var err error

	var reader io.Reader
	if *inputFile != "" {
		f, err := os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	} else {
		reader = os.Stdin
	}

	message, verified, err := bgp.DecryptCommand(keystoreDir, reader)
	if err != nil {
		if verified {
			fmt.Fprintf(os.Stderr, "Error verifying signature: %s\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error decrypting message: %s\n", err)
		}
		os.Exit(1)
	}

	// Show what operation was performed for user feedback
	if verified {
		fmt.Fprintf(os.Stderr, "✓ Signature verified successfully\n")
	}

	fmt.Print(message)

	if len(message) > 0 && message[len(message)-1] != '\n' {
		fmt.Print("\n")
	}
}

func keygenCommand(keystoreDir string) {
	keygenFlags := flag.NewFlagSet("keygen", flag.ExitOnError)
	algorithFlag := keygenFlags.String("alg", "rsa", "Algorithm (rsa or ec)")
	curveFlag := keygenFlags.String("curve", "P-256", "EC curve (P-256, P-384, P-521)")
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
	curve := keystore.Curve(*curveFlag)
	algorithm := keystore.Algorithm(*algorithFlag)

	prvKi, pubKi, err := bgp.KeygenCommand(keystoreDir, bgp.KeygenArgs{Name: *name, Email: *email, Algorithm: algorithm, Curve: curve})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key pair: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key pair generated successfully:\n")
	fmt.Printf("  Private key: %s\n", prvKi.String())
	fmt.Printf("  Public key:  %s\n", pubKi.String())
	fmt.Printf("  Key ID:      %s\n", pubKi.KeyID)
}

func importCommand(keystoreDir string) {
	importFlags := flag.NewFlagSet("import", flag.ExitOnError)
	keyFile := importFlags.String("key", "", "Path to key file to import (public or private)")
	name := importFlags.String("name", "", "Name for the key owner (optional if key contains metadata)")
	email := importFlags.String("email", "", "Email for the key owner (optional if key contains metadata)")

	importFlags.Usage = func() {
		fmt.Println("Usage: bgp import -key <keyfile> [-name <name>] [-email <email>]")
		fmt.Println()
		fmt.Println("The -name and -email flags are optional if the key file contains metadata")
		fmt.Println("from a previous BGP export operation. If provided, they will override")
		fmt.Println("any metadata found in the file.")
		fmt.Println()
		fmt.Println("Options:")
		importFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp import -key exported_key.pem                    # Use embedded metadata")
		fmt.Println("  bgp import -key alice_public.pem -name alice -email alice@company.com")
		fmt.Println("  bgp import -key /path/to/private.pem -name john -email john@example.com")
	}

	if err := importFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing import flags: %v\n", err)
		os.Exit(1)
	}

	if *keyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -key flag is required\n")
		importFlags.Usage()
		os.Exit(1)
	}

	// Determine final name and email
	finalName := *name
	finalEmail := *email

	err := bgp.ImportCommand(keystoreDir, bgp.ImportArgs{KeyFile: *keyFile, Name: finalName, Email: finalEmail})
	if err == nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func listKeysCommand(keystoreDir string) {
	listFlags := flag.NewFlagSet("list", flag.ExitOnError)

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

	keysByOwner, err := bgp.ListKeysCommand(keystoreDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys in keystore: %s\n\n", keystoreDir)
	for owner, ownerKeys := range keysByOwner {
		fmt.Printf("Owner: %s\n", owner)
		for _, key := range ownerKeys {
			fmt.Printf("  %7s Key: %s (Key ID: %s)\n", key.KeyType, key.Date, key.KeyID)
		}
		fmt.Println()
	}
}

func exportKeyCommand(keystoreDir string) {
	exportFlags := flag.NewFlagSet("export", flag.ExitOnError)
	id := exportFlags.String("id", "", "Key ID to export (as shown with -v on list)")
	out := exportFlags.String("out", "", "Output path (empty = stdout)")
	name := exportFlags.String("name", "", "Owner name (use with -email to select key)")
	email := exportFlags.String("email", "", "Owner email (use with -name to select key)")
	wantPrivate := exportFlags.Bool("private", false, "Export private key instead of public key")

	exportFlags.Usage = func() {
		fmt.Println("Usage: bgp export [-id <KEYID>] | [-name <name> -email <email>] [-out <outpath>] [-private]")
		fmt.Println()
		fmt.Println("Exports the public key by default. Use -private to export the private key instead.")
		fmt.Println()
		fmt.Println("Options:")
		exportFlags.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  bgp export -id <KEYID>                           # Export public key by Key ID")
		fmt.Println("  bgp export -name alice -email alice@example.com  # Export Alice's public key")
		fmt.Println("  bgp export -name alice -email alice@example.com -private  # Export Alice's private key")
		fmt.Println("  bgp export -id <KEYID> -out /tmp/key.pem         # Export to file")
	}

	if err := exportFlags.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing export flags: %v\n", err)
		os.Exit(1)
	}

	err := bgp.ExportKeyCommand(keystoreDir, bgp.ExportArgs{ID: *id, Name: *name, Email: *email, KeyType: keystore.KeyType(*wantPrivate), OutputFile: *out})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if *out == "-" || *out == "" {
		// already written to stdout
		return
	}
	fmt.Printf("Key exported to: %s\n", *out)
}

func deleteKeyCommand(keystoreDir string) {
	deleteFlags := flag.NewFlagSet("delete", flag.ExitOnError)
	id := deleteFlags.String("id", "", "Key ID to delete (as shown with -v on list)")
	name := deleteFlags.String("name", "", "Owner name (use with -email to select key)")
	email := deleteFlags.String("email", "", "Owner email (use with -name to select key)")
	wantPrivate := deleteFlags.Bool("private", false, "Select private key to delete")

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

	err := bgp.DeleteKeyCommand(keystoreDir,
		bgp.DeleteArgs{ID: *id, Name: *name, Email: *email, KeyType: keystore.KeyType(*wantPrivate)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
