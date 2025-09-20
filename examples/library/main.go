package main

import (
	"fmt"
	"log"

	"github.com/bazurto/bpg"
)

func main() {
	// Create a new bpg client with a keystore path
	client := bpg.NewClient("./keystore")

	// Example 1: Generate a key pair
	fmt.Println("Generating key pair...")
	err := client.GenerateKeyPair("rsa", "", "alice", "alice@example.com")
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	err = client.GenerateKeyPair("rsa", "", "bob", "bob@example.com")
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Example 2: List available keys
	fmt.Println("\nListing keys:")
	keys, err := client.ListKeys()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	for _, key := range keys {
		keyType := "Public"
		if key.IsPrivate {
			keyType = "Private"
		}
		fmt.Printf("  %s Key: %s <%s> (%s)\n", keyType, key.Name, key.Email, key.Date)
	}

	// Example 3: Encrypt a message
	fmt.Println("\nEncrypting message...")
	message := "Hello Bob, this is a secret message from Alice!"
	encryptedMsg, err := client.Encrypt(message, "alice@alice@example.com", "bob@example.com")
	if err != nil {
		log.Fatalf("Failed to encrypt message: %v", err)
	}

	fmt.Printf("Encrypted message sender: %s\n", encryptedMsg.Sender)
	fmt.Printf("Encrypted message recipient: %s\n", encryptedMsg.Recipient)
	fmt.Printf("Message timestamp: %s\n", encryptedMsg.Timestamp)

	// Example 4: Decrypt the message
	fmt.Println("\nDecrypting message...")
	decryptedMessage, err := client.Decrypt(encryptedMsg)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", decryptedMessage)

	// Example 5: Convert to/from JSON
	fmt.Println("\nTesting JSON serialization...")
	jsonData, err := encryptedMsg.ToJSON()
	if err != nil {
		log.Fatalf("Failed to convert to JSON: %v", err)
	}

	fmt.Printf("JSON length: %d bytes\n", len(jsonData))

	// Decrypt from JSON data
	decryptedFromJSON, err := client.DecryptJSON(jsonData)
	if err != nil {
		log.Fatalf("Failed to decrypt from JSON: %v", err)
	}

	fmt.Printf("Decrypted from JSON: %s\n", decryptedFromJSON)

	fmt.Println("\nLibrary example completed successfully!")
}
