<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright 2025 RH America LLC <info@rhamerica.com> -->

# BPG - Cryptographic Library and CLI Tool

A Go library and CLI tool for secure message encryption and decryption with key management.

## Features

- **Hybrid Encryption**: RSA-OAEP + AES-GCM for secure and efficient encryption
- **Key Management**: Automatic key generation, import, and rotation support
- **CLI Tool**: Full-featured command-line interface
- **Library API**: Easy-to-use Go library for integration into other projects
- **Key Rotation**: Automatic use of latest keys for encryption, all keys tried for decryption
- **Multiple Recipients**: Support for multiple public keys in keystore

## Project Structure

```
.
├── cmd/                    # CLI application
│   └── main.go            # Command-line interface
├── pkg/                   # Library packages
│   ├── crypto/           # Encryption/decryption operations
│   │   └── crypto.go
│   └── keystore/         # Key management and storage
│       └── keystore.go
├── examples/             # Usage examples
│   └── library/         # Library usage example
│       └── main.go
├── bpg.go             # High-level library API
├── go.mod
└── README.md
```

## Installation

### As a CLI tool:

```bash
go build -o bpg ./cmd
```

### As a library:

```bash
go get github.com/bazurto/bpg
```

## CLI Usage

### Basic Commands

```bash
# Generate a key pair
bpg keygen -name alice -email alice@example.com

# Import a public key
bpg import-key -key public.pem -name bob -email bob@example.com

# List all keys
bpg list-keys
bpg list-keys -v  # verbose with key IDs

# Encrypt a message
bpg encrypt -to alice -message "Hello World" -from bob@bob@example.com

# Decrypt a message
bpg decrypt < encrypted_message.json
echo '{"encrypted":"data"}' | bpg decrypt
```

### Global Options

```bash
# Use custom keystore location
bpg -keystore /path/to/keys list-keys
bpg -keystore ./secure keygen -name user -email user@domain.com

# By default, keys are stored in ~/.bpg/keystore
bpg list-keys  # Uses ~/.bpg/keystore
```

## Library Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/bazurto/bpg"
)

func main() {
    // Create a client with default keystore path (~/.bpg/keystore)
    client := bpg.NewClientWithDefaultPath()
    
    // Or create a client with custom keystore path
    // client := bpg.NewClient("./keystore")
    
    // Generate key pairs
    err := client.GenerateKeyPair("rsa", "", "alice", "alice@example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    err = client.GenerateKeyPair("rsa", "", "bob", "bob@example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt a message
    message := "Hello Bob, this is Alice!"
    encrypted, err := client.Encrypt(message, "alice@alice@example.com", "bob@example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt the message
    decrypted, err := client.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original: %s\n", message)
    fmt.Printf("Decrypted: %s\n", decrypted)
    
    // Work with JSON
    jsonData, _ := encrypted.ToJSON()
    decryptedFromJSON, _ := client.DecryptJSON(jsonData)
    fmt.Printf("From JSON: %s\n", decryptedFromJSON)
}
```

## API Documentation

### High-Level Client API

- `NewClient(keystorePath string) *Client` - Create a new client
- `Encrypt(message, sender, recipient string) (*crypto.EncryptedMessage, error)` - Encrypt a message
- `Decrypt(encryptedMsg *crypto.EncryptedMessage) (string, error)` - Decrypt a message
- `DecryptJSON(jsonData []byte) (string, error)` - Decrypt from JSON data
- `GenerateKeyPair(algorithm, curve, name, email string) error` - Generate and save key pair
- `ImportPublicKey(keyFile, name, email string) (string, error)` - Import public key
- `ListKeys() ([]keystore.KeyInfo, error)` - List all keys

### Low-Level Package APIs

#### `pkg/keystore` Package
- Key generation and management
- File I/O operations
- Key metadata parsing

#### `pkg/crypto` Package  
- Encryption/decryption operations
- Message signing and verification
- JSON serialization

## Security Features

- **RSA-OAEP + AES-GCM**: Industry-standard hybrid encryption
- **Key Rotation**: Automatically uses latest sender key, tries all keys for decryption
- **Digital Signatures**: Messages are signed for authenticity verification
- **Forward Security**: Each message uses a unique AES key
- **Secure Key Storage**: PEM-encoded keys with proper file permissions

## Key Format

Keys are stored in PEM format with standardized naming:
- Private keys: `{name}_{email}_{date}_private.pem`
- Public keys: `{name}_{email}_{date}_public.pem`

## Examples

See the `examples/` directory for complete usage examples:
- `examples/library/` - Library integration example

## Building and Testing

### Using Make (Recommended)

```bash
# Build everything (CLI + examples)
make build

# Run all checks (format, vet, test, build)
make all

# Run a quick demo
make demo

# Show all available targets
make help
```

### Manual Build

```bash
# Build CLI tool
go build -o crypt ./cmd

# Build library example
cd examples/library && go build -o library_example

# Test functionality
./library_example
```

### Available Make Targets

- `make build` - Build both CLI and examples
- `make test` - Run tests
- `make clean` - Remove built binaries
- `make fmt` - Format Go code
- `make demo` - Run a complete demonstration
- `make install` - Install CLI to GOPATH/bin
- `make release` - Build optimized release version

## License

GNU General Public License v3.0 - see LICENSE file for details.