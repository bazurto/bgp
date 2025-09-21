<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright 2025 RH America LLC <info@rhamerica.com> -->

# BGP - Cryptographic Library and CLI Tool

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
├── bgp.go                # High-level library API
├── go.mod
└── README.md
```

## Installation

### As a CLI tool:

```bash
go build -o bgp ./cmd
```

### As a library:

```bash
go get github.com/bazurto/bgp
```

## CLI Usage

### Global Options

```bash
# Use custom keystore location
bgp -keystore /path/to/keys <command> [options]

# Default keystore directory is: ~/.bgp/keystore
```

### Basic Commands

```bash
# Generate a new key pair
bgp keygen -name alice -email alice@example.com

# Import a key (public or private). The program will auto-detect key type.
bgp import -key /path/to/public.pem -name bob -email bob@example.com
bgp import -key /path/to/private.pem -name alice -email alice@example.com

# List keys
bgp list            # list keys grouped by owner (Key IDs shown by default)
bgp list -v         # verbose: also shows file paths

# Export a key by filename or owner
bgp export -key alice_alice@example.com_20250920_public.pem -out /tmp/alice_pub.pem

# Export the latest public key for an owner
bgp export -name alice -email alice@example.com -public -out /tmp/alice_pub.pem

# Export by Key ID (as shown with `list -v`)
bgp export -id <KEYID> -out /tmp/key.pem

# Delete a key
# You can delete a key by Key ID, by filename/path, or by owner (name+email).
# The command will prompt for confirmation unless you pass `-yes`.
bgp delete -id <KEYID>
bgp delete -name alice -email alice@example.com -private
bgp delete -key alice_alice@example.com_20250920_private.pem

# Encrypt / Decrypt
bgp encrypt -to alice -message "Hello" -from bob@example.com
bgp decrypt < encrypted_message.json
```

### Notes on Key IDs

- Each key (public/private) is assigned a deterministic Key ID derived from the public key material (sha256 fingerprint, shortened). Use `bgp list -v` to view Key IDs.
- You can export a key by its Key ID with `bgp export -id <KEYID>`.

## Library Usage

```go
import (
    "fmt"
    "log"
    "github.com/bazurto/bgp"
)

func main() {
    // Create a client with default keystore path (~/.bgp/keystore)
    client := bgp.NewClientWithDefaultPath()
    
    // Or create a client with custom keystore path
    // client := bgp.NewClient("./keystore")
    
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
    encrypted, err := client.Encrypt(message, "alice@example.com", "bob@example.com")
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
}
```

## Key Storage Format

Keys are stored in PEM format using the naming convention:

- Private: `{name}_{email}_{YYYYMMDD}_private.pem`
- Public:  `{name}_{email}_{YYYYMMDD}_public.pem`

Private key files are written with restrictive permissions (0600). Public keys are written with 0644.

## Examples

See `examples/library/` for a small program that demonstrates generating keys, encrypting and decrypting.

## Building and Testing

Recommended (Makefile targets):

```bash
make build   # build CLI and examples
make test    # run tests (if present)
make demo    # run a demo sequence
```

Manual:

```bash
go build -o bgp ./cmd
cd examples/library && go build -o library_example
./library_example
```

## Quick Demo (Example Output)

The following is a short demo showing generating a key, listing keys (Key IDs shown), and exporting by Key ID. Your Key ID will differ.

```
$ bgp keygen -name demo -email demo@example.com
Key pair generated successfully:
    Private key: ~/.bgp/keystore/demo_demo@example.com_20250920_private.pem
    Public key:  ~/.bgp/keystore/demo_demo@example.com_20250920_public.pem
    Key ID:      e1d2b997644d7d6b

$ bgp list
Keys in keystore: ~/.bgp/keystore

Owner: demo <demo@example.com>
    Private Key: 20250920 (Key ID: e1d2b997644d7d6b)
    Public Key: 20250920 (Key ID: e1d2b997644d7d6b)

$ bgp export -id e1d2b997644d7d6b -out /tmp/demo_export.pem
Key exported to: /tmp/demo_export.pem
```

## License

GNU General Public License v3.0 - see `LICENSE` for details.