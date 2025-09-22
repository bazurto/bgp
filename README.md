<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright 2025 RH America LLC <info@rhamerica.com> -->

# BGP - Cryptographic Library and CLI Tool

A Go library and CLI tool for secure message encryption and decryption with key management.

## Features

- **Hybrid Encryption**: RSA-OAEP + AES-GCM for secure and efficient encryption
- **Digital Signatures**: Sign messages for authentication and integrity verification
- **Flexible Operations**: Support for encrypt-only, sign-only, and combined sign+encrypt modes
- **Key Management**: Automatic key generation, import, and rotation support
- **Multiple Algorithms**: Support for RSA and Elliptic Curve (EC) key generation
- **CLI Tool**: Full-featured command-line interface
- **Library API**: Command functions for integration into other Go projects
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
│       ├── keystore.go
│       └── keystore_test.go
├── integration/          # Integration tests
│   └── integration_test.go
├── bgp.go                # High-level command functions
├── bgp_test.go           # Unit tests
├── scripts/              # Helper scripts
│   └── demo.sh
├── go.mod
├── go.sum
├── Makefile
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
bgp keygen -name bob -email bob@example.com -alg ec -curve P-384  # EC key

# Import a key (public or private). The program will auto-detect key type.
bgp import -key /path/to/public.pem -name bob -email bob@example.com
bgp import -key /path/to/private.pem -name alice -email alice@example.com

# List keys
bgp list            # list keys grouped by owner (Key IDs shown by default)

# Export a key by Key ID
bgp export -id <KEYID> -out /tmp/key.pem

# Export the latest public key for an owner
bgp export -name alice -email alice@example.com -out /tmp/alice_pub.pem

# Export the latest private key for an owner
bgp export -name alice -email alice@example.com -private -out /tmp/alice_priv.pem

# Delete a key
bgp delete -id <KEYID>
bgp delete -name alice -email alice@example.com -private

# Encrypt, Sign, or Both
bgp encrypt -to alice -message "Hello" -from bob@example.com     # Sign and encrypt
bgp encrypt -to alice -message "Secret data"                    # Encrypt only
bgp encrypt -from bob@example.com -message "Signed message"     # Sign only

# Decrypt or verify
bgp decrypt < encrypted_message.json    # Decrypt an encrypted message
bgp decrypt < signed_message.json       # Verify a signed message
```

### Encryption and Signing Modes

BGP supports three different operation modes:

1. **Encrypt + Sign** (`-to` and `-from`): Encrypts the message for the recipient and signs it with the sender's private key
2. **Encrypt Only** (`-to` only): Encrypts the message for the recipient without signing
3. **Sign Only** (`-from` only): Signs the message with the sender's private key without encryption

The `decrypt` command automatically detects the message type and performs the appropriate operation (decrypt, verify signature, or both).

### Notes on Key IDs

- Each key (public/private) is assigned a deterministic Key ID derived from the public key material (sha256 fingerprint, shortened). Use `bgp list -v` to view Key IDs.
- You can export a key by its Key ID with `bgp export -id <KEYID>`.

## Library Usage

The BGP package provides command functions that can be imported and used programmatically:

```go
import (
    "fmt"
    "log"
    "strings"
    "github.com/bazurto/bgp"
    "github.com/bazurto/bgp/pkg/keystore"
)

func main() {
    keystoreDir := "./keystore"
    
    // Generate key pairs
    _, _, err := bgp.KeygenCommand(keystoreDir, bgp.KeygenArgs{
        Name: "alice",
        Email: "alice@example.com",
        Algorithm: keystore.RSAAlgorithm,
        Curve: keystore.CurveP256,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    _, _, err = bgp.KeygenCommand(keystoreDir, bgp.KeygenArgs{
        Name: "bob", 
        Email: "bob@example.com",
        Algorithm: keystore.RSAAlgorithm,
        Curve: keystore.CurveP256,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt and sign a message
    message := "Hello Bob, this is Alice!"
    encrypted, err := bgp.EncryptCommand(keystoreDir, bgp.EncryptArgs{
        To: "bob@example.com",
        From: "alice@example.com", 
        Msg: message,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt the message
    reader := strings.NewReader(encrypted)
    decrypted, verified, err := bgp.DecryptCommand(keystoreDir, reader)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original: %s\n", message)
    fmt.Printf("Decrypted: %s\n", decrypted)
    fmt.Printf("Signature verified: %t\n", verified)
}
```

## Key Storage Format

Keys are stored in PEM format using the naming convention:

- Private: `{name}_{email}_{YYYYMMDD}_private.pem`
- Public:  `{name}_{email}_{YYYYMMDD}_public.pem`

Private key files are written with restrictive permissions (0600). Public keys are written with 0644.

## Building and Testing

Recommended (Makefile targets):

```bash
make build   # build CLI tool
make test    # run unit and integration tests
make demo    # run a demo sequence
```

Manual:

```bash
go build -o bgp ./cmd
go test ./...
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