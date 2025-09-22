package bgp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bazurto/bgp/pkg/keystore"
)

func TestEncryptingAndDecryptingForAnotherKeyStoreNoVerify(t *testing.T) {
	expected := "Hello World!"
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	ks1 := keystore.New(filepath.Join(dir1, "keystore1"))
	ks2 := keystore.New(filepath.Join(dir2, "keystore2"))

	// generate key pair to export
	priv1, pub1, _ := keystore.GenerateKeyPair("rsa", "")
	priv2, pub2, _ := keystore.GenerateKeyPair("rsa", "")

	// write private to a source file
	priv1Bytes, _ := keystore.PrivateKeyToBytes(priv1)
	pub1Bytes, _ := keystore.PublicKeyToBytes(pub1)
	os.WriteFile(filepath.Join(dir1, "private1.pem"), priv1Bytes, 0600)
	os.WriteFile(filepath.Join(dir1, "public1.pem"), pub1Bytes, 0644)

	priv2Bytes, _ := keystore.PrivateKeyToBytes(priv2)
	pub2Bytes, _ := keystore.PublicKeyToBytes(pub2)
	os.WriteFile(filepath.Join(dir2, "private2.pem"), priv2Bytes, 0600)
	os.WriteFile(filepath.Join(dir2, "public2.pem"), pub2Bytes, 0644)

	if _, _, err := ks1.SaveKeyPair(priv1, pub1, "ks1", "ks1@example.com"); err != nil {
		t.Fatalf("save keypair 1: %v", err)
	}
	if _, _, err := ks2.SaveKeyPair(priv2, pub2, "ks2", "ks2@example.com"); err != nil {
		t.Fatalf("save keypair 2: %v", err)
	}

	publicKi, _ := ks2.FindPublicKeyByRecipient("ks2@example.com")
	exportedKeyFile := filepath.Join(dir2, "exported_pub.json")
	ks2.Export(*publicKi, exportedKeyFile)
	ks1.ImportKey(exportedKeyFile, "", "")

	keystore1 := filepath.Join(dir1, "keystore1")
	keystore2 := filepath.Join(dir2, "keystore2")
	encrypted, err := EncryptCommand(keystore1, EncryptArgs{To: "ks2@example.com", Msg: expected})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	result, verified, err := DecryptCommand(keystore2, bytes.NewBuffer([]byte(encrypted)))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if result != expected {
		t.Fatalf("decrypted message mismatch: got %q, want %q", result, expected)
	}
	if verified {
		t.Fatalf("message should not be verified (not signed)")
	}
}

func TestEncryptingAndDecryptingForAnotherKeyStoreWithVerify(t *testing.T) {
	expected := "Hello World!"
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	keystore1 := filepath.Join(dir1, "keystore1")
	keystore2 := filepath.Join(dir2, "keystore2")

	// generate key pair to export
	_, ks1Pub, _ := KeygenCommand(keystore1, KeygenArgs{Name: "ks1", Email: "ks1@example.com"})
	_, ks2Pub, _ := KeygenCommand(keystore2, KeygenArgs{Name: "ks2", Email: "ks2@example.com"})

	exportedPub2File := filepath.Join(dir1, "exported_pub2.json")
	exportedPub1File := filepath.Join(dir2, "exported_pub1.json")

	ExportKeyCommand(keystore2, ExportArgs{ID: ks2Pub.KeyID, KeyType: keystore.PublicKey, OutputFile: exportedPub2File})
	ExportKeyCommand(keystore1, ExportArgs{ID: ks1Pub.KeyID, KeyType: keystore.PublicKey, OutputFile: exportedPub1File})

	ImportCommand(keystore1, ImportArgs{KeyFile: exportedPub2File}) // import pubkey2 in keystore1
	ImportCommand(keystore2, ImportArgs{KeyFile: exportedPub1File}) // import pubkey1 in keystore2

	encrypted, err := EncryptCommand(
		keystore1,
		EncryptArgs{
			To:   "ks2@example.com",
			Msg:  expected,
			From: "ks1@example.com",
		},
	)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	result, verified, err := DecryptCommand(keystore2, bytes.NewBuffer([]byte(encrypted)))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if result != expected {
		t.Fatalf("decrypted message mismatch: got %q, want %q", result, expected)
	}
	if !verified {
		t.Fatalf("message should be verified (signed)")
	}
}
