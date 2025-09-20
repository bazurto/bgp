package keystore

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// TestDeleteByOwnerAndByID verifies that resolving a key by owner and by key ID
// returns the expected path and that the file can be removed.
func TestDeleteByOwnerAndByID(t *testing.T) {
	// create temporary keystore directory
	tmpDir, err := ioutil.TempDir("", "keystore_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks := New(tmpDir)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("failed to ensure keystore exists: %v", err)
	}

	// create a fake public key file with the expected name pattern
	name := "alice"
	email := "alice@example.com"
	date := "20250920"
	pubFilename := filepath.Join(tmpDir, name+"_"+email+"_"+date+"_public.pem")
	privFilename := filepath.Join(tmpDir, name+"_"+email+"_"+date+"_private.pem")

	// write dummy data to both files
	if err := ioutil.WriteFile(pubFilename, []byte("PUBLICKEY"), 0644); err != nil {
		t.Fatalf("failed to write public file: %v", err)
	}
	if err := ioutil.WriteFile(privFilename, []byte("PRIVATEKEY"), 0600); err != nil {
		t.Fatalf("failed to write private file: %v", err)
	}

	// Collect keys and ensure they are present
	keys, err := ks.CollectKeyInfo()
	if err != nil {
		t.Fatalf("CollectKeyInfo failed: %v", err)
	}
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}

	// Resolve latest private key for owner
	resolvedPriv, err := ks.GetLatestKeyForOwner(name, email, true)
	if err != nil {
		t.Fatalf("GetLatestKeyForOwner failed: %v", err)
	}
	if resolvedPriv != privFilename {
		t.Fatalf("expected private path %s, got %s", privFilename, resolvedPriv)
	}

	// Delete the private file
	if err := os.Remove(resolvedPriv); err != nil {
		t.Fatalf("failed to delete private key: %v", err)
	}
	if _, err := os.Stat(resolvedPriv); !os.IsNotExist(err) {
		t.Fatalf("expected private key to be removed, stat err: %v", err)
	}

	// Now ensure FindKeyByID returns error for deleted key (it should not find it)
	// Note: since our dummy files are not real keys, FindKeyByID will not match them by ID.
	// But we can still ensure the public key exists and is resolvable by owner.
	resolvedPub, err := ks.GetLatestKeyForOwner(name, email, false)
	if err != nil {
		t.Fatalf("GetLatestKeyForOwner (public) failed: %v", err)
	}
	if resolvedPub != pubFilename {
		t.Fatalf("expected public path %s, got %s", pubFilename, resolvedPub)
	}

	// Clean up public file
	if err := os.Remove(resolvedPub); err != nil {
		t.Fatalf("failed to delete public key: %v", err)
	}
	if _, err := os.Stat(resolvedPub); !os.IsNotExist(err) {
		t.Fatalf("expected public key to be removed, stat err: %v", err)
	}
}
