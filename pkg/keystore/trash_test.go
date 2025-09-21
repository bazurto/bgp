package keystore

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMoveToTrash(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "keystore_trash_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ks := New(tmpDir)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("failed to ensure keystore exists: %v", err)
	}

	// create a dummy file
	filePath := filepath.Join(tmpDir, "alice_alice@example.com_20250920_public.pem")
	if err := ioutil.WriteFile(filePath, []byte("pub"), 0644); err != nil {
		t.Fatalf("failed to write dummy file: %v", err)
	}

	moved, err := ks.MoveToTrash(filePath)
	if err != nil {
		t.Fatalf("MoveToTrash failed: %v", err)
	}

	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("expected moved file at %s, stat failed: %v", moved, err)
	}

	// original should not exist
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("expected original file to be removed, stat err: %v", err)
	}
}
