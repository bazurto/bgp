package keystore

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestFindKeyByID_SaveAndFind(t *testing.T) {
	tmp, err := ioutil.TempDir("", "keystore_test")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	ks := New(tmp)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("ensure exists: %v", err)
	}

	// generate a key
	priv, pub, err := GenerateKeyPair("rsa", "", "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(priv, pub, "alice", "alice@example.com"); err != nil {
		t.Fatalf("save keypair: %v", err)
	}

	// collect info and ensure key id present
	infos, err := ks.CollectKeyInfo()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(infos) == 0 {
		t.Fatalf("no keys found")
	}

	// pick first key id and find it
	var id string
	for _, ki := range infos {
		if ki.KeyID != "" {
			id = ki.KeyID
			break
		}
	}
	if id == "" {
		t.Fatalf("no key id found in infos: %+v", infos)
	}

	found, err := ks.FindKeyByID(id)
	if err != nil {
		t.Fatalf("FindKeyByID: %v", err)
	}
	if _, err := os.Stat(found); err != nil {
		t.Fatalf("found file missing: %v", err)
	}
}

func TestImportPublicAndPrivate(t *testing.T) {
	srcDir, err := ioutil.TempDir("", "keystore_src")
	if err != nil {
		t.Fatalf("tempdir src: %v", err)
	}
	defer os.RemoveAll(srcDir)

	ksDir, err := ioutil.TempDir("", "keystore_dest")
	if err != nil {
		t.Fatalf("tempdir dest: %v", err)
	}
	defer os.RemoveAll(ksDir)

	// generate key pair to export
	priv, pub, err := GenerateKeyPair("rsa", "", "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// write public to a source file
	pubFile := filepath.Join(srcDir, "bob_public.pem")
	if err := ExportPublicKey(pub, pubFile); err != nil {
		t.Fatalf("export public: %v", err)
	}

	// write private to a source file
	privFile := filepath.Join(srcDir, "bob_private.pem")
	if err := ExportPrivateKey(priv, privFile); err != nil {
		t.Fatalf("export private: %v", err)
	}

	ks := New(ksDir)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("ensure exists: %v", err)
	}

	// Import public
	destPub, err := ks.ImportPublicKey(pubFile, "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("ImportPublicKey: %v", err)
	}
	if _, err := os.Stat(destPub); err != nil {
		t.Fatalf("imported public missing: %v", err)
	}

	// Import private
	destPriv, err := ks.ImportPrivateKey(privFile, "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("ImportPrivateKey: %v", err)
	}
	if fi, err := os.Stat(destPriv); err != nil {
		t.Fatalf("imported private missing: %v", err)
	} else {
		// ensure permissions are restrictive (owner read/write at least)
		if fi.Mode().Perm()&0600 == 0 {
			t.Fatalf("imported private file permissions not restrictive: %v", fi.Mode())
		}
	}
}
