package keystore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindKeyByID_SaveAndFind(t *testing.T) {
	tmp, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	ks := New(tmp)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("ensure exists: %v", err)
	}

	// generate a key
	priv, pub, err := GenerateKeyPair("rsa", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, _, err := ks.SaveKeyPair(priv, pub, "alice", "alice@example.com"); err != nil {
		t.Fatalf("save keypair: %v", err)
	}

	// collect info and ensure key id present
	infos, err := ks.CollectKeyInfoAll()
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

	private, err := ks.FindKeyByID(id, PrivateKey)
	if err != nil {
		t.Fatalf("FindKeyByID private: %v", err)
	}

	public, err := ks.FindKeyByID(id, PublicKey)
	if err != nil {
		t.Fatalf("FindKeyByID public: %v", err)
	}
	if private == nil {
		t.Fatalf("FindKeyByID no private key found")
	}
	if public == nil {
		t.Fatalf("FindKeyByID no public key found")
	}
}

func TestImportPublicAndPrivate(t *testing.T) {
	srcDir := t.TempDir()

	ksDir, err := os.MkdirTemp("", "keystore_dest")
	if err != nil {
		t.Fatalf("tempdir dest: %v", err)
	}
	defer os.RemoveAll(ksDir)

	// generate key pair to export
	priv, pub, err := GenerateKeyPair("rsa", "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// write public to a source file
	if _, err := PublicKeyToBytes(pub); err != nil {
		t.Fatalf("export public: %v", err)
	}

	// write private to a source file
	privFile := filepath.Join(srcDir, "bob_private.pem")
	if b, err := PrivateKeyToBytes(priv); err != nil {
		t.Fatalf("export private: %v", err)
	} else {
		if err := os.WriteFile(privFile, b, 0600); err != nil {
			t.Fatalf("write private: %v", err)
		}
	}

	ks := New(ksDir)
	if err := ks.EnsureExists(); err != nil {
		t.Fatalf("ensure exists: %v", err)
	}

	// Import private
	err = ks.ImportKey(privFile, "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("ImportPrivateKey: %v", err)
	}

	keys, _ := ks.GetAllPrivateKeys()
	var ki *KeyInfo
	for _, k := range keys {
		if k.Name == "bob" {
			ki = &k
			break
		}
	}

	if ki == nil {
		t.Fatalf("imported key not found in keystore")
	}
}
