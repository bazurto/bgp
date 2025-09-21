package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEndToEnd builds the bgp binary and runs keygen -> list -> delete (dry-run and actual)
func TestEndToEnd(t *testing.T) {
	// build binary from project root (one level up from integration/)
	bin := filepath.Join(os.TempDir(), "bgp-integration-bin")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd")
	// run build from repo root (parent of integration/)
	cmd.Dir = ".."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build bgp: %v", err)
	}
	defer os.Remove(bin)

	tmpDir, err := os.MkdirTemp("", "bgp_integration")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate a key
	cmd = exec.Command(bin, "-keystore", tmpDir, "keygen", "-name", "inttest", "-email", "int@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, string(out))
	}

	// List keys and capture Key ID
	cmd = exec.Command(bin, "-keystore", tmpDir, "list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list failed: %v\n%s", err, string(out))
	}

	re := regexp.MustCompile(`Key ID:\s*([0-9a-fA-F]+)`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		t.Fatalf("could not find Key ID in list output: %s", string(out))
	}
	keyID := matches[1]

	// Dry-run delete
	cmd = exec.Command(bin, "-keystore", tmpDir, "delete", "-id", keyID, "-dry-run")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run delete failed: %v\n%s", err, string(out))
	}
	if !bytes.Contains(out, []byte("Would move to trash")) && !bytes.Contains(out, []byte("Would permanently delete")) {
		t.Fatalf("unexpected dry-run output: %s", string(out))
	}

	// Actual delete (move to trash)
	cmd = exec.Command(bin, "-keystore", tmpDir, "delete", "-id", keyID, "-yes")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("delete failed: %v\n%s", err, string(out))
	}
	if !bytes.Contains(out, []byte("Moved to trash")) {
		t.Fatalf("unexpected delete output: %s", string(out))
	}

	// Ensure .trash exists and contains a file
	trashDir := filepath.Join(tmpDir, ".trash")
	infos, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("expected trash contents, err: %v", err)
	}
	if len(infos) == 0 {
		t.Fatalf("expected trash to contain at least one file")
	}
}
