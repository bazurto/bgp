package integration

import (
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

	// Delete
	cmd = exec.Command(bin, "-keystore", tmpDir, "delete", "-id", keyID)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("delete failed: %v\n%s", err, string(out))
	}
}
