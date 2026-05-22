package integration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyctl_matchesWebhookDenial(t *testing.T) {
	root := repoRoot(t)
	bad := filepath.Join(root, "examples", "bad-pod.yaml")
	policies := filepath.Join(root, "policies")

	cmd := exec.Command("go", "run", "./cmd/policyctl", "check", "-f", bad, "-p", policies)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected policyctl to exit non-zero")
	}
	text := string(out)
	for _, want := range []string{"deny-privileged", "require-labels", "require-limits", "image-allowlist", "deny-latest-tag"} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing rule %q:\n%s", want, text)
		}
	}
}

func TestPolicyctl_goodPod(t *testing.T) {
	root := repoRoot(t)
	good := filepath.Join(root, "examples", "good-pod.yaml")
	policies := filepath.Join(root, "policies")

	cmd := exec.Command("go", "run", "./cmd/policyctl", "check", "-f", good, "-p", policies)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0, got %v: %s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// test/integration -> repo root
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
