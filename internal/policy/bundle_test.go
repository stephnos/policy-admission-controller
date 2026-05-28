package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundle(t *testing.T) {
	b, err := LoadBundle(filepath.Join("..", "..", "policies", "baseline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Metadata.Name != "baseline" {
		t.Fatalf("name: got %q", b.Metadata.Name)
	}
	if len(b.Spec.Rules) != 6 {
		t.Fatalf("rules: got %d", len(b.Spec.Rules))
	}
}

func TestParseBundle_validation(t *testing.T) {
	_, err := ParseBundle([]byte(`apiVersion: v1
kind: PolicyBundle
metadata:
  name: x
spec:
  rules: []`))
	if err == nil {
		t.Fatal("expected error for bad apiVersion")
	}
}

func TestLoadBundleDir_prefersBaseline(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "other.yaml"), []byte(minimalBundle("other")), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "baseline.yaml"), []byte(minimalBundle("baseline")), 0o644)
	b, err := LoadBundleDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.Metadata.Name != "baseline" {
		t.Fatalf("got %q", b.Metadata.Name)
	}
}

func minimalBundle(name string) string {
	return `apiVersion: policygate.io/v1
kind: PolicyBundle
metadata:
  name: ` + name + `
spec:
  rules:
    - id: deny-privileged
      type: denyPrivileged
      denyPrivileged: {}
`
}
