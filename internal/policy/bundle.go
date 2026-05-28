package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	expectedAPIVersion = "policygate.io/v1"
	expectedKind       = "PolicyBundle"
)

// LoadBundle reads a PolicyBundle from a YAML file.
func LoadBundle(path string) (*PolicyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy bundle %q: %w", path, err)
	}
	return ParseBundle(data)
}

// LoadBundleDir loads the first *.yaml / *.yml file in dir (single bundle per dir).
func LoadBundleDir(dir string) (*PolicyBundle, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %q: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy YAML files in %q", dir)
	}
	if len(paths) > 1 {
		// Prefer baseline.yaml when multiple files exist.
		for _, p := range paths {
			if filepath.Base(p) == "baseline.yaml" {
				return LoadBundle(p)
			}
		}
	}
	return LoadBundle(paths[0])
}

// ParseBundle unmarshals and validates a PolicyBundle.
func ParseBundle(data []byte) (*PolicyBundle, error) {
	var b PolicyBundle
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse policy bundle: %w", err)
	}
	if err := validateBundle(&b); err != nil {
		return nil, err
	}
	normalizeRules(&b)
	return &b, nil
}

func validateBundle(b *PolicyBundle) error {
	if b.APIVersion != expectedAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (want %s)", b.APIVersion, expectedAPIVersion)
	}
	if b.Kind != expectedKind {
		return fmt.Errorf("unsupported kind %q (want %s)", b.Kind, expectedKind)
	}
	if b.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if len(b.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must not be empty")
	}
	seen := make(map[string]struct{}, len(b.Spec.Rules))
	for i, r := range b.Spec.Rules {
		if r.ID == "" {
			return fmt.Errorf("spec.rules[%d].id is required", i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if ruleKind(r) == "" {
			return fmt.Errorf("spec.rules[%d] (%s): unknown or empty rule type", i, r.ID)
		}
	}
	return nil
}

func ruleKind(r Rule) string {
	switch {
	case r.DenyPrivileged != nil:
		return "denyPrivileged"
	case r.DenyHostNetwork != nil:
		return "denyHostNetwork"
	case r.RequireLabels != nil:
		return "requireLabels"
	case r.RequireResourceLimits != nil:
		return "requireResourceLimits"
	case r.DenyImageAllowlist != nil:
		return "denyImageAllowlist"
	case r.DenyLatestTag != nil:
		return "denyLatestTag"
	default:
		return ""
	}
}

func normalizeRules(b *PolicyBundle) {
	for i := range b.Spec.Rules {
		if b.Spec.Rules[i].Type == "" {
			b.Spec.Rules[i].Type = ruleKind(b.Spec.Rules[i])
		}
	}
}
