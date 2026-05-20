package policy

// PolicyBundle is a versioned set of workload security rules.
type PolicyBundle struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Metadata   BundleMetadata    `yaml:"metadata" json:"metadata"`
	Spec       PolicyBundleSpec  `yaml:"spec" json:"spec"`
}

type BundleMetadata struct {
	Name string `yaml:"name" json:"name"`
}

type PolicyBundleSpec struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Rule is a single declarative check. Exactly one rule type should be set.
type Rule struct {
	ID   string `yaml:"id" json:"id"`
	Type string `yaml:"type" json:"type"`

	DenyPrivileged      *DenyPrivilegedRule      `yaml:"denyPrivileged,omitempty" json:"denyPrivileged,omitempty"`
	DenyHostNetwork     *DenyHostNetworkRule     `yaml:"denyHostNetwork,omitempty" json:"denyHostNetwork,omitempty"`
	RequireLabels       *RequireLabelsRule       `yaml:"requireLabels,omitempty" json:"requireLabels,omitempty"`
	RequireResourceLimits *RequireResourceLimitsRule `yaml:"requireResourceLimits,omitempty" json:"requireResourceLimits,omitempty"`
	DenyImageAllowlist  *DenyImageAllowlistRule  `yaml:"denyImageAllowlist,omitempty" json:"denyImageAllowlist,omitempty"`
	DenyLatestTag       *DenyLatestTagRule       `yaml:"denyLatestTag,omitempty" json:"denyLatestTag,omitempty"`
}

type DenyPrivilegedRule struct{}
type DenyHostNetworkRule struct {
	ExemptNamespaceLabel string `yaml:"exemptNamespaceLabel" json:"exemptNamespaceLabel"`
	ExemptLabelValue     string `yaml:"exemptLabelValue" json:"exemptLabelValue"`
}
type RequireLabelsRule struct {
	Keys []string `yaml:"keys" json:"keys"`
}
type RequireResourceLimitsRule struct {
	Resources []string `yaml:"resources" json:"resources"`
}
type DenyImageAllowlistRule struct {
	AllowPrefixes []string `yaml:"allowPrefixes" json:"allowPrefixes"`
}
type DenyLatestTagRule struct {
	ExemptNamespaceLabel string `yaml:"exemptNamespaceLabel" json:"exemptNamespaceLabel"`
	ExemptLabelValue     string `yaml:"exemptLabelValue" json:"exemptLabelValue"`
}

// Violation is a single policy failure with an actionable message.
type Violation struct {
	Rule    string `json:"rule"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// NamespaceContext carries exemption metadata for namespace-scoped rules.
type NamespaceContext struct {
	Labels map[string]string
}
