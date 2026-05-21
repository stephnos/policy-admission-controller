package policy

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Evaluator applies a PolicyBundle to Kubernetes workload objects.
type Evaluator struct {
	bundle *PolicyBundle
}

func NewEvaluator(bundle *PolicyBundle) *Evaluator {
	return &Evaluator{bundle: bundle}
}

func (e *Evaluator) BundleName() string {
	return e.bundle.Metadata.Name
}

// EvaluatePod checks a Pod against all rules in deterministic order.
func (e *Evaluator) EvaluatePod(pod *corev1.Pod, ns NamespaceContext) []Violation {
	var out []Violation
	for _, rule := range e.bundle.Spec.Rules {
		out = append(out, e.evalRule(rule, pod, ns)...)
	}
	return out
}

func (e *Evaluator) evalRule(rule Rule, pod *corev1.Pod, ns NamespaceContext) []Violation {
	switch rule.Type {
	case "denyPrivileged":
		return checkDenyPrivileged(rule.ID, pod)
	case "denyHostNetwork":
		return checkDenyHostNetwork(rule.ID, rule.DenyHostNetwork, pod, ns)
	case "requireLabels":
		return checkRequireLabels(rule.ID, rule.RequireLabels, pod)
	case "requireResourceLimits":
		return checkRequireResourceLimits(rule.ID, rule.RequireResourceLimits, pod)
	case "denyImageAllowlist":
		return checkDenyImageAllowlist(rule.ID, rule.DenyImageAllowlist, pod)
	case "denyLatestTag":
		return checkDenyLatestTag(rule.ID, rule.DenyLatestTag, pod, ns)
	default:
		return []Violation{{
			Rule:    rule.ID,
			Path:    "",
			Message: fmt.Sprintf("internal error: unsupported rule type %q", rule.Type),
		}}
	}
}

func checkDenyPrivileged(ruleID string, pod *corev1.Pod) []Violation {
	var v []Violation
	containers := allContainers(pod)
	for i, c := range containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			path := containerPath(pod, i, c.Name) + ".securityContext.privileged"
			v = append(v, Violation{
				Rule:    ruleID,
				Path:    path,
				Message: "privileged containers are not allowed; set securityContext.privileged to false or omit it",
			})
		}
	}
	return v
}

func checkDenyHostNetwork(ruleID string, cfg *DenyHostNetworkRule, pod *corev1.Pod, ns NamespaceContext) []Violation {
	if !pod.Spec.HostNetwork {
		return nil
	}
	if namespaceExempt(ns, cfg.ExemptNamespaceLabel, cfg.ExemptLabelValue) {
		return nil
	}
	return []Violation{{
		Rule:    ruleID,
		Path:    "spec.hostNetwork",
		Message: fmt.Sprintf("hostNetwork is not allowed; remove spec.hostNetwork or label the namespace %s=%s",
			cfg.ExemptNamespaceLabel, cfg.ExemptLabelValue),
	}}
}

func checkRequireLabels(ruleID string, cfg *RequireLabelsRule, pod *corev1.Pod) []Violation {
	var v []Violation
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	for _, key := range cfg.Keys {
		if _, ok := pod.Labels[key]; !ok {
			v = append(v, Violation{
				Rule:    ruleID,
				Path:    fmt.Sprintf("metadata.labels[%q]", key),
				Message: fmt.Sprintf("required label %q is missing; add metadata.labels.%s", key, key),
			})
		} else if strings.TrimSpace(pod.Labels[key]) == "" {
			v = append(v, Violation{
				Rule:    ruleID,
				Path:    fmt.Sprintf("metadata.labels[%q]", key),
				Message: fmt.Sprintf("required label %q must be non-empty", key),
			})
		}
	}
	return v
}

func checkRequireResourceLimits(ruleID string, cfg *RequireResourceLimitsRule, pod *corev1.Pod) []Violation {
	var v []Violation
	containers := allContainers(pod)
	for i, c := range containers {
		if c.Resources.Limits == nil {
			for _, res := range cfg.Resources {
				v = append(v, missingLimitViolation(ruleID, pod, i, c.Name, res)...)
			}
			continue
		}
		for _, res := range cfg.Resources {
			if _, ok := c.Resources.Limits[corev1.ResourceName(res)]; !ok {
				v = append(v, missingLimitViolation(ruleID, pod, i, c.Name, res)...)
			} else if q := c.Resources.Limits[corev1.ResourceName(res)]; q.IsZero() {
				v = append(v, Violation{
					Rule: ruleID,
					Path: fmt.Sprintf("%s.resources.limits[%q]", containerPath(pod, i, c.Name), res),
					Message: fmt.Sprintf("set a non-zero resources.limits.%s on container %q", res, c.Name),
				})
			}
		}
	}
	return v
}

func missingLimitViolation(ruleID string, pod *corev1.Pod, idx int, name, res string) []Violation {
	example := "128Mi"
	if res == "cpu" {
		example = "100m"
	}
	return []Violation{{
		Rule:    ruleID,
		Path:    fmt.Sprintf("%s.resources.limits[%q]", containerPath(pod, idx, name), res),
		Message: fmt.Sprintf("set resources.limits.%s on container %q (e.g. resources.limits.%s: %s)", res, name, res, example),
	}}
}

func checkDenyImageAllowlist(ruleID string, cfg *DenyImageAllowlistRule, pod *corev1.Pod) []Violation {
	var v []Violation
	containers := allContainers(pod)
	for i, c := range containers {
		if imageAllowed(c.Image, cfg.AllowPrefixes) {
			continue
		}
		v = append(v, Violation{
			Rule:    ruleID,
			Path:    fmt.Sprintf("%s.image", containerPath(pod, i, c.Name)),
			Message: fmt.Sprintf("image %q is not allowed; use an image with prefix %v", c.Image, cfg.AllowPrefixes),
		})
	}
	return v
}

func checkDenyLatestTag(ruleID string, cfg *DenyLatestTagRule, pod *corev1.Pod, ns NamespaceContext) []Violation {
	if namespaceExempt(ns, cfg.ExemptNamespaceLabel, cfg.ExemptLabelValue) {
		return nil
	}
	var v []Violation
	containers := allContainers(pod)
	for i, c := range containers {
		if hasLatestTag(c.Image) {
			v = append(v, Violation{
				Rule:    ruleID,
				Path:    fmt.Sprintf("%s.image", containerPath(pod, i, c.Name)),
				Message: fmt.Sprintf("image tag :latest is not allowed for %q; pin an explicit digest or version tag, or label the namespace %s=%s",
					c.Image, cfg.ExemptNamespaceLabel, cfg.ExemptLabelValue),
			})
		}
	}
	return v
}

func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	return out
}

func containerPath(pod *corev1.Pod, idx int, name string) string {
	if idx < len(pod.Spec.Containers) {
		return fmt.Sprintf("spec.containers[%q]", name)
	}
	return fmt.Sprintf("spec.initContainers[%q]", name)
}

func imageAllowed(image string, prefixes []string) bool {
	ref := strings.TrimSpace(image)
	for _, p := range prefixes {
		if strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

func hasLatestTag(image string) bool {
	ref := strings.TrimSpace(image)
	if !strings.Contains(ref, ":") {
		return true // implicit latest
	}
	tag := ref[strings.LastIndex(ref, ":")+1:]
	if tag == "latest" {
		return true
	}
	// Handle port in registry host — only treat as latest if final segment is "latest"
	if at := strings.LastIndex(ref, "@"); at != -1 {
		return false
	}
	return tag == "latest"
}

func namespaceExempt(ns NamespaceContext, key, value string) bool {
	if key == "" {
		return false
	}
	if ns.Labels == nil {
		return false
	}
	return ns.Labels[key] == value
}

// FormatDenial renders violations for admission response and CLI output.
func FormatDenial(violations []Violation) string {
	if len(violations) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("admission denied by policygate:\n")
	for _, v := range violations {
		fmt.Fprintf(&b, "- rule %s", v.Rule)
		if v.Path != "" {
			fmt.Fprintf(&b, " (%s)", v.Path)
		}
		fmt.Fprintf(&b, ": %s\n", v.Message)
	}
	return strings.TrimRight(b.String(), "\n")
}
