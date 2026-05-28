package exemptions

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/stephnos/policygate/internal/policy"
)

// Resolver loads namespace labels for exemption checks.
type Resolver struct {
	client kubernetes.Interface
}

func NewResolver(client kubernetes.Interface) *Resolver {
	return &Resolver{client: client}
}

func (r *Resolver) NamespaceContext(ctx context.Context, name string) (policy.NamespaceContext, error) {
	if r == nil || r.client == nil || name == "" {
		return policy.NamespaceContext{}, nil
	}
	ns, err := r.client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return policy.NamespaceContext{}, err
	}
	return policy.NamespaceContext{Labels: ns.Labels}, nil
}

// SystemNamespaces returns namespaces that should skip admission by default.
var SystemNamespaces = map[string]struct{}{
	"kube-system":          {},
	"kube-public":          {},
	"kube-node-lease":      {},
	"local-path-storage":   {},
	"policygate":           {},
}

func IsIgnoredNamespace(name string, extra []string) bool {
	if _, ok := SystemNamespaces[name]; ok {
		return true
	}
	for _, n := range extra {
		if n == name {
			return true
		}
	}
	return false
}

// LabelsFromObject extracts namespace labels when embedded in admission context.
func LabelsFromObject(ns *corev1.Namespace) policy.NamespaceContext {
	if ns == nil {
		return policy.NamespaceContext{}
	}
	return policy.NamespaceContext{Labels: ns.Labels}
}
