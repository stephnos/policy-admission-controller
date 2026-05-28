package policy

import (
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func loadBaselineEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	b, err := LoadBundle(filepath.Join("..", "..", "policies", "baseline.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return NewEvaluator(b)
}

func TestEvaluatePod_good(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": "x", "team": "y"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "registry.k8s.io/pause:3.9",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
			}},
		},
	}
	if v := e.EvaluatePod(pod, NamespaceContext{}); len(v) != 0 {
		t.Fatalf("expected admit, got %#v", v)
	}
}

func TestEvaluatePod_denyPrivileged(t *testing.T) {
	e := loadBaselineEvaluator(t)
	priv := true
	pod := baselinePod()
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &priv}
	v := e.EvaluatePod(pod, NamespaceContext{})
	assertRule(t, v, "deny-privileged")
}

func TestEvaluatePod_denyHostNetwork_exempt(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := baselinePod()
	pod.Spec.HostNetwork = true
	v := e.EvaluatePod(pod, NamespaceContext{Labels: map[string]string{
		"policy.example.com/host-network": "allowed",
	}})
	if len(v) != 0 {
		t.Fatalf("expected exempt, got %#v", v)
	}
}

func TestEvaluatePod_requireLabels(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := baselinePod()
	delete(pod.Labels, "team")
	v := e.EvaluatePod(pod, NamespaceContext{})
	assertRule(t, v, "require-labels")
}

func TestEvaluatePod_requireLimits(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := baselinePod()
	pod.Spec.Containers[0].Resources.Limits = nil
	v := e.EvaluatePod(pod, NamespaceContext{})
	assertRule(t, v, "require-limits")
}

func TestEvaluatePod_imageAllowlist(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := baselinePod()
	pod.Spec.Containers[0].Image = "docker.io/evil/malware:1.0"
	v := e.EvaluatePod(pod, NamespaceContext{})
	assertRule(t, v, "image-allowlist")
}

func TestEvaluatePod_denyLatestTag(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := baselinePod()
	pod.Spec.Containers[0].Image = "registry.k8s.io/pause:latest"
	v := e.EvaluatePod(pod, NamespaceContext{})
	assertRule(t, v, "deny-latest-tag")
}

func TestEvaluatePod_deterministicOrder(t *testing.T) {
	e := loadBaselineEvaluator(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "a"}},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:latest",
				SecurityContext: func() *corev1.SecurityContext {
					p := true
					return &corev1.SecurityContext{Privileged: &p}
				}(),
			}},
		},
	}
	v1 := e.EvaluatePod(pod, NamespaceContext{})
	v2 := e.EvaluatePod(pod, NamespaceContext{})
	if len(v1) < 2 {
		t.Fatalf("expected multiple violations, got %d", len(v1))
	}
	for i := range v1 {
		if v1[i].Rule != v2[i].Rule {
			t.Fatalf("order mismatch at %d: %s vs %s", i, v1[i].Rule, v2[i].Rule)
		}
	}
}

func baselinePod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{"app": "demo", "team": "platform"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "registry.k8s.io/pause:3.9",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
			}},
		},
	}
}

func assertRule(t *testing.T, v []Violation, id string) {
	t.Helper()
	for _, x := range v {
		if x.Rule == id {
			return
		}
	}
	t.Fatalf("missing rule %q in %#v", id, v)
}
