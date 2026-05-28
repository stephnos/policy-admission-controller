package admission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/stephnos/policygate/internal/policy"
)

func TestHandler_admitGoodPod(t *testing.T) {
	h := testHandler(t)
	body := reviewBody(t, goodPodRaw(), false)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if review.Response == nil || !review.Response.Allowed {
		t.Fatalf("expected allowed, got %#v", review.Response)
	}
}

func TestHandler_denyBadPod(t *testing.T) {
	h := testHandler(t)
	body := reviewBody(t, badPodRaw(), false)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var review admissionv1.AdmissionReview
	_ = json.Unmarshal(rec.Body.Bytes(), &review)
	if review.Response == nil || review.Response.Allowed {
		t.Fatalf("expected denied")
	}
	if review.Response.Result == nil || review.Response.Result.Message == "" {
		t.Fatal("expected denial message")
	}
	if len(review.Response.Result.Message) < 40 {
		t.Fatalf("message too short: %q", review.Response.Result.Message)
	}
}

func TestHandler_dryRun(t *testing.T) {
	h := testHandler(t)
	dry := true
	body := reviewBody(t, badPodRaw(), dry)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var review admissionv1.AdmissionReview
	_ = json.Unmarshal(rec.Body.Bytes(), &review)
	if review.Response == nil || review.Response.Allowed {
		t.Fatal("dry-run should still evaluate and deny")
	}
}

func TestHandler_ignoreKubeSystem(t *testing.T) {
	h := testHandler(t)
	body := reviewBodyNS(t, "kube-system", badPodRaw(), false)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var review admissionv1.AdmissionReview
	_ = json.Unmarshal(rec.Body.Bytes(), &review)
	if !review.Response.Allowed {
		t.Fatal("kube-system should be ignored")
	}
}

func testHandler(t *testing.T) *Handler {
	t.Helper()
	bundle := mustBundle(t)
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{}},
	})
	return NewHandler(Config{
		Evaluator:       policy.NewEvaluator(bundle),
		NamespaceClient: client,
	})
}

func mustBundle(t *testing.T) *policy.PolicyBundle {
	t.Helper()
	b, err := policy.ParseBundle([]byte(`apiVersion: policygate.io/v1
kind: PolicyBundle
metadata:
  name: test
spec:
  rules:
    - id: deny-privileged
      type: denyPrivileged
      denyPrivileged: {}
    - id: require-labels
      type: requireLabels
      requireLabels:
        keys: [app, team]
    - id: require-limits
      type: requireResourceLimits
      requireResourceLimits:
        resources: [cpu, memory]
`))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reviewBody(t *testing.T, podJSON []byte, dryRun bool) []byte {
	return reviewBodyNS(t, "default", podJSON, dryRun)
}

func reviewBodyNS(t *testing.T, ns string, podJSON []byte, dryRun bool) []byte {
	t.Helper()
	req := &admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
		Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
		SubResource: "",
		RequestKind: &metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		RequestResource: &metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Name: "test-pod",
		Namespace: ns,
		Operation: admissionv1.Create,
		UserInfo: authenticationv1.UserInfo{Username: "test"},
		Object: runtime.RawExtension{Raw: podJSON},
	}
	if dryRun {
		req.DryRun = &dryRun
	}
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  req,
	}
	data, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func goodPodRaw() []byte {
	return []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "good", "labels": {"app": "a", "team": "b"}},
  "spec": {"containers": [{"name": "app", "image": "registry.k8s.io/pause:3.9", "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}}}]}
}`)
}

func badPodRaw() []byte {
	return []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "bad", "labels": {"app": "a"}},
  "spec": {
    "hostNetwork": true,
    "containers": [{
      "name": "app",
      "image": "nginx:latest",
      "securityContext": {"privileged": true}
    }]
  }
}`)
}
