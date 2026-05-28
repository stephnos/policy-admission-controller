package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"

	"github.com/stephnos/policygate/internal/exemptions"
	"github.com/stephnos/policygate/internal/policy"
)

const maxBodyBytes = 3 << 20 // 3 MiB

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(admissionv1.AddToScheme(scheme))
}

var codecs = serializer.NewCodecFactory(scheme)

// Config configures the validating admission handler.
type Config struct {
	Evaluator       *policy.Evaluator
	NamespaceClient kubernetes.Interface
	IgnoreNamespaces []string
	Logger          *slog.Logger
}

// Handler serves Kubernetes ValidatingAdmissionWebhook requests.
type Handler struct {
	cfg Config
}

func NewHandler(cfg Config) *Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handler{cfg: cfg}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		latencySeconds.Observe(time.Since(start).Seconds())
	}()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to read body")
		policyEvalErrorsTotal.Inc()
		requestsTotal.WithLabelValues("error").Inc()
		return
	}

	var review admissionv1.AdmissionReview
	if _, _, err := codecs.UniversalDeserializer().Decode(body, nil, &review); err != nil {
		h.writeError(w, http.StatusBadRequest, "failed to decode AdmissionReview")
		policyEvalErrorsTotal.Inc()
		requestsTotal.WithLabelValues("error").Inc()
		return
	}

	resp := h.handleReview(r.Context(), &review)
	review.Response = resp

	review.Response.UID = review.Request.UID
	review.Kind = "AdmissionReview"
	review.APIVersion = "admission.k8s.io/v1"

	out, err := json.Marshal(review)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to encode response")
		requestsTotal.WithLabelValues("error").Inc()
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)

	result := "allowed"
	if !resp.Allowed {
		result = "denied"
	}
	requestsTotal.WithLabelValues(result).Inc()
}

func (h *Handler) handleReview(ctx context.Context, review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	req := review.Request
	if req == nil {
		policyEvalErrorsTotal.Inc()
		return deniedResponse("", "missing AdmissionReview.request")
	}

	ns := req.Namespace
	name := req.Name
	uid := string(req.UID)

	if exemptions.IsIgnoredNamespace(ns, h.cfg.IgnoreNamespaces) {
		h.logDecision(uid, ns, name, true, nil, req.DryRun)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	if req.Kind.Group != "" || req.Kind.Version != "v1" || req.Kind.Kind != "Pod" {
		h.logDecision(uid, ns, name, true, nil, req.DryRun)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		h.logDecision(uid, ns, name, true, nil, req.DryRun)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	var pod corev1.Pod
	if _, _, err := codecs.UniversalDeserializer().Decode(req.Object.Raw, nil, &pod); err != nil {
		policyEvalErrorsTotal.Inc()
		h.logDecision(uid, ns, name, false, nil, req.DryRun)
		return deniedResponse(uid, fmt.Sprintf("failed to decode Pod: %v", err))
	}

	nsCtx, err := h.namespaceContext(ctx, ns)
	if err != nil {
		policyEvalErrorsTotal.Inc()
		h.cfg.Logger.Error("namespace lookup failed", "uid", uid, "namespace", ns, "error", err)
		return deniedResponse(uid, fmt.Sprintf("failed to load namespace %q for policy exemptions: %v", ns, err))
	}

	violations := h.cfg.Evaluator.EvaluatePod(&pod, nsCtx)
	if len(violations) > 0 {
		msg := policy.FormatDenial(violations)
		h.logDecision(uid, ns, name, false, violations, req.DryRun)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: msg,
			},
		}
	}

	h.logDecision(uid, ns, name, true, nil, req.DryRun)
	return &admissionv1.AdmissionResponse{Allowed: true}
}

func (h *Handler) namespaceContext(ctx context.Context, name string) (policy.NamespaceContext, error) {
	if h.cfg.NamespaceClient == nil {
		return policy.NamespaceContext{}, nil
	}
	resolver := exemptions.NewResolver(h.cfg.NamespaceClient)
	return resolver.NamespaceContext(ctx, name)
}

func deniedResponse(uid, msg string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: msg,
		},
	}
}

func (h *Handler) logDecision(uid, ns, name string, allowed bool, violations []policy.Violation, dryRun *bool) {
	attrs := []any{
		"uid", uid,
		"namespace", ns,
		"name", name,
		"allowed", allowed,
	}
	if dryRun != nil && *dryRun {
		attrs = append(attrs, "dry_run", true)
	}
	if !allowed && len(violations) > 0 {
		ids := make([]string, len(violations))
		for i, v := range violations {
			ids[i] = v.Rule
		}
		attrs = append(attrs, "rule_ids", ids)
	}
	h.cfg.Logger.Info("admission decision", attrs...)
}

func (h *Handler) writeError(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}
