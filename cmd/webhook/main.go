package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/stephnos/policygate/internal/admission"
	"github.com/stephnos/policygate/internal/policy"
)

func main() {
	var (
		listenAddr      = flag.String("addr", ":8443", "webhook listen address")
		metricsAddr     = flag.String("metrics-addr", ":9090", "metrics listen address")
		certFile        = flag.String("tls-cert", getenv("TLS_CERT_FILE", "/certs/tls.crt"), "TLS certificate file")
		keyFile         = flag.String("tls-key", getenv("TLS_KEY_FILE", "/certs/tls.key"), "TLS private key file")
		policyPath      = flag.String("policy", getenv("POLICY_PATH", "/policies"), "policy bundle file or directory")
		ignoreNS        = flag.String("ignore-namespaces", getenv("IGNORE_NAMESPACES", ""), "comma-separated namespaces to skip")
		kubeconfig      = flag.String("kubeconfig", "", "kubeconfig path (in-cluster if empty)")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	bundle, err := loadPolicy(*policyPath)
	if err != nil {
		logger.Error("load policy", "error", err)
		os.Exit(1)
	}
	logger.Info("loaded policy bundle", "name", bundle.Metadata.Name, "rules", len(bundle.Spec.Rules))

	var client kubernetes.Interface
	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		logger.Error("kubernetes config", "error", err)
		os.Exit(1)
	}
	client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error("kubernetes client", "error", err)
		os.Exit(1)
	}

	evaluator := policy.NewEvaluator(bundle)
	handler := admission.NewHandler(admission.Config{
		Evaluator:        evaluator,
		NamespaceClient:  client,
		IgnoreNamespaces: splitCSV(*ignoreNS),
		Logger:           logger,
	})

	srv := admission.NewServer(admission.ServerConfig{
		Addr:        *listenAddr,
		MetricsAddr: *metricsAddr,
		Handler:     handler,
	})
	srv.SetLogger(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			logger.Error("server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	if err := srv.Shutdown(context.Background()); err != nil {
		logger.Error("shutdown", "error", err)
		os.Exit(1)
	}
}

func loadPolicy(path string) (*policy.PolicyBundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return policy.LoadBundleDir(path)
	}
	return policy.LoadBundle(path)
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
