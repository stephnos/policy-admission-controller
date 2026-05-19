package admission

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server wraps the webhook HTTP server and metrics endpoint.
type Server struct {
	webhook *http.Server
	metrics *http.Server
	logger  *slog.Logger
}

type ServerConfig struct {
	Addr         string
	MetricsAddr  string
	CertFile     string
	KeyFile      string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Handler      http.Handler
}

func NewServer(cfg ServerConfig) *Server {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.MetricsAddr == "" {
		cfg.MetricsAddr = ":9090"
	}

	mux := http.NewServeMux()
	mux.Handle("/validate", cfg.Handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	webhook := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	metrics := &http.Server{
		Addr:         cfg.MetricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return &Server{webhook: webhook, metrics: metrics, logger: slog.Default()}
}

func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	errCh := make(chan error, 2)
	go func() {
		s.logger.Info("metrics server listening", "addr", s.metrics.Addr)
		errCh <- s.metrics.ListenAndServe()
	}()
	go func() {
		s.logger.Info("webhook server listening", "addr", s.webhook.Addr)
		errCh <- s.webhook.ListenAndServeTLS(certFile, keyFile)
	}()
	return <-errCh
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err1, err2 error
	if s.webhook != nil {
		err1 = s.webhook.Shutdown(ctx)
	}
	if s.metrics != nil {
		err2 = s.metrics.Shutdown(ctx)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *Server) SetLogger(l *slog.Logger) {
	s.logger = l
}

func WaitForShutdown(parent context.Context, srv *Server) error {
	<-parent.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}
