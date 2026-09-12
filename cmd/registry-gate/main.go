// Command registry-gate is the single binary that gates Docker registry
// token issuance in front of a stock Harbor pull-through cache: anonymous
// pulls are limited to a whitelist, PAT holders can pull everything.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/admin"
	"github.com/ZJUSCT/registry-gate/internal/config"
	"github.com/ZJUSCT/registry-gate/internal/gate"
	"github.com/ZJUSCT/registry-gate/internal/httpx"
	"github.com/ZJUSCT/registry-gate/internal/otellogs"
	"github.com/ZJUSCT/registry-gate/internal/portal"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/internal/token"
	"github.com/ZJUSCT/registry-gate/internal/whitelist"
)

// version is injected at build time (-ldflags "-X main.version=...");
// "dev" for local builds.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "registry-gate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/registry-gate/config.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger, shutdownLogs, err := newLogger(cfg, version)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	// Whitelist (hot reload per config; SIGHUP handled internally).
	wl, err := whitelist.New(cfg.Whitelist.Files, cfg.Whitelist.Inline,
		whitelist.WithLogger(logger), whitelist.WithHotReload(cfg.Whitelist.Reload))
	if err != nil {
		return err
	}
	defer wl.Close()

	// Persistence (OpenSQLite creates the parent directory).
	st, err := store.OpenSQLite(cfg.Storage.SqlitePath)
	if err != nil {
		return err
	}
	defer st.Close()

	// The PAT signing key is deployment-local: generated on first start
	// and kept in sqlite. Verification uses its public half.
	signKid, signKey, err := st.GetOrCreateSignKey()
	if err != nil {
		return err
	}
	verifier := &token.Verifier{
		Keys:   map[string]ed25519.PublicKey{signKid: signKey.Public().(ed25519.PublicKey)},
		Issuer: cfg.Auth.Token.Issuer,
	}
	patIssuer := &token.Issuer{Key: signKey, Kid: signKid, Issuer: cfg.Auth.Token.Issuer}

	// Metrics + shared HTTP plumbing.
	metrics := httpx.NewMetrics()
	metrics.SetWhitelistSizeFunc(wl.Size)
	metrics.SetWhitelistReloadErrorsFunc(wl.ReloadErrors)
	proxies, err := httpx.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		return err
	}

	// Gate: map the frozen config onto the gate's own GateConfig and
	// expand the message templates.
	portalURL := cfg.PortalURL()
	gcfg := gate.GateConfig{
		Path:               cfg.Gate.Path,
		AnonymousEnabled:   cfg.Gate.Anonymous.Enabled,
		ExternalURL:        cfg.Server.ExternalURL,
		HarborBaseURL:      cfg.Harbor.BaseURL,
		HarborTokenPath:    cfg.Harbor.TokenPath,
		InsecureSkipVerify: cfg.Harbor.InsecureSkipVerify,
		RequestTimeout:     cfg.Server.RequestTimeout,
		DenyMessage:        config.ExpandMessage(cfg.Gate.DenyMessage, portalURL, cfg.Server.ExternalURL),
		LoginFailedMessage: config.ExpandMessage(cfg.Gate.LoginFailedMessage, portalURL, cfg.Server.ExternalURL),
		Projects:           cfg.Projects.Map,
		PerIPRate:          cfg.Gate.AuthFailureLimit.PerIP,
		PerUsernameRate:    cfg.Gate.AuthFailureLimit.PerUsername,
	}
	if sa := cfg.Harbor.ServiceAccount; sa != nil {
		gcfg.ServiceAccountUsername = sa.Username
		gcfg.ServiceAccountPassword = sa.Password
	}
	gateHandler := gate.New(gcfg, wl, verifier, st, logger, metrics, proxies)

	// Main listener: gate + portal/admin base paths.
	mux := http.NewServeMux()
	mux.Handle(cfg.Gate.Path, gateHandler)
	// The /v2/ capability probe is answered by the gate itself (docker
	// login re-requests it with the probe PAT). In production Envoy
	// routes exactly /v2/ here and /v2/* to Harbor; locally the handler
	// 404s anything deeper than the probe.
	mux.Handle("/v2/", gateHandler.PingHandler())
	mux.Handle("/v2", gateHandler.PingHandler())

	if cfg.Portal.Enabled {
		sessionSecret, err := st.GetOrCreateSecret("portal_session_key")
		if err != nil {
			return err
		}
		portalHandler, err := portal.Handler(portal.Options{
			BasePath:         cfg.Portal.BasePath,
			ExternalURL:      cfg.Server.ExternalURL,
			OIDCIssuer:       cfg.Portal.SSO.OIDC.Issuer,
			ClientID:         cfg.Portal.SSO.OIDC.ClientID,
			ClientSecret:     cfg.Portal.SSO.OIDC.ClientSecret,
			RedirectURI:      cfg.Portal.SSO.OIDC.RedirectURI,
			Scopes:           cfg.Portal.SSO.OIDC.Scopes,
			MaxTokensPerUser: cfg.Portal.MaxTokensPerUser,
			TokenTTL:         cfg.Auth.Token.DefaultTTL,
			MaxTokenTTL:      cfg.Auth.Token.MaxTTL,
			SessionSecret:    sessionSecret,
			Store:            st,
			Issuer:           patIssuer,
		}, logger)
		if err != nil {
			return fmt.Errorf("portal: %w", err)
		}
		mux.Handle(cfg.Portal.BasePath+"/", portalHandler)
	}

	if cfg.Admin.Enabled {
		sessionSecret, err := st.GetOrCreateSecret("admin_session_key")
		if err != nil {
			return err
		}
		adminHandler, err := admin.Handler(admin.Options{
			BasePath:      cfg.Admin.BasePath,
			ExternalURL:   cfg.Server.ExternalURL,
			ClientID:      cfg.Admin.GitHub.ClientID,
			ClientSecret:  cfg.Admin.GitHub.ClientSecret,
			AllowedUsers:  cfg.Admin.GitHub.AllowedUsers,
			AllowedOrgs:   cfg.Admin.GitHub.AllowedOrgs,
			SessionSecret: sessionSecret,
			Store:         st,
		}, logger)
		if err != nil {
			return fmt.Errorf("admin: %w", err)
		}
		mux.Handle(cfg.Admin.BasePath+"/", adminHandler)
	}

	mux.Handle("/", http.NotFoundHandler())
	mainSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           httpx.RequestLogger(logger, proxies, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Internal listener: /metrics and /healthz.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", metrics.Handler())
	metricsMux.Handle("/healthz", httpx.Healthz())
	metricsSrv := &http.Server{
		Addr:              cfg.Server.MetricsListen,
		Handler:           metricsMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Usage pruning: daily, plus once shortly after startup.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	pruneDone := make(chan struct{})
	go pruneLoop(ctx, st, cfg.Storage.UsageRetention, logger, pruneDone)

	serveErr := make(chan error, 2)
	go func() {
		logger.Info("metrics listener ready", "addr", cfg.Server.MetricsListen)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- fmt.Errorf("metrics listener %s: %w", cfg.Server.MetricsListen, err)
		}
	}()
	go func() {
		if err := mainSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
		}
	}()

	logger.Info("registry-gate ready",
		"addr", cfg.Server.Listen,
		"gate_path", cfg.Gate.Path,
		"harbor", cfg.Harbor.BaseURL,
		"whitelist_entries", wl.Size(),
	)

	// Block until a listener fails or SIGTERM/SIGINT arrives.
	select {
	case err := <-serveErr:
		stop()
		_ = mainSrv.Close()
		_ = metricsSrv.Close()
		<-pruneDone
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mainSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("main server shutdown", "error", err.Error())
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics server shutdown", "error", err.Error())
	}
	// Flush any pending OTel log records (bounded; dropping is fine).
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer flushCancel()
	if err := shutdownLogs(flushCtx); err != nil {
		logger.Error("otel logs shutdown", "error", err.Error())
	}
	select {
	case <-pruneDone:
	case <-time.After(5 * time.Second):
		logger.Warn("prune loop did not stop in time")
	}
	return nil
}

// newLogger builds the slog logger requested by the [log] and
// [observability.otel_logs] sections: stdout always, plus OTLP export
// when enabled. The returned shutdown flushes pending OTel records.
func newLogger(cfg *config.Config, buildVersion string) (*slog.Logger, func(context.Context) error, error) {
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var stdout slog.Handler
	if cfg.Log.Format == "text" {
		stdout = slog.NewTextHandler(os.Stdout, opts)
	} else {
		stdout = slog.NewJSONHandler(os.Stdout, opts)
	}
	o := cfg.Observability.OtelLogs
	if o.ServiceVersion == "" {
		o.ServiceVersion = buildVersion
	}
	handler, shutdown, err := otellogs.Setup(otellogs.Config{
		Enabled:        o.Enabled,
		Endpoint:       o.Endpoint,
		Headers:        o.Headers,
		Timeout:        o.Timeout,
		MaxQueueSize:   o.MaxQueueSize,
		FlushInterval:  o.FlushInterval,
		ServiceName:    o.ServiceName,
		ServiceVersion: o.ServiceVersion,
	}, stdout, level)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(handler), shutdown, nil
}

// pruneLoop deletes usage records older than the retention window once a
// day (and once at startup, after a short grace period).
func pruneLoop(ctx context.Context, st *store.SQLite, retention time.Duration, logger *slog.Logger, done chan<- struct{}) {
	defer close(done)
	prune := func() {
		n, err := st.PruneUsage(ctx, time.Now().Add(-retention))
		if err != nil {
			logger.Error("usage prune failed", "error", err.Error())
			return
		}
		if n > 0 {
			logger.Info("usage pruned", "rows", n)
		}
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			prune()
		case <-ticker.C:
			prune()
		}
	}
}
