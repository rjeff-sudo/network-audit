// Command server is the SME-Shield application entry point.
// It loads config, wires all dependencies, registers routes, and starts
// the HTTP server with graceful shutdown.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/handlers"
	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
	platformDB "github.com/rjeff-sudo/sme-shield/platform/db"
	"github.com/rjeff-sudo/sme-shield/platform/nvd"
)

func main() {
	// ── 1. Load config ────────────────────────────────────────────────────────
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("[main] load config: %v", err)
	}
	log.Printf("[main] config loaded — port %d, db %s", cfg.Server.Port, cfg.Server.DBPath)

	// ── 2. Open database ──────────────────────────────────────────────────────
	db, err := platformDB.Open(cfg.Server.DBPath)
	if err != nil {
		log.Fatalf("[main] open database: %v", err)
	}
	defer db.Close()

	// ── 3. Build shared dependencies ─────────────────────────────────────────
	wsHub  := hub.New()
	nvdCli := nvd.NewClient(cfg, db)
	engine := audit.NewEngine(cfg, db, nvdCli)

	// ── 4. Build handlers ─────────────────────────────────────────────────────
	scanH      := handlers.NewScanHandler(engine, wsHub)
	discoveryH := handlers.NewDiscoveryHandler(cfg, wsHub)
	historyH   := handlers.NewHistoryHandler(db)
	reportH    := handlers.NewReportHandler(db)

	// ── 5. Register routes ────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// WebSocket — browser connects here for live audit events.
	mux.HandleFunc("/ws", wsHub.ServeWS)

	// REST API
	mux.HandleFunc("/api/scan",     scanH.ServeHTTP)
	mux.HandleFunc("/api/subnet",   discoveryH.Subnet)
	mux.HandleFunc("/api/discover", discoveryH.Discover)
	mux.HandleFunc("/api/history",  historyH.List)
	mux.HandleFunc("/api/history/", routeHistory(historyH))
	mux.HandleFunc("/api/report/",  reportH.Download)

	// Static UI files — fallback to index.html for SPA routing.
	mux.Handle("/", spaHandler(cfg.Server.UIDir))

	// ── 6. Middleware chain ───────────────────────────────────────────────────
	handler := withLogging(withCORS(mux))

	// ── 7. Start background tasks ─────────────────────────────────────────────
	go runCachePruner(db, cfg)

	// ── 8. HTTP server with graceful shutdown ─────────────────────────────────
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0,            // must be 0 — WebSocket connections are long-lived
		IdleTimeout:  120 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[main] SME-Shield running → http://localhost%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[main] listen: %v", err)
		}
	}()

	<-quit
	log.Println("[main] shutting down — draining connections (10s)...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[main] forced shutdown: %v", err)
	}
	log.Println("[main] stopped cleanly")
}

// ── Route helpers ─────────────────────────────────────────────────────────────

// routeHistory dispatches /api/history/{id} to Get or Delete based on method.
func routeHistory(h *handlers.HistoryHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.Get(w, r)
		case http.MethodDelete:
			h.Delete(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	}
}

// spaHandler serves files from dir. If the requested path does not exist as a
// file, it returns index.html so the JS router can handle it client-side.
func spaHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(dir + r.URL.Path); os.IsNotExist(err) {
			http.ServeFile(w, r, dir+"/index.html")
			return
		}
		fs.ServeHTTP(w, r)
	})
}

// ── Middleware ────────────────────────────────────────────────────────────────

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[http] %s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Background tasks ──────────────────────────────────────────────────────────

// runCachePruner removes stale NVD cache rows every hour.
func runCachePruner(db *sql.DB, cfg models.Config) {
	ttl := time.Duration(cfg.NVD.CacheTTLHours) * time.Hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		n, err := nvd.PruneCache(db, ttl)
		if err != nil {
			log.Printf("[cache] prune error: %v", err)
		} else if n > 0 {
			log.Printf("[cache] pruned %d stale entries", n)
		}
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

func loadConfig(path string) (models.Config, error) {
	var cfg models.Config

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode yaml: %w", err)
	}

	// Safe defaults — protect against a partially-filled config.yaml.
	if cfg.Server.Port == 0          { cfg.Server.Port = 8080 }
	if cfg.Server.UIDir == ""        { cfg.Server.UIDir = "./ui" }
	if cfg.Server.DBPath == ""       { cfg.Server.DBPath = "./audit.db" }
	if cfg.Scanner.WorkerCount == 0  { cfg.Scanner.WorkerCount = 100 }
	if cfg.Scanner.TimeoutMs == 0    { cfg.Scanner.TimeoutMs = 500 }
	if cfg.Scanner.BannerTimeoutMs == 0 { cfg.Scanner.BannerTimeoutMs = 2000 }
	if cfg.Discovery.WorkerCount == 0 { cfg.Discovery.WorkerCount = 50 }
	if cfg.Discovery.TimeoutMs == 0  { cfg.Discovery.TimeoutMs = 800 }
	if cfg.NVD.BaseURL == ""         { cfg.NVD.BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0" }
	if cfg.NVD.CacheTTLHours == 0    { cfg.NVD.CacheTTLHours = 168 }
	if cfg.NVD.RequestDelayMs == 0   { cfg.NVD.RequestDelayMs = 600 }

	return cfg, nil
}