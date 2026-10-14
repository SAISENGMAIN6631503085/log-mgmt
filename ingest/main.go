// The ingest service: receives logs (HTTP JSON, file upload, syslog via Vector), normalizes
// them into the common schema and stores them in ClickHouse.
//
// Why a separate Go service: ingestion is the one part that touches every single log, so it's
// the part that has to keep up as volume grows. Go handles many requests per CPU and ships as
// one small binary. Login, search, the dashboard and alerts stay in the Python backend, where
// requests are few and the code is mostly business rules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"logmgmt/ingest/geoip"
	"logmgmt/ingest/normalize"
	"logmgmt/ingest/server"
	"logmgmt/ingest/store"
)

const placeholderSecret = "change-me-to-a-long-random-string"

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check that the service on :8080 answers, then exit (for Docker)")
	flag.Parse()
	addr := env("INGEST_LISTEN", ":8080")
	if *healthcheck {
		// The runtime image has no shell or curl, so the binary checks itself.
		resp, err := http.Get("http://127.0.0.1" + addr + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	if err := run(addr); err != nil {
		log.Fatal(err)
	}
}

func run(addr string) error {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 || secret == placeholderSecret {
		return server.ErrWeakSecret // a weak secret would let anyone forge admin tokens
	}
	routes, err := normalize.ParseTenantMap(os.Getenv("SYSLOG_TENANT_MAP"))
	if err != nil {
		return err
	}
	retention, err := strconv.Atoi(env("RETENTION_DAYS", "7"))
	if err != nil {
		return fmt.Errorf("RETENTION_DAYS: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(env("POSTGRES_USER", "logmgmt"), os.Getenv("POSTGRES_PASSWORD")),
		Host:   env("POSTGRES_HOST", "postgres") + ":" + env("POSTGRES_PORT", "5432"),
		Path:   env("POSTGRES_DB", "logmgmt"),
	}).String()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	srv := &server.Server{
		Config: server.Config{
			JWTSecret:     secret,
			SyslogToken:   os.Getenv("SYSLOG_INGEST_TOKEN"),
			TenantRoutes:  routes,
			DefaultTenant: env("DEFAULT_TENANT", "demoA"),
			RetentionDays: retention,
		},
		Store: store.New(env("CLICKHOUSE_URL", "http://clickhouse:8123"), env("CLICKHOUSE_DB", "logmgmt"),
			env("CLICKHOUSE_USER", "logmgmt"), os.Getenv("CLICKHOUSE_PASSWORD")),
		Keys:  server.PostgresKeys{Pool: pool},
		GeoIP: geoip.Open(env("GEOIP_DB", "/app/geoip/dbip-country-lite.mmdb")),
		Now:   time.Now,
	}
	httpServer := &http.Server{Addr: addr, Handler: srv.Routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done() // on docker stop: finish the requests in flight, then exit
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("ingest listening on %s", addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
