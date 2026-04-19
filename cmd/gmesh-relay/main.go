// Command gmesh-relay is the DERP-style relay server. Peers behind
// symmetric NAT (or with UDP blocked entirely) connect here as a fallback;
// the relay forwards encrypted WireGuard packets between them.
//
// Configuration via env vars (simpler than a separate config file for a
// single-purpose daemon):
//
//	GMESH_RELAY_ADDR    listen address (default :4500)
//	GMESH_RELAY_SECRET  shared HMAC secret (required)
//	GMESH_RELAY_LOG     log level: debug|info|warn|error (default info)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mohammad2000/Gmesh/internal/logger"
	"github.com/mohammad2000/Gmesh/internal/version"
)

func main() {
	addr := flag.String("addr", envOr("GMESH_RELAY_ADDR", ":4500"), "UDP listen address")
	secret := flag.String("secret", os.Getenv("GMESH_RELAY_SECRET"), "HMAC shared secret (required)")
	logLevel := flag.String("log-level", envOr("GMESH_RELAY_LOG", "info"), "log level")
	logFormat := flag.String("log-format", envOr("GMESH_RELAY_LOG_FORMAT", "text"), "log format: text|json")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gmesh-relay %s (%s) built %s\n", version.Version, version.Commit, version.BuildDate)
		return
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "GMESH_RELAY_SECRET is required (pass via env or --secret)")
		os.Exit(2)
	}

	log := logger.Init(*logFormat, *logLevel)
	log.Info("gmesh-relay starting",
		"version", version.Version, "commit", version.Commit, "addr", *addr)

	srv := NewServer(*addr, []byte(*secret), log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("relay exited", "error", err)
		os.Exit(1)
	}
	st := srv.Stats()
	log.Info("gmesh-relay shut down",
		"auth_ok", st.AuthOK,
		"auth_fail", st.AuthFail,
		"frames_forwarded", st.FramesForwarded,
		"bytes_forwarded", st.BytesForwarded,
		"active_sessions", st.ActiveSessions,
	)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
