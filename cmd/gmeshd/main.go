// Command gmeshd is the gmesh daemon. It runs as a root systemd service,
// manages the WireGuard interface, handles NAT traversal, and exposes a
// gRPC API on /run/gmesh.sock.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/engine"
	"github.com/mohammad2000/Gmesh/internal/logger"
	"github.com/mohammad2000/Gmesh/internal/rpc"
	"github.com/mohammad2000/Gmesh/internal/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/gmesh/config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gmeshd %s (%s) built %s\n", version.Version, version.Commit, version.BuildDate)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	log := logger.Init(cfg.Log.Format, cfg.Log.Level)
	log.Info("starting gmeshd",
		"version", version.Version,
		"commit", version.Commit,
		"socket", cfg.Socket.Path,
	)

	eng, err := engine.New(cfg, engine.Options{Log: log})
	if err != nil {
		log.Error("engine init failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		log.Error("engine start failed", "error", err)
		os.Exit(1)
	}

	srv := rpc.NewServer(eng, log)
	stop, err := srv.Start()
	if err != nil {
		log.Error("rpc start failed", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()
	log.Info("shutting down")

	stop()
	if err := eng.Stop(context.Background()); err != nil {
		log.Error("engine stop failed", "error", err)
	}
	log.Info("goodbye")
}
