//go:build windows

package main

import (
	"context"

	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

const winServiceName = "GritivaMesh"

func winHome() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Gritiva", "gmesh")
}

func defaultConfigPath() string { return filepath.Join(winHome(), "gmesh.yaml") }

// serviceMain runs gmeshd under the Service Control Manager when Windows
// started it as a service: stop/shutdown cancel the daemon's context and
// the log goes to %ProgramData%\Gritiva\gmesh\gmeshd.log (a service has no
// console). Returns false when started from a console.
func serviceMain() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	_ = os.MkdirAll(winHome(), 0o700)
	lp := filepath.Join(winHome(), "gmeshd.log")
	if st, err := os.Stat(lp); err == nil && st.Size() > 20<<20 {
		_ = os.Rename(lp, lp+".1")
	}
	if f, err := os.OpenFile(lp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	code := 0
	if err := svc.Run(winServiceName, &meshService{code: &code}); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		os.Exit(1)
	}
	os.Exit(code)
	return true
}

type meshService struct{ code *int }

func (s *meshService) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseContext = func() context.Context { return ctx }
	done := make(chan int, 1)
	go func() { done <- run() }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-done:
			*s.code = c
			// an exit we didn't ask for: the recovery actions start it again
			if c == 0 {
				c = 1
			}
			return true, uint32(c)
		case r := <-req:
			switch r.Cmd {
			case svc.Interrogate:
				st <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case c := <-done:
					*s.code = c
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}
