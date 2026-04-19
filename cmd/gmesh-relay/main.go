// Command gmesh-relay is the DERP-style relay server. Peers behind
// symmetric NAT (or with UDP blocked entirely) connect here as a fallback;
// the relay forwards encrypted WireGuard packets between them.
//
// This is a stub — full implementation lands in Phase 4.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mohammad2000/Gmesh/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gmesh-relay %s (%s) built %s\n", version.Version, version.Commit, version.BuildDate)
		return
	}

	fmt.Fprintln(os.Stderr, "gmesh-relay: not yet implemented (Phase 4)")
	os.Exit(1)
}
