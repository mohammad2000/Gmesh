package traversal

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

// ── DIRECT ─────────────────────────────────────────────────────────────

// DirectStrategy attempts a plain UDP probe to the remote endpoint. Success
// means the UDP round-trip works; WireGuard handshake verification happens
// at a higher layer.
type DirectStrategy struct {
	Probe       Prober
	DialTimeout time.Duration
	Log         *slog.Logger
}

// Prober sends a 1-byte probe to remote and returns RTT on reply.
type Prober interface {
	Probe(ctx context.Context, remoteEndpoint string, timeout time.Duration) (rtt time.Duration, err error)
}

// UDPProber is the production prober — it dials UDP and measures RTT.
type UDPProber struct {
	ProbePayload []byte // first byte should be nat.MagicByte
}

// Probe dials `remote`, sends payload, waits for echo. Returns RTT.
func (u *UDPProber) Probe(ctx context.Context, remote string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", remote)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", remote, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	payload := u.ProbePayload
	if len(payload) == 0 {
		payload = []byte{0x7E, 0xA1, 0xB2, 0xC3}
	}

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, fmt.Errorf("write probe: %w", err)
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		return 0, fmt.Errorf("read echo: %w", err)
	}
	return time.Since(start), nil
}

// Method returns MethodDirect.
func (d *DirectStrategy) Method() Method { return MethodDirect }

// Attempt tries a single direct UDP probe to the remote endpoint.
func (d *DirectStrategy) Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error) {
	if pc.RemoteEndpoint == "" {
		return &Outcome{Method: MethodDirect, Error: "remote endpoint empty"}, nil
	}
	timeout := d.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	rtt, err := d.Probe.Probe(ctx, pc.RemoteEndpoint, timeout)
	if err != nil {
		return &Outcome{Method: MethodDirect, Error: err.Error()}, nil
	}
	if d.Log != nil {
		d.Log.Debug("direct strategy succeeded", "peer_id", pc.PeerID, "rtt_ms", rtt.Milliseconds())
	}
	return &Outcome{Method: MethodDirect, Success: true, LatencyMS: rtt.Milliseconds()}, nil
}

// ── UPnP port map ──────────────────────────────────────────────────────

// UPnPStrategy asks the local IGD to map an external port to this node's
// WG listen port. Success means subsequent DIRECT strategies will work.
type UPnPStrategy struct {
	InternalPort uint16 // WG listen port
	Log          *slog.Logger
	// Leases is a running map of installed mappings keyed by external port.
	// Used to tear them down on Close.
	leases map[uint16]upnpLease
}

type upnpLease struct {
	externalPort uint16
	client       igdClient
}

// igdClient abstracts the two IGDv2 flavors we support (WANIPv1 & v2).
type igdClient interface {
	AddPortMapping(remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMapping(remoteHost string, externalPort uint16, protocol string) error
}

// Method returns MethodUPnPPortMap.
func (u *UPnPStrategy) Method() Method { return MethodUPnPPortMap }

// Attempt searches for an IGD via SSDP and installs a port mapping.
func (u *UPnPStrategy) Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error) {
	_ = pc // UPnP doesn't talk to the peer directly; peer config happens downstream

	if u.InternalPort == 0 {
		return &Outcome{Method: MethodUPnPPortMap, Error: "internal port not set"}, nil
	}

	clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err != nil || len(clients) == 0 {
		// Try v1.
		v1, _, err2 := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
		if err2 != nil || len(v1) == 0 {
			msg := "no IGD found"
			if err != nil {
				msg = err.Error()
			}
			return &Outcome{Method: MethodUPnPPortMap, Error: msg}, nil
		}
		return u.install(v1[0].ServiceClient, pc.PeerID)
	}
	return u.install(clients[0].ServiceClient, pc.PeerID)
}

func (u *UPnPStrategy) install(cli interface{}, peerID int64) (*Outcome, error) {
	_ = cli
	_ = peerID
	// Real impl: call AddPortMapping with random external port in [49152..65535],
	// record the lease, return MethodUPnPPortMap success with the external port in
	// the payload (needs Outcome extension to carry port). For Phase 2 we
	// treat UPnP success as "mapping installed" and rely on the strategy
	// engine to follow up with a DIRECT attempt using the now-open port.
	//
	// Full plumbing lands in Phase 3 together with hole-punching refinements.
	return &Outcome{Method: MethodUPnPPortMap, Error: "UPnP port-map install not yet implemented"}, nil
}

// Close tears down all installed leases. Idempotent.
func (u *UPnPStrategy) Close() error {
	for _, l := range u.leases {
		_ = l.client.DeletePortMapping("", l.externalPort, "UDP")
	}
	u.leases = nil
	return nil
}
