// Command gmeshctl is the operator CLI for gmeshd.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/version"
)

var (
	socketPath string
	outputJSON bool
)

func main() {
	root := &cobra.Command{
		Use:   "gmeshctl",
		Short: "Control and inspect the gmeshd daemon",
		Version: fmt.Sprintf("%s (%s) built %s",
			version.Version, version.Commit, version.BuildDate),
	}
	root.PersistentFlags().StringVar(&socketPath, "socket", "/run/gmesh.sock", "path to gmeshd Unix socket")
	root.PersistentFlags().BoolVar(&outputJSON, "json", false, "emit JSON instead of tabular output")

	root.AddCommand(
		statusCmd(),
		versionCmd(),
		joinCmd(),
		leaveCmd(),
		peerCmd(),
		natCmd(),
		holePunchCmd(),
		relayCmd(),
		firewallCmd(),
		scopeCmd(),
		eventsCmd(),
		healthCmd(),
		egressCmd(),
		ingressCmd(),
		quotaCmd(),
		pathCmd(),
		policyCmd(),
		mtlsCmd(),
		circuitCmd(),
		anomalyCmd(),
		l7Cmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────

func dial() (gmeshv1.GMeshClient, func(), error) {
	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", strings.TrimPrefix(addr, "unix://"))
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	return gmeshv1.NewGMeshClient(conn), func() { _ = conn.Close() }, nil
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ── Top-level commands ─────────────────────────────────────────────────

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon + mesh status",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := c.Status(ctx, &gmeshv1.StatusRequest{})
			if err != nil {
				return fmt.Errorf("status rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("joined:       %v\n", resp.Joined)
			fmt.Printf("mesh_ip:      %s\n", resp.MeshIp)
			fmt.Printf("interface:    %s\n", resp.Interface)
			fmt.Printf("peer_count:   %d\n", resp.PeerCount)
			fmt.Printf("active_peers: %d\n", resp.ActivePeers)
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show daemon version (via RPC)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := c.Version(ctx, &gmeshv1.VersionRequest{})
			if err != nil {
				return fmt.Errorf("version rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("gmeshd %s (%s) built %s\n", resp.Version, resp.Commit, resp.BuildDate)
			return nil
		},
	}
}

func joinCmd() *cobra.Command {
	var (
		meshIP, iface, cidr, nodeID string
		port                        uint16
	)
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Bring up the WireGuard interface and join the mesh",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.Join(ctx, &gmeshv1.JoinRequest{
				MeshIp:        meshIP,
				ListenPort:    uint32(port),
				InterfaceName: iface,
				NetworkCidr:   cidr,
				NodeId:        nodeID,
			})
			if err != nil {
				return fmt.Errorf("join rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("joined\npublic_key: %s\n", resp.PublicKey)
			return nil
		},
	}
	cmd.Flags().StringVar(&meshIP, "mesh-ip", "", "mesh IP to assign (e.g. 10.200.0.7)")
	cmd.Flags().StringVar(&iface, "interface", "wg-gritiva", "WireGuard interface name")
	cmd.Flags().StringVar(&cidr, "network-cidr", "10.200.0.0/16", "mesh network CIDR")
	cmd.Flags().Uint16Var(&port, "listen-port", 51820, "WireGuard listen port")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "stable node identifier (optional)")
	_ = cmd.MarkFlagRequired("mesh-ip")
	return cmd
}

func leaveCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "leave",
		Short: "Tear down the WireGuard interface and leave the mesh",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err = c.Leave(ctx, &gmeshv1.LeaveRequest{Reason: reason})
			if err != nil {
				return fmt.Errorf("leave rpc: %w", err)
			}
			fmt.Println("left mesh")
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "manual", "audit reason")
	return cmd
}

// ── Peer subcommands ──────────────────────────────────────────────────

func peerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "peer", Short: "Manage mesh peers"}
	cmd.AddCommand(peerListCmd(), peerAddCmd(), peerRemoveCmd(), peerShowCmd(), peerUpdateCmd())
	return cmd
}

func peerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all peers",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListPeers(ctx, &gmeshv1.ListPeersRequest{})
			if err != nil {
				return fmt.Errorf("list peers rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTYPE\tMESH_IP\tENDPOINT\tSTATUS\tRX\tTX\tHANDSHAKE")
			for _, p := range resp.Peers {
				hs := "-"
				if p.LastHandshakeUnix > 0 {
					hs = time.Since(time.Unix(p.LastHandshakeUnix, 0)).Round(time.Second).String() + " ago"
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
					p.Id, p.Type, p.MeshIp, p.Endpoint, p.Status, p.RxBytes, p.TxBytes, hs)
			}
			return w.Flush()
		},
	}
}

func peerAddCmd() *cobra.Command {
	var (
		id         int64
		meshIP     string
		publicKey  string
		endpoint   string
		allowedIPs []string
		keepalive  uint32
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a peer",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.AddPeer(ctx, &gmeshv1.AddPeerRequest{
				PeerId:     id,
				MeshIp:     meshIP,
				PublicKey:  publicKey,
				Endpoint:   endpoint,
				AllowedIps: allowedIPs,
				Keepalive:  keepalive,
			})
			if err != nil {
				return fmt.Errorf("add peer rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("added peer id=%d mesh_ip=%s\n", resp.Peer.Id, resp.Peer.MeshIp)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "peer ID (required)")
	cmd.Flags().StringVar(&meshIP, "mesh-ip", "", "peer's mesh IP (required)")
	cmd.Flags().StringVar(&publicKey, "public-key", "", "peer's WG public key (required)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "host:port")
	cmd.Flags().StringSliceVar(&allowedIPs, "allowed-ips", nil, "comma-separated allowed IPs (default: mesh-ip/32)")
	cmd.Flags().Uint32Var(&keepalive, "keepalive", 25, "persistent keepalive seconds")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("mesh-ip")
	_ = cmd.MarkFlagRequired("public-key")
	return cmd
}

func peerRemoveCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a peer",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.RemovePeer(ctx, &gmeshv1.RemovePeerRequest{PeerId: id}); err != nil {
				return fmt.Errorf("remove peer rpc: %w", err)
			}
			fmt.Printf("removed peer id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "peer ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func peerShowCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show a single peer",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.GetPeerStats(ctx, &gmeshv1.GetPeerStatsRequest{PeerId: id})
			if err != nil {
				return fmt.Errorf("get peer stats rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Peer)
			}
			p := resp.Peer
			fmt.Printf("id:            %d\n", p.Id)
			fmt.Printf("type:          %s\n", p.Type)
			fmt.Printf("mesh_ip:       %s\n", p.MeshIp)
			fmt.Printf("endpoint:      %s\n", p.Endpoint)
			fmt.Printf("allowed_ips:   %v\n", p.AllowedIps)
			fmt.Printf("status:        %s\n", p.Status)
			fmt.Printf("rx:            %d bytes\n", p.RxBytes)
			fmt.Printf("tx:            %d bytes\n", p.TxBytes)
			fmt.Printf("latency:       %d ms\n", p.LatencyMs)
			if p.LastHandshakeUnix > 0 {
				fmt.Printf("last handshake: %s ago\n", time.Since(time.Unix(p.LastHandshakeUnix, 0)).Round(time.Second))
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "peer ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// ── NAT + Hole-punch ──────────────────────────────────────────────────

func natCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "nat", Short: "NAT discovery + inspection"}
	discover := &cobra.Command{
		Use:   "discover",
		Short: "Run STUN-based NAT discovery",
	}
	var force bool
	discover.Flags().BoolVar(&force, "force", false, "bypass the cache")
	discover.RunE = func(_ *cobra.Command, _ []string) error {
		c, close_, err := dial()
		if err != nil {
			return err
		}
		defer close_()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := c.DiscoverNAT(ctx, &gmeshv1.DiscoverNATRequest{ForceRefresh: force})
		if err != nil {
			return fmt.Errorf("discover nat rpc: %w", err)
		}
		if outputJSON {
			return writeJSON(resp.Nat)
		}
		fmt.Printf("nat_type:            %s\n", resp.Nat.NatType)
		fmt.Printf("external_ip:         %s\n", resp.Nat.ExternalIp)
		fmt.Printf("external_port:       %d\n", resp.Nat.ExternalPort)
		fmt.Printf("supports_hole_punch: %v\n", resp.Nat.SupportsHolePunch)
		fmt.Printf("is_relay_capable:    %v\n", resp.Nat.IsRelayCapable)
		return nil
	}
	cmd.AddCommand(discover)
	return cmd
}

func holePunchCmd() *cobra.Command {
	var (
		peerID   int64
		endpoint string
	)
	cmd := &cobra.Command{
		Use:   "hole-punch",
		Short: "Attempt a hole-punch against --endpoint (Phase 2: DIRECT only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.HolePunch(ctx, &gmeshv1.HolePunchRequest{
				PeerId:         peerID,
				RemoteEndpoint: endpoint,
			})
			if err != nil {
				return fmt.Errorf("hole punch rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("success:     %v\n", resp.Success)
			fmt.Printf("method_used: %s\n", resp.MethodUsed)
			fmt.Printf("latency_ms:  %d\n", resp.LatencyMs)
			if resp.Error != "" {
				fmt.Printf("error:       %s\n", resp.Error)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "peer ID (optional)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "remote host:port")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}

// ── Relay ─────────────────────────────────────────────────────────────

func relayCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "relay", Short: "Relay (UDP) + WS tunnel management"}
	cmd.AddCommand(relaySetupCmd(), wsTunnelCmd())
	return cmd
}

func relaySetupCmd() *cobra.Command {
	var (
		peerID    int64
		relayAddr string
		sessionID string
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Open a gmesh-relay session for a peer",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.SetupRelay(ctx, &gmeshv1.SetupRelayRequest{
				PeerId:         peerID,
				RelayEndpoint:  relayAddr,
				RelaySessionId: sessionID,
			})
			if err != nil {
				return fmt.Errorf("setup relay rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("ok:    %v\n", resp.Ok)
			if resp.Error != "" {
				fmt.Printf("error: %s\n", resp.Error)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "peer ID")
	cmd.Flags().StringVar(&relayAddr, "relay", "", "relay host:port")
	cmd.Flags().StringVar(&sessionID, "session", "", "session identifier")
	_ = cmd.MarkFlagRequired("peer-id")
	_ = cmd.MarkFlagRequired("relay")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

func wsTunnelCmd() *cobra.Command {
	var (
		peerID int64
		url    string
	)
	cmd := &cobra.Command{
		Use:   "ws-tunnel",
		Short: "Open a WebSocket tunnel to a backend /ws/relay endpoint",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resp, err := c.AllocateWSTunnel(ctx, &gmeshv1.AllocateWSTunnelRequest{
				PeerId:       peerID,
				BackendWsUrl: url,
			})
			if err != nil {
				return fmt.Errorf("ws tunnel rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("ok:    %v\n", resp.Ok)
			if resp.Error != "" {
				fmt.Printf("error: %s\n", resp.Error)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "peer ID")
	cmd.Flags().StringVar(&url, "url", "", "wss://.../ws/relay/{session}/{peer}")
	_ = cmd.MarkFlagRequired("peer-id")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

// ── Firewall ──────────────────────────────────────────────────────────

func firewallCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "firewall", Short: "Firewall (nftables/iptables) management"}
	cmd.AddCommand(
		firewallStatusCmd(),
		firewallApplyCmd(),
		firewallResetCmd(),
		firewallTemplatesCmd(),
	)
	return cmd
}

func firewallStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show active backend + rule count + hit counters",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.GetFirewallStatus(ctx, &gmeshv1.GetFirewallStatusRequest{})
			if err != nil {
				return fmt.Errorf("firewall status rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("backend:     %s\n", resp.Backend)
			fmt.Printf("active:      %d rules\n", resp.ActiveRules)
			if len(resp.HitCounts) > 0 {
				fmt.Println("hits:")
				for id, n := range resp.HitCounts {
					fmt.Printf("  rule %d: %d\n", id, n)
				}
			}
			return nil
		},
	}
}

func firewallApplyCmd() *cobra.Command {
	var (
		file   string
		policy string
		reset  bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a JSON rule file (replace-all)",
		RunE: func(_ *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read rules: %w", err)
			}
			var wireRules []*gmeshv1.FirewallRule
			if err := json.Unmarshal(raw, &wireRules); err != nil {
				return fmt.Errorf("parse rules: %w", err)
			}

			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp, err := c.ApplyFirewall(ctx, &gmeshv1.ApplyFirewallRequest{
				Rules:         wireRules,
				ForceReset:    reset,
				DefaultPolicy: policy,
			})
			if err != nil {
				return fmt.Errorf("apply firewall rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("applied: %d\nfailed:  %d\n", resp.AppliedCount, resp.FailedCount)
			for _, e := range resp.Errors {
				fmt.Printf("  ! %s\n", e)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "path to JSON rules file")
	cmd.Flags().StringVar(&policy, "policy", "accept", "default chain policy: accept|deny")
	cmd.Flags().BoolVar(&reset, "reset", false, "flush before apply")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func firewallResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Flush all gmesh-managed firewall rules",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.ResetFirewall(ctx, &gmeshv1.ResetFirewallRequest{}); err != nil {
				return fmt.Errorf("reset firewall rpc: %w", err)
			}
			fmt.Println("firewall reset")
			return nil
		},
	}
}

func firewallTemplatesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "templates", Short: "List and apply canned rule templates"}

	list := &cobra.Command{
		Use:   "list",
		Short: "Show available templates",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Templates are compiled into the binary; list from our package.
			fmt.Println("available templates:")
			for _, n := range firewallTemplateNames() {
				fmt.Printf("  %s\n", n)
			}
			return nil
		},
	}

	var (
		name   string
		policy string
		reset  bool
	)
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Apply a named template",
		RunE: func(_ *cobra.Command, _ []string) error {
			rules, ok := firewallGetTemplate(name)
			if !ok {
				return fmt.Errorf("template %q not found", name)
			}
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.ApplyFirewall(ctx, &gmeshv1.ApplyFirewallRequest{
				Rules:         rules,
				ForceReset:    reset,
				DefaultPolicy: policy,
			})
			if err != nil {
				return fmt.Errorf("apply template rpc: %w", err)
			}
			fmt.Printf("template %q: applied=%d failed=%d\n", name, resp.AppliedCount, resp.FailedCount)
			return nil
		},
	}
	apply.Flags().StringVar(&name, "name", "", "template name (see 'templates list')")
	apply.Flags().StringVar(&policy, "policy", "accept", "default policy: accept|deny")
	apply.Flags().BoolVar(&reset, "reset", false, "flush before apply")
	_ = apply.MarkFlagRequired("name")

	cmd.AddCommand(list, apply)
	return cmd
}

// firewallTemplateNames returns the compiled-in template list.
func firewallTemplateNames() []string { return firewall.TemplateNames() }

// firewallGetTemplate returns the named template as gRPC wire rules.
func firewallGetTemplate(name string) ([]*gmeshv1.FirewallRule, bool) {
	rules, ok := firewall.GetTemplate(name)
	if !ok {
		return nil, false
	}
	out := make([]*gmeshv1.FirewallRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, firewallRuleToProto(r))
	}
	return out, true
}

func firewallRuleToProto(r firewall.Rule) *gmeshv1.FirewallRule {
	dir := "inbound"
	switch r.Direction {
	case firewall.DirectionOutbound:
		dir = "outbound"
	case firewall.DirectionBoth:
		dir = "both"
	}
	return &gmeshv1.FirewallRule{
		Id: r.ID, Name: r.Name, Enabled: r.Enabled, Priority: r.Priority,
		Action: gmeshv1.FirewallAction(r.Action), Protocol: gmeshv1.FirewallProtocol(r.Protocol),
		Source: r.Source, Destination: r.Destination, PortRange: r.PortRange,
		Direction: dir, TcpFlags: r.TCPFlags, ConnState: r.ConnState,
		RateLimit: r.RateLimit, RateBurst: r.RateBurst,
		Schedule: r.ScheduleRaw, ExpiresAt: r.ExpiresAt, Tags: r.Tags,
	}
}

// ── Scope ─────────────────────────────────────────────────────────────

func scopeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scope", Short: "Manage netns-isolated scope peers"}
	cmd.AddCommand(scopeConnectCmd(), scopeDisconnectCmd())
	return cmd
}

func scopeConnectCmd() *cobra.Command {
	var (
		id                                                    int64
		meshIP, netns, vethCIDR, vmVethIP, scopeIP, gatewayIP string
		listenPort                                            uint16
	)
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Create scope netns + veth + in-netns WG + DNAT rule",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resp, err := c.ScopeConnect(ctx, &gmeshv1.ScopeConnectRequest{
				ScopeId:       id,
				ScopeMeshIp:   meshIP,
				ScopeNetns:    netns,
				VethCidr:      vethCIDR,
				VmVethIp:      vmVethIP,
				ScopeIp:       scopeIP,
				GatewayMeshIp: gatewayIP,
				ListenPort:    uint32(listenPort),
			})
			if err != nil {
				return fmt.Errorf("scope connect rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Peer)
			}
			fmt.Printf("scope %d connected\npublic_key: %s\nmesh_ip:    %s\n",
				resp.Peer.Id, resp.Peer.PublicKey, resp.Peer.MeshIp)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "scope ID")
	cmd.Flags().StringVar(&meshIP, "mesh-ip", "", "scope's mesh IP (10.200.x.x)")
	cmd.Flags().StringVar(&netns, "netns", "", "netns name (default scope-<id>)")
	cmd.Flags().StringVar(&vethCIDR, "veth-cidr", "", "veth /30, e.g. 10.50.42.0/30")
	cmd.Flags().StringVar(&vmVethIP, "vm-veth-ip", "", "host end of veth")
	cmd.Flags().StringVar(&scopeIP, "scope-ip", "", "scope end of veth")
	cmd.Flags().StringVar(&gatewayIP, "gateway-mesh-ip", "", "parent VM mesh_ip")
	cmd.Flags().Uint16Var(&listenPort, "listen-port", 0, "host-visible UDP port (DNAT'd into netns)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("mesh-ip")
	_ = cmd.MarkFlagRequired("listen-port")
	return cmd
}

func scopeDisconnectCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Tear down a scope's networking",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.ScopeDisconnect(ctx, &gmeshv1.ScopeDisconnectRequest{ScopeId: id}); err != nil {
				return fmt.Errorf("scope disconnect rpc: %w", err)
			}
			fmt.Printf("scope %d disconnected\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "scope ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// ── Events + Health ───────────────────────────────────────────────────

func eventsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "events", Short: "Subscribe to gmeshd event stream"}
	cmd.AddCommand(eventsTailCmd())
	return cmd
}

func eventsTailCmd() *cobra.Command {
	var types []string
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Stream events as they happen (ctrl-c to stop)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			stream, err := c.SubscribeEvents(ctx, &gmeshv1.SubscribeEventsRequest{Types: types})
			if err != nil {
				return fmt.Errorf("subscribe: %w", err)
			}
			for {
				ev, err := stream.Recv()
				if err != nil {
					return fmt.Errorf("recv: %w", err)
				}
				if outputJSON {
					if err := writeJSON(ev); err != nil {
						return err
					}
					continue
				}
				ts := time.UnixMilli(ev.TimestampUnixMs).Format(time.RFC3339)
				fmt.Printf("%s  %-22s  peer=%s  %s\n", ts, ev.Type, ev.PeerId, ev.PayloadJson)
			}
		},
	}
	cmd.Flags().StringSliceVar(&types, "type", nil, "filter by event type(s); repeat or comma-separate")
	return cmd
}

func healthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Per-peer health snapshot",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.HealthCheck(ctx, &gmeshv1.HealthCheckRequest{})
			if err != nil {
				return fmt.Errorf("health rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PEER\tSTATUS\tSCORE\tLATENCY\tHANDSHAKE_AGE\tLOSS")
			for _, p := range resp.Peers {
				fmt.Fprintf(w, "%d\t%s\t%d\t%d ms\t%d s\t%.3f\n",
					p.PeerId, p.Status, p.Score, p.LatencyMs, p.HandshakeAgeS, p.PacketLoss)
			}
			return w.Flush()
		},
	}
}

// ── Egress profiles ──────────────────────────────────────────────────

func egressCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "egress", Short: "Per-profile outbound routing via a mesh exit node"}
	cmd.AddCommand(egressCreateCmd(), egressDeleteCmd(), egressListCmd(), egressExitCmd())
	return cmd
}

func egressCreateCmd() *cobra.Command {
	var (
		id, exitPeer, sourceScope int64
		backupExitPeer            int64
		name, sourceCIDR, proto   string
		destCIDR, destPorts       string
		priority                  int32
		enabled                   bool
		exitPool                  []int64
		exitWeights               []int32
		geoipCountries            []string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an egress profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.CreateEgressProfile(ctx, &gmeshv1.CreateEgressProfileRequest{
				Profile: &gmeshv1.EgressProfile{
					Id: id, Name: name, Enabled: enabled, Priority: priority,
					SourceScopeId: sourceScope, SourceCidr: sourceCIDR,
					Protocol: proto, DestCidr: destCIDR, DestPorts: destPorts,
					ExitPeerId:       exitPeer,
					BackupExitPeerId: backupExitPeer,
					ExitPool:         exitPool,
					ExitWeights:      exitWeights,
					GeoipCountries:   geoipCountries,
				},
			})
			if err != nil {
				return fmt.Errorf("create egress rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Profile)
			}
			fmt.Printf("created egress profile id=%d name=%q exit_peer=%d\n",
				resp.Profile.Id, resp.Profile.Name, resp.Profile.ExitPeerId)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "profile ID (stable, user-chosen)")
	cmd.Flags().StringVar(&name, "name", "", "profile name")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "enabled flag")
	cmd.Flags().Int32Var(&priority, "priority", 100, "0..1000, lower=earlier match")
	cmd.Flags().Int64Var(&sourceScope, "source-scope", 0, "source scope ID; 0 = bare host")
	cmd.Flags().StringVar(&sourceCIDR, "source-cidr", "", `optional source CIDR (e.g. "10.50.42.0/30")`)
	cmd.Flags().StringVar(&proto, "protocol", "", `"any" | "tcp" | "udp"`)
	cmd.Flags().StringVar(&destCIDR, "dest", "0.0.0.0/0", "destination CIDR")
	cmd.Flags().StringVar(&destPorts, "dest-ports", "", `e.g. "443" or "80,443"`)
	cmd.Flags().Int64Var(&exitPeer, "exit-peer", 0, "mesh peer ID to use as exit (required unless --exit-pool)")
	cmd.Flags().Int64Var(&backupExitPeer, "backup-exit-peer", 0, "peer to swap to on path_down for exit-peer")
	cmd.Flags().Int64SliceVar(&exitPool, "exit-pool", nil, "weighted pool of exit peer IDs (Phase 16); needs --exit-weights")
	cmd.Flags().Int32SliceVar(&exitWeights, "exit-weights", nil, "weights matching --exit-pool (same length)")
	cmd.Flags().StringSliceVar(&geoipCountries, "geoip-country", nil, "ISO-3166 country codes for GeoIP match (Phase 15)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func egressDeleteCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove an egress profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.DeleteEgressProfile(ctx, &gmeshv1.DeleteEgressProfileRequest{Id: id}); err != nil {
				return fmt.Errorf("delete egress rpc: %w", err)
			}
			fmt.Printf("deleted egress profile id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "profile ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func egressListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all egress profiles",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListEgressProfiles(ctx, &gmeshv1.ListEgressProfilesRequest{})
			if err != nil {
				return fmt.Errorf("list egress rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tENABLED\tPRIORITY\tSOURCE\tPROTO\tDEST\tPORTS\tEXIT_PEER")
			for _, p := range resp.Profiles {
				src := "any"
				if p.SourceScopeId != 0 {
					src = fmt.Sprintf("scope:%d", p.SourceScopeId)
				} else if p.SourceCidr != "" {
					src = p.SourceCidr
				}
				fmt.Fprintf(w, "%d\t%s\t%v\t%d\t%s\t%s\t%s\t%s\t%d\n",
					p.Id, p.Name, p.Enabled, p.Priority, src,
					p.Protocol, p.DestCidr, p.DestPorts, p.ExitPeerId)
			}
			return w.Flush()
		},
	}
}

func egressExitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "exit", Short: "Enable or disable this node as an exit"}
	enable := &cobra.Command{
		Use:   "enable",
		Short: "Install MASQUERADE + FORWARD rules so this node can be an exit",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.EnableExit(ctx, &gmeshv1.EnableExitRequest{}); err != nil {
				return fmt.Errorf("enable exit rpc: %w", err)
			}
			fmt.Println("exit enabled")
			return nil
		},
	}
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Tear down exit rules",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.DisableExit(ctx, &gmeshv1.DisableExitRequest{}); err != nil {
				return fmt.Errorf("disable exit rpc: %w", err)
			}
			fmt.Println("exit disabled")
			return nil
		},
	}
	cmd.AddCommand(enable, disable)
	return cmd
}

// ── Ingress profiles ─────────────────────────────────────────────────

func ingressCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ingress", Short: "Public port forwarding via a mesh edge peer"}
	cmd.AddCommand(ingressCreateCmd(), ingressDeleteCmd(), ingressListCmd())
	return cmd
}

func ingressCreateCmd() *cobra.Command {
	var (
		id, backendPeer, backendScope, edgePeer int64
		name, backendIP, proto                  string
		backendPort, edgePort                   uint16
		allowedSrc                              []string
		enabled                                 bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an ingress profile (reverse port forward)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.CreateIngressProfile(ctx, &gmeshv1.CreateIngressProfileRequest{
				Profile: &gmeshv1.IngressProfile{
					Id: id, Name: name, Enabled: enabled,
					BackendPeerId: backendPeer, BackendScopeId: backendScope,
					BackendIp: backendIP, BackendPort: uint32(backendPort),
					EdgePeerId: edgePeer, EdgePort: uint32(edgePort),
					Protocol:           proto,
					AllowedSourceCidrs: allowedSrc,
				},
			})
			if err != nil {
				return fmt.Errorf("create ingress rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Profile)
			}
			fmt.Printf("created ingress profile id=%d name=%q edge=:%d → %s:%d\n",
				resp.Profile.Id, resp.Profile.Name, resp.Profile.EdgePort,
				resp.Profile.BackendIp, resp.Profile.BackendPort)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "profile ID")
	cmd.Flags().StringVar(&name, "name", "", "profile name")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "enabled flag")
	cmd.Flags().Int64Var(&backendPeer, "backend-peer", 0, "backend mesh peer ID")
	cmd.Flags().Int64Var(&backendScope, "backend-scope", 0, "optional backend scope ID")
	cmd.Flags().StringVar(&backendIP, "backend-ip", "", "backend IP (mesh IP of peer or scope)")
	cmd.Flags().Uint16Var(&backendPort, "backend-port", 0, "backend port")
	cmd.Flags().Int64Var(&edgePeer, "edge-peer", 0, "edge peer ID (this daemon's peer ID)")
	cmd.Flags().Uint16Var(&edgePort, "edge-port", 0, "public port on the edge peer")
	cmd.Flags().StringVar(&proto, "protocol", "tcp", `"tcp" | "udp"`)
	cmd.Flags().StringSliceVar(&allowedSrc, "allow-source", nil, "optional source CIDR allowlist (repeat)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("backend-ip")
	_ = cmd.MarkFlagRequired("backend-port")
	_ = cmd.MarkFlagRequired("edge-port")
	return cmd
}

func ingressDeleteCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove an ingress profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.DeleteIngressProfile(ctx, &gmeshv1.DeleteIngressProfileRequest{Id: id}); err != nil {
				return fmt.Errorf("delete ingress rpc: %w", err)
			}
			fmt.Printf("deleted ingress profile id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "profile ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func ingressListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all ingress profiles",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListIngressProfiles(ctx, &gmeshv1.ListIngressProfilesRequest{})
			if err != nil {
				return fmt.Errorf("list ingress rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tENABLED\tEDGE_PORT\tBACKEND\tPROTO")
			for _, p := range resp.Profiles {
				fmt.Fprintf(w, "%d\t%s\t%v\t%d\t%s:%d\t%s\n",
					p.Id, p.Name, p.Enabled, p.EdgePort, p.BackendIp, p.BackendPort, p.Protocol)
			}
			return w.Flush()
		},
	}
}

// ── Quota ────────────────────────────────────────────────────────────

func quotaCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "quota", Short: "Byte-quota policies for egress profiles"}
	cmd.AddCommand(quotaCreateCmd(), quotaDeleteCmd(), quotaListCmd(), quotaUsageCmd(), quotaResetCmd())
	return cmd
}

func quotaCreateCmd() *cobra.Command {
	var (
		id, profileID, backupID int64
		name, period            string
		limit                   int64
		warn, shift, stop       float64
		enabled, hardStop, autoRollback bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Attach a byte-quota to an egress profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.CreateQuota(ctx, &gmeshv1.CreateQuotaRequest{
				Quota: &gmeshv1.Quota{
					Id: id, Name: name, Enabled: enabled,
					EgressProfileId: profileID,
					Period:          period,
					LimitBytes:      limit,
					WarnAt:          warn, ShiftAt: shift, StopAt: stop,
					BackupProfileId: backupID,
					HardStop:        hardStop,
					AutoRollback:    autoRollback,
				},
			})
			if err != nil {
				return fmt.Errorf("create quota rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Quota)
			}
			fmt.Printf("created quota id=%d name=%q profile=%d limit=%d bytes\n",
				resp.Quota.Id, resp.Quota.Name, resp.Quota.EgressProfileId, resp.Quota.LimitBytes)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "quota ID")
	cmd.Flags().StringVar(&name, "name", "", "quota name")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "enabled flag")
	cmd.Flags().Int64Var(&profileID, "profile", 0, "egress profile ID to watch")
	cmd.Flags().StringVar(&period, "period", "daily", `"hourly" | "daily" | "weekly" | "monthly"`)
	cmd.Flags().Int64Var(&limit, "limit-bytes", 0, "period budget in bytes")
	cmd.Flags().Float64Var(&warn, "warn-at", 0, "warn threshold fraction 0..1")
	cmd.Flags().Float64Var(&shift, "shift-at", 0, "shift-to-backup threshold fraction 0..1")
	cmd.Flags().Float64Var(&stop, "stop-at", 0, "stop threshold fraction 0..1")
	cmd.Flags().Int64Var(&backupID, "backup-profile", 0, "backup egress profile ID for auto-shift")
	cmd.Flags().BoolVar(&hardStop, "hard-stop", false, "install nftables DROP rule when stop_at is crossed")
	cmd.Flags().BoolVar(&autoRollback, "auto-rollback", false, "restore primary exit_peer on reset/rollover after a shift")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("profile")
	_ = cmd.MarkFlagRequired("limit-bytes")
	return cmd
}

func quotaDeleteCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove a quota",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.DeleteQuota(ctx, &gmeshv1.DeleteQuotaRequest{Id: id}); err != nil {
				return fmt.Errorf("delete quota rpc: %w", err)
			}
			fmt.Printf("deleted quota id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "quota ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func quotaListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all quotas",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListQuotas(ctx, &gmeshv1.ListQuotasRequest{})
			if err != nil {
				return fmt.Errorf("list quota rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tPROFILE\tPERIOD\tLIMIT\tUSED\tPERCENT\tSTATUS")
			for _, q := range resp.Quotas {
				frac := 0.0
				if q.LimitBytes > 0 {
					frac = float64(q.UsedBytes) / float64(q.LimitBytes) * 100
				}
				status := "ok"
				if q.StopFired {
					status = "STOP"
				} else if q.ShiftFired {
					status = "SHIFTED"
				} else if q.WarnFired {
					status = "WARN"
				}
				fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\t%d\t%.1f%%\t%s\n",
					q.Id, q.Name, q.EgressProfileId, q.Period,
					q.LimitBytes, q.UsedBytes, frac, status)
			}
			return w.Flush()
		},
	}
}

func quotaUsageCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Force a tick + show live usage",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.GetQuotaUsage(ctx, &gmeshv1.GetQuotaUsageRequest{Id: id})
			if err != nil {
				return fmt.Errorf("usage rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			for _, q := range resp.Quotas {
				pct := 0.0
				if q.LimitBytes > 0 {
					pct = float64(q.UsedBytes) / float64(q.LimitBytes) * 100
				}
				fmt.Printf("quota %d (%s): used=%d / limit=%d (%.1f%%) period=%s\n",
					q.Id, q.Name, q.UsedBytes, q.LimitBytes, pct, q.Period)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "quota ID (0 = all)")
	return cmd
}

func quotaResetCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Zero a quota's counter + clear latches",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.ResetQuota(ctx, &gmeshv1.ResetQuotaRequest{Id: id}); err != nil {
				return fmt.Errorf("reset quota rpc: %w", err)
			}
			fmt.Printf("reset quota id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "quota ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func peerUpdateCmd() *cobra.Command {
	var (
		id         int64
		endpoint   string
		allowedIPs []string
		keepalive  uint32
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a peer's endpoint / allowed-ips / keepalive",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.UpdatePeer(ctx, &gmeshv1.UpdatePeerRequest{
				PeerId:     id,
				Endpoint:   endpoint,
				AllowedIps: allowedIPs,
				Keepalive:  keepalive,
			})
			if err != nil {
				return fmt.Errorf("update peer rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("updated peer id=%d\n", resp.Peer.Id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "peer ID")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "new host:port")
	cmd.Flags().StringSliceVar(&allowedIPs, "allowed-ips", nil, "new allowed IPs")
	cmd.Flags().Uint32Var(&keepalive, "keepalive", 0, "new keepalive seconds")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

// ── policy (Phase 17) ─────────────────────────────────────────────────

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Event-driven rule engine (YAML)"}
	cmd.AddCommand(policyListCmd(), policyReloadCmd())
	return cmd
}

func policyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show active policies",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListPolicies(ctx, &gmeshv1.ListPoliciesRequest{})
			if err != nil {
				return fmt.Errorf("policy list rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tEVENT\tPEER\tPROFILE\tACTION\tSOURCE")
			for _, p := range resp.Policies {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
					p.Name, p.Event, p.PeerId, p.ProfileId, p.Action, p.Source)
			}
			return w.Flush()
		},
	}
}

func policyReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Re-read the configured policies directory",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ReloadPolicies(ctx, &gmeshv1.ReloadPoliciesRequest{})
			if err != nil {
				return fmt.Errorf("policy reload rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("loaded %d policies\n", resp.Loaded)
			for _, e := range resp.Errors {
				fmt.Fprintf(os.Stderr, "  ERR: %s\n", e)
			}
			return nil
		},
	}
}

// ── path (Phase 14) ───────────────────────────────────────────────────

func pathCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "path", Short: "Path monitor (RTT / loss / up-down)"}
	cmd.AddCommand(pathListCmd())
	return cmd
}

func pathListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show active-probe status for every peer",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListPathStates(ctx, &gmeshv1.ListPathStatesRequest{})
			if err != nil {
				return fmt.Errorf("path list rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PEER\tMESH_IP\tSTATUS\tRTT_MS\tLOSS%\tOK\tFAIL\tSAMPLES")
			for _, s := range resp.States {
				rtt := float64(s.LastRttUs) / 1000.0
				fmt.Fprintf(w, "%d\t%s\t%s\t%.2f\t%.1f\t%d\t%d\t%d\n",
					s.PeerId, s.MeshIp, s.Status, rtt, s.LossPct,
					s.ConsecutiveOk, s.ConsecutiveFail, s.Samples)
			}
			return w.Flush()
		},
	}
}

// ── mtls (Phase 20) ───────────────────────────────────────────────────

func mtlsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mtls", Short: "Embedded CA + SPIFFE peer certs"}
	cmd.AddCommand(mtlsInitCmd(), mtlsStatusCmd(), mtlsIssueCmd(),
		mtlsListCmd(), mtlsRevokeCmd(), mtlsTrustCmd())
	return cmd
}

func mtlsInitCmd() *cobra.Command {
	var trust string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Bootstrap the mesh CA (one-time per mesh)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.InitCA(ctx, &gmeshv1.InitCARequest{
				TrustDomain: trust, Force: force,
			})
			if err != nil {
				return fmt.Errorf("init ca rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("CA initialised; trust_domain=%s\n", resp.TrustDomain)
			fmt.Println(resp.CaPem)
			return nil
		},
	}
	cmd.Flags().StringVar(&trust, "trust-domain", "gmesh.local", "SPIFFE trust domain")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing CA — DESTRUCTIVE")
	return cmd
}

func mtlsStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show CA loaded state + issued/revoked counts",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.CAStatus(ctx, &gmeshv1.CAStatusRequest{})
			if err != nil {
				return fmt.Errorf("status rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			fmt.Printf("loaded:       %v\n", resp.Loaded)
			fmt.Printf("trust_domain: %s\n", resp.TrustDomain)
			fmt.Printf("issued:       %d\n", resp.IssuedCount)
			fmt.Printf("revoked:      %d\n", resp.RevokedCount)
			return nil
		},
	}
}

func mtlsIssueCmd() *cobra.Command {
	var (
		peerID, validityDays int64
		cn, spiffe           string
		dnsNames, ipAddrs    []string
		outDir               string
	)
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Sign a peer certificate and (optionally) save to disk",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.IssueCert(ctx, &gmeshv1.IssueCertRequest{
				PeerId: peerID, CommonName: cn, SpiffeId: spiffe,
				DnsNames: dnsNames, IpAddrs: ipAddrs,
				ValidityDays: validityDays,
			})
			if err != nil {
				return fmt.Errorf("issue rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			ic := resp.Cert
			fmt.Printf("serial:    %s\n", ic.Serial)
			fmt.Printf("peer_id:   %d\n", ic.PeerId)
			fmt.Printf("spiffe_id: %s\n", ic.SpiffeId)
			fmt.Printf("valid:     %s → %s\n",
				time.Unix(ic.NotBeforeUnix, 0).UTC().Format(time.RFC3339),
				time.Unix(ic.NotAfterUnix, 0).UTC().Format(time.RFC3339))
			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o700); err != nil {
					return fmt.Errorf("mkdir %s: %w", outDir, err)
				}
				for _, f := range []struct {
					name string
					data string
					mode os.FileMode
				}{
					{"cert.pem", ic.CertPem, 0o644},
					{"key.pem", ic.KeyPem, 0o600},
					{"ca.pem", ic.CaPem, 0o644},
				} {
					if err := os.WriteFile(filepath.Join(outDir, f.name), []byte(f.data), f.mode); err != nil {
						return fmt.Errorf("write %s: %w", f.name, err)
					}
				}
				fmt.Printf("written to %s/{cert,key,ca}.pem\n", outDir)
			} else {
				fmt.Println("---- ca.pem ----")
				fmt.Println(ic.CaPem)
				fmt.Println("---- cert.pem ----")
				fmt.Println(ic.CertPem)
				fmt.Println("---- key.pem ----")
				fmt.Println(ic.KeyPem)
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "peer ID (required)")
	cmd.Flags().StringVar(&cn, "cn", "", `subject CN (default "peer-<id>")`)
	cmd.Flags().StringVar(&spiffe, "spiffe-id", "", "override SPIFFE URI (default auto)")
	cmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS SAN (repeatable)")
	cmd.Flags().StringSliceVar(&ipAddrs, "ip", nil, "IP SAN (repeatable)")
	cmd.Flags().Int64Var(&validityDays, "days", 0, "validity days (default 90)")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "write cert/key/ca.pem into this dir")
	_ = cmd.MarkFlagRequired("peer-id")
	return cmd
}

func mtlsListCmd() *cobra.Command {
	var peerID int64
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued certificates",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListCerts(ctx, &gmeshv1.ListCertsRequest{PeerId: peerID})
			if err != nil {
				return fmt.Errorf("list rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SERIAL\tPEER\tCN\tSPIFFE\tNOT_AFTER\tREVOKED")
			for _, s := range resp.Certs {
				exp := time.Unix(s.NotAfterUnix, 0).UTC().Format("2006-01-02")
				rv := ""
				if s.Revoked {
					rv = s.RevokeReason
					if rv == "" {
						rv = "yes"
					}
				}
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
					s.Serial, s.PeerId, s.CommonName, s.SpiffeId, exp, rv)
			}
			return w.Flush()
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "filter by peer id (0 = all)")
	return cmd
}

func mtlsRevokeCmd() *cobra.Command {
	var serial, reason string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Mark a cert revoked by serial",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.RevokeCert(ctx, &gmeshv1.RevokeCertRequest{Serial: serial, Reason: reason}); err != nil {
				return fmt.Errorf("revoke rpc: %w", err)
			}
			fmt.Printf("revoked %s\n", serial)
			return nil
		},
	}
	cmd.Flags().StringVar(&serial, "serial", "", "cert serial (hex; required)")
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "free-form reason string")
	_ = cmd.MarkFlagRequired("serial")
	return cmd
}

func mtlsTrustCmd() *cobra.Command {
	var outFile string
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Print the CA root cert (trust bundle) for relying parties",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ExportTrust(ctx, &gmeshv1.ExportTrustRequest{})
			if err != nil {
				return fmt.Errorf("export rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, []byte(resp.CaPem), 0o644); err != nil {
					return err
				}
				fmt.Printf("wrote %s (trust_domain=%s)\n", outFile, resp.TrustDomain)
				return nil
			}
			fmt.Printf("# trust_domain: %s\n%s", resp.TrustDomain, resp.CaPem)
			return nil
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "write to this file instead of stdout")
	return cmd
}

// ── circuit (Phase 19) ────────────────────────────────────────────────

func circuitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "circuit", Short: "Multi-hop source-routed paths through the mesh"}
	cmd.AddCommand(circuitCreateCmd(), circuitDeleteCmd(), circuitListCmd())
	return cmd
}

func circuitCreateCmd() *cobra.Command {
	var (
		id, source        int64
		name              string
		hops              []int64
		proto             string
		destCIDR, ports   string
		priority          int32
		enabled           bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Install this node's share of a multi-hop path",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := c.CreateCircuit(ctx, &gmeshv1.CreateCircuitRequest{
				Circuit: &gmeshv1.Circuit{
					Id: id, Name: name, Enabled: enabled, Priority: priority,
					Source: source, Hops: hops,
					Protocol: proto, DestCidr: destCIDR, DestPorts: ports,
				},
			})
			if err != nil {
				return fmt.Errorf("create circuit rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp.Circuit)
			}
			fmt.Printf("created circuit id=%d name=%q\n", resp.Circuit.Id, resp.Circuit.Name)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "circuit ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "circuit name (required)")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "enabled flag")
	cmd.Flags().Int32Var(&priority, "priority", 100, "0..1000, lower = earlier match")
	cmd.Flags().Int64Var(&source, "source", 0, "source peer ID (required)")
	cmd.Flags().Int64SliceVar(&hops, "hop", nil, "hop peer ID (repeat for chain)")
	cmd.Flags().StringVar(&proto, "protocol", "", `"any" | "tcp" | "udp"`)
	cmd.Flags().StringVar(&destCIDR, "dest", "0.0.0.0/0", "destination CIDR")
	cmd.Flags().StringVar(&ports, "dest-ports", "", `e.g. "443" or "80,443"`)
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("source")
	_ = cmd.MarkFlagRequired("hop")
	return cmd
}

func circuitDeleteCmd() *cobra.Command {
	var id int64
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove this node's share of a circuit",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.DeleteCircuit(ctx, &gmeshv1.DeleteCircuitRequest{Id: id}); err != nil {
				return fmt.Errorf("delete circuit rpc: %w", err)
			}
			fmt.Printf("deleted circuit id=%d\n", id)
			return nil
		},
	}
	cmd.Flags().Int64Var(&id, "id", 0, "circuit ID (required)")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func circuitListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show circuits this node is aware of",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListCircuits(ctx, &gmeshv1.ListCircuitsRequest{})
			if err != nil {
				return fmt.Errorf("list circuit rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSOURCE\tPATH\tPROTO\tDEST\tPORTS")
			for _, c := range resp.Circuits {
				hops := make([]string, 0, len(c.Hops)+1)
				hops = append(hops, fmt.Sprintf("%d", c.Source))
				for _, h := range c.Hops {
					hops = append(hops, fmt.Sprintf("%d", h))
				}
				fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\n",
					c.Id, c.Name, c.Source, strings.Join(hops, "→"),
					c.Protocol, c.DestCidr, c.DestPorts)
			}
			return w.Flush()
		},
	}
}

// ── anomaly (Phase 21) ────────────────────────────────────────────────

func anomalyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "anomaly", Short: "Statistical anomaly alerts"}
	cmd.AddCommand(anomalyListCmd())
	return cmd
}

func anomalyListCmd() *cobra.Command {
	var peerID int64
	var limit int32
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show recent anomaly alerts (newest first)",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListAnomalies(ctx, &gmeshv1.ListAnomaliesRequest{
				PeerId: peerID, Limit: limit,
			})
			if err != nil {
				return fmt.Errorf("list anomalies rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "OBSERVED\tDETECTOR\tSEVERITY\tPEER\tMESSAGE")
			for _, a := range resp.Alerts {
				ts := time.Unix(a.ObservedUnix, 0).UTC().Format(time.RFC3339)
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
					ts, a.Detector, a.Severity, a.PeerId, a.Message)
			}
			return w.Flush()
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "filter by peer (0 = all)")
	cmd.Flags().Int32Var(&limit, "limit", 50, "max alerts (0 = all)")
	return cmd
}

// ── l7 (Phase 18) ─────────────────────────────────────────────────────

func l7Cmd() *cobra.Command {
	cmd := &cobra.Command{Use: "l7", Short: "Application-layer traffic classification"}
	cmd.AddCommand(l7FlowsCmd(), l7TotalsCmd())
	return cmd
}

func l7FlowsCmd() *cobra.Command {
	var peerID int64
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Show classified live flows",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListL7Flows(ctx, &gmeshv1.ListL7FlowsRequest{PeerId: peerID})
			if err != nil {
				return fmt.Errorf("list l7 flows rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PEER\tL4\tL7\tCONF\tSRC\tDST\tRX\tTX")
			for _, f := range resp.Flows {
				fmt.Fprintf(w, "%d\t%s\t%s\t%.0f%%\t%s:%d\t%s:%d\t%d\t%d\n",
					f.PeerId, f.L4Proto, f.L7Proto, f.Confidence*100,
					f.SrcIp, f.SrcPort, f.DstIp, f.DstPort,
					f.RxBytes, f.TxBytes)
			}
			return w.Flush()
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "filter by peer (0 = all)")
	return cmd
}

func l7TotalsCmd() *cobra.Command {
	var peerID int64
	cmd := &cobra.Command{
		Use:   "totals",
		Short: "Show per-(peer, protocol) byte/flow totals",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, close_, err := dial()
			if err != nil {
				return err
			}
			defer close_()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.ListL7Totals(ctx, &gmeshv1.ListL7TotalsRequest{PeerId: peerID})
			if err != nil {
				return fmt.Errorf("list l7 totals rpc: %w", err)
			}
			if outputJSON {
				return writeJSON(resp)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PEER\tL7\tBYTES\tFLOWS")
			for _, t := range resp.Totals {
				fmt.Fprintf(w, "%d\t%s\t%d\t%d\n",
					t.PeerId, t.L7Proto, t.Bytes, t.Flows)
			}
			return w.Flush()
		},
	}
	cmd.Flags().Int64Var(&peerID, "peer-id", 0, "filter by peer (0 = all)")
	return cmd
}
