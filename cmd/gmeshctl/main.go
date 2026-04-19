// Command gmeshctl is the operator CLI for gmeshd.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
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
