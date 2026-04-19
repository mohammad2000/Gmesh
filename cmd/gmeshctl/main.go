// Command gmeshctl is the operator CLI for gmeshd.
//
// Example:
//
//	gmeshctl status
//	gmeshctl peers list
//	gmeshctl peer add --id 42 --mesh-ip 10.200.0.7 --public-key XXX --endpoint 1.2.3.4:51820
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
	"github.com/mohammad2000/Gmesh/internal/version"
)

var socketPath string

func main() {
	root := &cobra.Command{
		Use:   "gmeshctl",
		Short: "Control and inspect the gmeshd daemon",
		Version: fmt.Sprintf("%s (%s) built %s",
			version.Version, version.Commit, version.BuildDate),
	}
	root.PersistentFlags().StringVar(&socketPath, "socket", "/run/gmesh.sock", "path to gmeshd Unix socket")

	root.AddCommand(
		statusCmd(),
		versionCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func dial() (*grpc.ClientConn, error) {
	return grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", addr[len("unix://"):])
		}),
	)
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon + mesh status",
		RunE: func(_ *cobra.Command, _ []string) error {
			conn, err := dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			c := gmeshv1.NewGMeshClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := c.Status(ctx, &gmeshv1.StatusRequest{})
			if err != nil {
				return fmt.Errorf("status rpc: %w", err)
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
			conn, err := dial()
			if err != nil {
				return err
			}
			defer conn.Close()
			c := gmeshv1.NewGMeshClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			resp, err := c.Version(ctx, &gmeshv1.VersionRequest{})
			if err != nil {
				return fmt.Errorf("version rpc: %w", err)
			}
			fmt.Printf("gmeshd %s (%s) built %s\n", resp.Version, resp.Commit, resp.BuildDate)
			return nil
		},
	}
}
