package rpc

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
)

// blockingEvents holds SubscribeEvents open until the client goes away,
// like the agent's event forwarder does.
type blockingEvents struct {
	gmeshv1.UnimplementedGMeshServer
	subscribed chan struct{}
}

func (b *blockingEvents) SubscribeEvents(_ *gmeshv1.SubscribeEventsRequest, ss gmeshv1.GMesh_SubscribeEventsServer) error {
	close(b.subscribed)
	<-ss.Context().Done()
	return nil
}

func TestStopGRPCDoesNotWaitForOpenStreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	gs := grpc.NewServer()
	svc := &blockingEvents{subscribed: make(chan struct{})}
	gmeshv1.RegisterGMeshServer(gs, svc)
	go func() { _ = gs.Serve(ln) }()

	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := gmeshv1.NewGMeshClient(conn).SubscribeEvents(context.Background(), &gmeshv1.SubscribeEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = stream.Recv() }()
	select {
	case <-svc.subscribed:
	case <-time.After(3 * time.Second):
		t.Fatal("stream never reached the server")
	}

	start := time.Now()
	stopGRPC(gs, 200*time.Millisecond, silentLog())
	if dt := time.Since(start); dt > 2*time.Second {
		t.Fatalf("stopGRPC took %v with an open stream; want ~200ms", dt)
	}
}
