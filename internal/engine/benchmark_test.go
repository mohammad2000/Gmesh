package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/peer"
)

// BenchmarkAddPeer1000 measures how long it takes to install 1000 peers.
// Uses the same fakeWG as the engine tests so we only measure engine +
// registry + routing overhead, not kernel ops.
func BenchmarkAddPeer1000(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		eng, _ := benchSetup(b)
		ctx := context.Background()
		if _, err := eng.Join(ctx, "10.200.0.1", "wg-bench", 51820, "10.200.0.0/16", "n"); err != nil {
			b.Fatal(err)
		}
		for i := 1; i <= 1000; i++ {
			_ = eng.AddPeer(ctx, &peer.Peer{
				ID:         int64(i),
				Type:       peer.TypeVM,
				MeshIP:     fmt.Sprintf("10.200.%d.%d", i/256, i%256),
				PublicKey:  fmt.Sprintf("KEY%039d=", i),
				Endpoint:   "1.2.3.4:51820",
				AllowedIPs: []string{fmt.Sprintf("10.200.%d.%d/32", i/256, i%256)},
			}, 0)
		}
	}
}

// BenchmarkApplyFirewall1000 measures a 1000-rule apply through the
// memory backend. The translator builds the full nft script in-memory
// but never executes it, so the numbers here approximate the Go-side
// translation cost only.
func BenchmarkApplyFirewall1000(b *testing.B) {
	b.ReportAllocs()
	rules := make([]firewall.Rule, 1000)
	for i := range rules {
		rules[i] = firewall.Rule{
			ID: int64(i + 1), Name: fmt.Sprintf("rule %d", i),
			Enabled: true, Priority: int32(i % 1000),
			Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP,
			PortRange: fmt.Sprintf("%d", 1024+(i%60000)),
			Direction: firewall.DirectionInbound,
		}
	}

	for n := 0; n < b.N; n++ {
		eng, _ := benchSetup(b)
		if _, _, errs := eng.ApplyFirewall(context.Background(), rules, "accept", false); len(errs) > 0 {
			b.Fatalf("apply errors: %v", errs)
		}
	}
}

// BenchmarkStatus1000Peers measures Status() latency with 1k peers.
func BenchmarkStatus1000Peers(b *testing.B) {
	eng, _ := benchSetup(b)
	ctx := context.Background()
	_, _ = eng.Join(ctx, "10.200.0.1", "wg-bench", 51820, "10.200.0.0/16", "n")
	for i := 1; i <= 1000; i++ {
		_ = eng.AddPeer(ctx, &peer.Peer{
			ID: int64(i), Type: peer.TypeVM,
			MeshIP: fmt.Sprintf("10.200.%d.%d", i/256, i%256),
			PublicKey: fmt.Sprintf("KEY%039d=", i),
		}, 0)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _ = eng.RefreshPeerStats(ctx)
		_ = eng.Peers.Snapshot()
	}
}

// TestApplyFirewall1000Latency is a sanity test — confirms the bench
// scenario runs in well under 1 second so Phase 5's "sub-second" claim
// is reproducible in CI.
func TestApplyFirewall1000Latency(t *testing.T) {
	rules := make([]firewall.Rule, 1000)
	for i := range rules {
		rules[i] = firewall.Rule{
			ID: int64(i + 1), Enabled: true, Priority: int32(i % 1000),
			Action: firewall.ActionAllow, Protocol: firewall.ProtoTCP,
			PortRange: fmt.Sprintf("%d", 1024+(i%60000)),
			Direction: firewall.DirectionInbound,
		}
	}
	eng, _ := benchSetup(t)
	start := time.Now()
	applied, failed, errs := eng.ApplyFirewall(context.Background(), rules, "accept", false)
	dt := time.Since(start)
	if failed != 0 || len(errs) != 0 {
		t.Fatalf("unexpected errors: failed=%d errs=%v", failed, errs)
	}
	if applied != 1000 {
		t.Errorf("applied = %d; want 1000", applied)
	}
	if dt > 500*time.Millisecond {
		t.Errorf("apply took %v; want <500ms", dt)
	}
	t.Logf("applied 1000 rules in %v (%.0f rules/ms)", dt, float64(1000)/float64(dt.Milliseconds()+1))
}

func TestAddPeer1000Latency(t *testing.T) {
	eng, _ := benchSetup(t)
	ctx := context.Background()
	if _, err := eng.Join(ctx, "10.200.0.1", "wg-bench", 51820, "10.200.0.0/16", "n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 1; i <= 1000; i++ {
		if err := eng.AddPeer(ctx, &peer.Peer{
			ID:         int64(i),
			Type:       peer.TypeVM,
			MeshIP:     fmt.Sprintf("10.200.%d.%d", i/256, i%256),
			PublicKey:  fmt.Sprintf("KEY%039d=", i),
			Endpoint:   "1.2.3.4:51820",
			AllowedIPs: []string{fmt.Sprintf("10.200.%d.%d/32", i/256, i%256)},
		}, 0); err != nil {
			t.Fatalf("AddPeer %d: %v", i, err)
		}
	}
	dt := time.Since(start)
	if eng.Peers.Count() != 1000 {
		t.Errorf("count = %d; want 1000", eng.Peers.Count())
	}
	t.Logf("added 1000 peers in %v (%.0f peers/ms)", dt, float64(1000)/float64(dt.Milliseconds()+1))
}

func benchSetup(tb testLike) (*Engine, *fakeWG) {
	tb.Helper()
	eng, fw := setupTB(tb)
	return eng, fw
}
