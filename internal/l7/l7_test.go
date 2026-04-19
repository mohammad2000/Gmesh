package l7

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestClassifyKnownPort(t *testing.T) {
	c := NewClassifier()
	f := Flow{L4Proto: "tcp", DstPort: 443}
	c.Classify(&f)
	if f.L7Proto != ProtoTLS {
		t.Errorf("443/tcp = %q; want tls", f.L7Proto)
	}
	if f.Confidence != 1.0 {
		t.Errorf("confidence = %v; want 1.0", f.Confidence)
	}
}

func TestClassifySourcePortFallback(t *testing.T) {
	c := NewClassifier()
	f := Flow{L4Proto: "tcp", SrcPort: 22, DstPort: 50022}
	c.Classify(&f)
	if f.L7Proto != ProtoSSH {
		t.Errorf("sport=22 fallback mislabelled: %q", f.L7Proto)
	}
}

func TestClassifyUnknown(t *testing.T) {
	c := NewClassifier()
	f := Flow{L4Proto: "tcp", DstPort: 54321}
	c.Classify(&f)
	if f.L7Proto != ProtoUnknown {
		t.Errorf("unknown port → %q; want %q", f.L7Proto, ProtoUnknown)
	}
	if f.Confidence != 0 {
		t.Errorf("confidence = %v; want 0 on unknown", f.Confidence)
	}
}

func TestClassifyUDPDistinctFromTCP(t *testing.T) {
	c := NewClassifier()
	f443udp := Flow{L4Proto: "udp", DstPort: 443}
	c.Classify(&f443udp)
	if f443udp.L7Proto != ProtoQUIC {
		t.Errorf("443/udp = %q; want quic", f443udp.L7Proto)
	}
	f443tcp := Flow{L4Proto: "tcp", DstPort: 443}
	c.Classify(&f443tcp)
	if f443tcp.L7Proto != ProtoTLS {
		t.Errorf("443/tcp = %q; want tls", f443tcp.L7Proto)
	}
}

func TestAddPortOverride(t *testing.T) {
	c := NewClassifier()
	c.AddPort("tcp", 9000, "custom-rpc")
	f := Flow{L4Proto: "tcp", DstPort: 9000}
	c.Classify(&f)
	if f.L7Proto != "custom-rpc" {
		t.Errorf("custom port = %q", f.L7Proto)
	}
}

func TestClassifyTagsPeerID(t *testing.T) {
	c := NewClassifier()
	c.SetPeerIndex(map[string]int64{
		"10.250.0.20": 3,
		"10.250.0.1":  1,
	})
	f := Flow{L4Proto: "tcp", DstPort: 443, SrcIP: "10.250.0.1", DstIP: "10.250.0.20"}
	c.Classify(&f)
	if f.PeerID != 3 {
		t.Errorf("peer_id = %d; want 3 (dst IP match)", f.PeerID)
	}
}

func TestAggregatorDeltaAccounting(t *testing.T) {
	a := NewAggregator()
	c := NewClassifier()
	k := Flow{
		L4Proto: "tcp", DstPort: 443, SrcPort: 52000,
		SrcIP: "10.250.0.1", DstIP: "10.250.0.20",
		RxBytes: 100, TxBytes: 50,
	}
	c.Classify(&k)
	a.Ingest([]Flow{k})

	// Same flow grows; delta = new − old = 100 bytes.
	k.RxBytes = 200
	k.TxBytes = 50
	c.Classify(&k)
	a.Ingest([]Flow{k})

	totals := a.Totals()
	if len(totals) != 1 {
		t.Fatalf("totals=%d; want 1", len(totals))
	}
	// First batch contributes Rx+Tx=150; second adds 100 → total 250.
	if totals[0].Bytes != 250 {
		t.Errorf("bytes = %d; want 250", totals[0].Bytes)
	}
	if totals[0].Flows != 1 {
		t.Errorf("flows = %d; want 1", totals[0].Flows)
	}
}

func TestAggregatorIgnoresShrinkingCounter(t *testing.T) {
	a := NewAggregator()
	c := NewClassifier()
	k := Flow{L4Proto: "tcp", DstPort: 80, RxBytes: 1000, TxBytes: 0}
	c.Classify(&k)
	a.Ingest([]Flow{k})
	// Counter regression (e.g. conntrack entry replaced) must not
	// subtract from totals.
	k.RxBytes = 100
	c.Classify(&k)
	a.Ingest([]Flow{k})
	if got := a.Totals()[0].Bytes; got != 1000 {
		t.Errorf("bytes = %d; want 1000 (regression ignored)", got)
	}
}

func TestAggregatorReset(t *testing.T) {
	a := NewAggregator()
	c := NewClassifier()
	k := Flow{L4Proto: "tcp", DstPort: 80, RxBytes: 50, TxBytes: 50}
	c.Classify(&k)
	a.Ingest([]Flow{k})
	a.Reset()
	if len(a.Totals()) != 0 || len(a.Flows()) != 0 {
		t.Error("Reset did not clear state")
	}
}


func TestMonitorTickIntegration(t *testing.T) {
	m := New(silent(), 0)
	stub := NewStubReader()
	stub.Push([]Flow{
		{L4Proto: "tcp", DstPort: 443, DstIP: "10.250.0.20", RxBytes: 100, TxBytes: 50},
		{L4Proto: "tcp", DstPort: 22, DstIP: "10.250.0.20", RxBytes: 10, TxBytes: 10},
	})
	m.Reader = stub
	m.Classifier.SetPeerIndex(map[string]int64{"10.250.0.20": 3})

	n, err := m.Tick()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("n = %d; want 2", n)
	}
	totals := m.Totals()
	if len(totals) != 2 {
		t.Fatalf("totals=%d; want 2", len(totals))
	}
	for _, tot := range totals {
		if tot.PeerID != 3 {
			t.Errorf("peer_id = %d; want 3", tot.PeerID)
		}
	}
}

func TestFlowStringRenders(t *testing.T) {
	f := Flow{L4Proto: "tcp", SrcIP: "a", DstIP: "b", SrcPort: 1, DstPort: 2, L7Proto: ProtoHTTP, Confidence: 1}
	if got := f.String(); got == "" {
		t.Error("empty string")
	}
}

func TestStubReaderQueueOrder(t *testing.T) {
	r := NewStubReader()
	r.Push([]Flow{{L4Proto: "tcp", DstPort: 80}})
	r.Push([]Flow{{L4Proto: "tcp", DstPort: 443}})
	got, _ := r.Read()
	if len(got) != 1 || got[0].DstPort != 80 {
		t.Errorf("first read = %v", got)
	}
	got, _ = r.Read()
	if len(got) != 1 || got[0].DstPort != 443 {
		t.Errorf("second read = %v", got)
	}
	got, _ = r.Read()
	if len(got) != 0 {
		t.Error("third read should be empty")
	}
}

func TestMonitorRunStopsOnCtx(t *testing.T) {
	m := New(silent(), 20*time.Millisecond)
	stub := NewStubReader()
	m.Reader = stub
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		m.Run(ctx)
	}()
	<-done
}
