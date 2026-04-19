package rpc

import (
	"context"
	"path"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/mohammad2000/Gmesh/internal/audit"
	"github.com/mohammad2000/Gmesh/internal/metrics"
)

// newMetricsInterceptor returns a unary interceptor that increments the
// request counter and observes the latency histogram for every RPC.
func newMetricsInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		method := shortMethod(info.FullMethod)
		metrics.RPCLatency.WithLabelValues(method).Observe(time.Since(start).Seconds())
		metrics.RPCRequests.WithLabelValues(method, status.Code(err).String()).Inc()
		return resp, err
	}
}

// newStreamMetricsInterceptor does the same for server-streaming RPCs.
// Latency for streams is "until the stream ends", which is the right
// thing — long-lived streams show up as multi-second histogram samples.
func newStreamMetricsInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		method := shortMethod(info.FullMethod)
		metrics.RPCLatency.WithLabelValues(method).Observe(time.Since(start).Seconds())
		metrics.RPCRequests.WithLabelValues(method, status.Code(err).String()).Inc()
		return err
	}
}

// newAuditInterceptor returns a unary interceptor that appends one
// audit.Record per RPC. Streaming RPCs are not audited by default — the
// event stream is self-describing via SubscribeEvents anyway.
func newAuditInterceptor(al *audit.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		if al == nil {
			return resp, err
		}
		code := status.Code(err).String()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		al.Write(audit.Record{
			Method:    shortMethod(info.FullMethod),
			Code:      code,
			LatencyMS: time.Since(start).Milliseconds(),
			PeerID:    extractPeerID(req),
			ScopeID:   extractScopeID(req),
			Params:    summarizeParams(req),
			Error:     errStr,
		})
		return resp, err
	}
}

// shortMethod trims "/gmesh.v1.GMesh/AddPeer" to "AddPeer".
func shortMethod(full string) string { return path.Base(full) }

// extractPeerID best-effort pulls a peer_id off a request proto.
// Using reflection-free type switches to keep it fast + side-effect free.
func extractPeerID(req any) int64 {
	type pider interface{ GetPeerId() int64 }
	if p, ok := req.(pider); ok {
		return p.GetPeerId()
	}
	return 0
}

// extractScopeID does the same for scope_id.
func extractScopeID(req any) int64 {
	type sider interface{ GetScopeId() int64 }
	if s, ok := req.(sider); ok {
		return s.GetScopeId()
	}
	return 0
}

// summarizeParams emits a small subset of request fields safe to audit.
// Private keys, secrets, and tokens are intentionally never included.
func summarizeParams(req any) map[string]interface{} {
	// We only peek at well-known getter methods so we never leak large or
	// secret fields. Exhaustive enumeration would balloon this function;
	// the fields chosen below give operators enough context to trace an
	// action without exposing crypto material.
	out := map[string]interface{}{}
	type meshIPer interface{ GetMeshIp() string }
	if m, ok := req.(meshIPer); ok {
		if v := m.GetMeshIp(); v != "" {
			out["mesh_ip"] = v
		}
	}
	type endpointer interface{ GetEndpoint() string }
	if m, ok := req.(endpointer); ok {
		if v := m.GetEndpoint(); v != "" {
			out["endpoint"] = v
		}
	}
	type ifacer interface{ GetInterfaceName() string }
	if m, ok := req.(ifacer); ok {
		if v := m.GetInterfaceName(); v != "" {
			out["interface"] = v
		}
	}
	type portder interface{ GetListenPort() uint32 }
	if m, ok := req.(portder); ok {
		if v := m.GetListenPort(); v != 0 {
			out["listen_port"] = v
		}
	}
	type scopeMeshIPer interface{ GetScopeMeshIp() string }
	if m, ok := req.(scopeMeshIPer); ok {
		if v := m.GetScopeMeshIp(); v != "" {
			out["scope_mesh_ip"] = v
		}
	}
	type policyer interface{ GetDefaultPolicy() string }
	if m, ok := req.(policyer); ok {
		if v := m.GetDefaultPolicy(); v != "" {
			out["default_policy"] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
