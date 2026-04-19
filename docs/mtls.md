# mTLS / SPIFFE identity (Phase 20)

`internal/mtls` is a small embedded certificate authority that issues
short-lived certificates for mesh peers with a SPIFFE-style identity
(`spiffe://<trust-domain>/peer/<id>`). It complements WireGuard's
public-key identity with an application-layer identity that services
running on top of the mesh (ingress TLS termination, per-peer gRPC
auth, service-to-service clients) can verify.

## Why embed a CA

- **One trust anchor per mesh.** External CAs would require operators
  to juggle DNS, domains, and ACME challenges per VM. A gmesh mesh
  already has a stable identity space (peer IDs + WG public keys) —
  we lean on that.
- **Short-lived by design.** Default 90-day validity, `gmeshctl mtls
  issue` is cheap enough (< 1 ms/cert on ECDSA P-256) to re-issue
  weekly from a cron job.
- **No external dependencies.** The whole thing is `crypto/x509` +
  filesystem. No HSM, no Vault, no cloud KMS.

What it deliberately does NOT do yet:

- OCSP responder — revocation is a JSON list polled by verifiers.
- Intermediate CAs — one self-signed root per mesh.
- Auto-rotation — callers re-issue via RPC when they want.
- HSM/KMS-backed root — the root key is a local file, mode 0600.

## Config

```yaml
mtls:
  dir: /var/lib/gmesh/ca
  trust_domain: gmesh.local
```

Omit `dir` to disable; all `mtls` RPCs will return
`FailedPrecondition`. The directory must be writable by the user
running gmeshd — the root key lives there as `ca.key` (0600).

## CLI

```
gmeshctl mtls init [--trust-domain gmesh.local] [--force]
gmeshctl mtls status
gmeshctl mtls issue --peer-id N [--cn peer-N] [--dns svc.internal]
                    [--ip 10.250.0.7] [--days 90]
                    [--spiffe-id spiffe://…] [--out-dir /path]
gmeshctl mtls list [--peer-id N]
gmeshctl mtls revoke --serial <hex> [--reason "..."]
gmeshctl mtls trust [--out ca.pem]
```

### Typical flow

Bootstrap on the CA host (pick one mesh node as the authority — usually
the same one operators call control plane):

```
$ gmeshctl mtls init
CA initialised; trust_domain=gmesh.local
-----BEGIN CERTIFICATE-----
...
```

Issue a peer cert:

```
$ gmeshctl mtls issue --peer-id 3 --dns fsn1.internal --out-dir /etc/tls/gmesh/fsn1
serial:    8980ab…
peer_id:   3
spiffe_id: spiffe://gmesh.local/peer/3
valid:     2026-04-19T21:07:21Z → 2026-07-18T21:07:21Z
written to /etc/tls/gmesh/fsn1/{cert,key,ca}.pem
```

Ship `cert.pem` + `key.pem` + `ca.pem` to peer 3 (over the mesh is
fine — the private key only leaves the CA host as a one-off secret).

Verify a remote peer's cert:

```go
caCert, _ := mtls.ParseCertPEM(trustBundle)
pool := x509.NewCertPool()
pool.AddCert(caCert)
_, err := peerCert.Verify(x509.VerifyOptions{Roots: pool})
```

Revoke:

```
$ gmeshctl mtls revoke --serial 8980ab… --reason "laptop stolen"
revoked 8980ab…
```

Revocations land in `/var/lib/gmesh/ca/revoked.json` and show up in
`gmeshctl mtls list` with a non-empty REVOKED column. Verifiers can
check `Manager.IsRevoked(serial)` before trusting a cert.

## On-disk layout

```
/var/lib/gmesh/ca/
├── ca.crt                       # PEM root certificate
├── ca.key                       # PEM root key, mode 0600
├── issued/
│   ├── peer-1-<serial>.json     # Summary + cert PEM
│   └── peer-3-<serial>.json
└── revoked.json                 # JSON array of revoked serials
```

Every write uses a temp-then-rename pattern so a crashed gmeshd can't
leave a half-written CA file.

## SPIFFE details

The issued cert carries:

- **Subject CN** — `peer-<id>` by default, operator-overridable.
- **URI SAN** — `spiffe://<trust-domain>/peer/<id>`.
- **DNS SAN(s)** — operator-supplied (`--dns fsn1.internal`).
- **IP SAN(s)** — operator-supplied (`--ip 10.250.0.7`).
- **Extended key usage** — server + client auth, so the same cert is
  usable for incoming (server-side TLS) and outgoing (mTLS client)
  handshakes.

The URI SAN is the canonical identity. Services validating a peer
should match on that (or on the serial, if they pin). The CN is for
humans and log lines.

## What's next

- Ingress profile `require_mtls: true` — currently reserved in proto,
  validate rejected. Phase 20.5 will let an ingress profile terminate
  TLS using the CA root as trust anchor, requiring a valid peer cert
  and optional SPIFFE ID match.
- gRPC control-plane TLS (`gmeshctl → gmeshd`) — today the socket is
  a Unix domain socket on localhost, secured by file mode. A future
  phase will allow a TCP socket with mTLS using the mesh CA.
- Auto-rotation sidecar in the agent — would watch `NotAfter` and
  re-issue automatically ~7 days before expiry.
