"""Spin up a real gmeshd for integration tests.

The daemon runs in a subprocess pointing at /tmp/gmesh-pytest.sock.
Tests that need a live daemon use the ``daemon`` fixture, which yields
the socket path and tears the daemon down on exit.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GMESHD = REPO_ROOT / "bin" / "gmeshd"


def _run_daemon(name: str, ports: tuple[int, int], socket_extra: str = ""):
    """Start gmeshd with a throwaway config; yields (info, proc)."""
    if not GMESHD.exists():
        pytest.skip(f"gmeshd not built (expected at {GMESHD}; run `make build`)")

    tmp = Path(tempfile.mkdtemp(prefix=f"gmesh-pytest-{name}-"))
    socket = tmp / "gmesh.sock"
    cfg = tmp / "config.yaml"
    cfg.write_text(f"""
socket: {{path: {socket}, mode: 0o660{socket_extra}}}
log:    {{format: text, level: info}}
state:  {{dir: {tmp}, file: state.json}}
wireguard: {{interface: wg-pytest, listen_port: {ports[0]}, mtu: 1420, network_cidr: 10.200.0.0/16}}
nat:    {{udp_responder_port: {ports[1]}}}
firewall: {{use_nftables: false}}
health: {{check_interval_seconds: 2, reconnect_failing_threshold: 2}}
""")

    log = open(tmp / "daemon.log", "w")
    proc = subprocess.Popen(
        [str(GMESHD), "--config", str(cfg)],
        stdout=log, stderr=subprocess.STDOUT,
    )
    # Wait for the socket.
    for _ in range(50):
        if socket.exists():
            break
        time.sleep(0.1)
    if not socket.exists():
        proc.kill()
        pytest.fail(f"gmeshd never created socket; see {tmp}/daemon.log")

    yield {"socket": str(socket), "tmp": str(tmp)}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()
    # Leave tmp behind for postmortem if tests failed.


@pytest.fixture(scope="session")
def daemon():
    yield from _run_daemon("plain", (52040, 52041))


@pytest.fixture(scope="session")
def token_daemon():
    """A gmeshd whose control socket requires socket.token_file."""
    token_dir = Path(tempfile.mkdtemp(prefix="gmesh-pytest-token-"))
    token_file = token_dir / "control.token"
    for info in _run_daemon("token", (52042, 52043), f", token_file: {token_file}"):
        info["token_file"] = str(token_file)
        yield info


# Ensure the in-tree gen/py is on sys.path before anything imports the stubs.
_GEN_PY = str(REPO_ROOT / "gen" / "py")
if os.path.isdir(_GEN_PY) and _GEN_PY not in sys.path:
    sys.path.insert(0, _GEN_PY)
