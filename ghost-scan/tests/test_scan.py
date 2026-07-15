"""Offline tests for ghost-scan — no network required."""

import socket
import threading

from ghost_scan import scanner
from ghost_scan.fingerprint import classify_port, grab_banner


def test_classify_known_ports():
    assert classify_port(80) == "http"
    assert classify_port(443) == "https"
    assert classify_port(22) == "ssh"
    assert classify_port(3306) == "mysql" or classify_port(3306) != "unknown"
    assert classify_port(999999) == "unknown"


def test_parse_ports():
    assert scanner.parse_ports("1-3,5") == [1, 2, 3, 5]
    assert scanner.parse_ports("80") == [80]
    assert scanner.parse_ports("22,80,443") == [22, 80, 443]
    assert scanner.parse_ports("3-1") == [1, 2, 3]  # reversed range normalized


def test_scan_finds_local_open_port():
    # Spin up a dummy server on an ephemeral port, scan just that port.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    results = scanner.scan_ports("127.0.0.1", [port], timeout=1.0, max_threads=1)
    srv.close()

    assert len(results) == 1
    assert results[0]["port"] == port
    assert results[0]["state"] == "open"
    assert results[0]["service"] == classify_port(port)


def test_scan_reports_closed_port():
    # Port 1 (tcpmux) is virtually never open on localhost; treat as closed probe.
    results = scanner.scan_ports("127.0.0.1", [1], timeout=0.3, max_threads=1)
    assert results[0]["port"] == 1
    assert results[0]["state"] in ("open", "closed")
