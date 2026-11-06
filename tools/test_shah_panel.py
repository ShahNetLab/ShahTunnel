#!/usr/bin/env python3
import json
import socket
import tempfile
import unittest
from pathlib import Path

import shah_panel


class PanelHelpersTest(unittest.TestCase):
    def test_parse_host_port_ipv4_and_hostname(self):
        self.assertEqual(shah_panel.parse_host_port("127.0.0.1:9443"), ("127.0.0.1", 9443))
        self.assertEqual(shah_panel.parse_host_port("example.net:443"), ("example.net", 443))

    def test_parse_host_port_ipv6(self):
        self.assertEqual(shah_panel.parse_host_port("[::1]:443"), ("::1", 443))
        self.assertIsNone(shah_panel.parse_host_port("::1:443"))

    def test_parse_host_port_rejects_bad_ports(self):
        for value in ("host", "host:0", "host:65536", "host:notaport", "", None):
            self.assertIsNone(shah_panel.parse_host_port(value))

    def test_offset_address(self):
        self.assertEqual(shah_panel.offset_address("example.net:9443", 1), "example.net:9444")
        self.assertEqual(shah_panel.offset_address("[2001:db8::1]:9443", 2), "[2001:db8::1]:9445")
        self.assertIsNone(shah_panel.offset_address("host:65535", 1))

    def test_adaptive_hub_checks_all_configured_transport_ports(self):
        profile = {"role": "hub", "config": {"transport": "adaptive", "control_listen": "0.0.0.0:9443", "ports": []}}
        endpoints = shah_panel.profile_endpoints(profile)
        self.assertEqual([address for _, address in endpoints], ["0.0.0.0:9443", "0.0.0.0:9444", "0.0.0.0:9445"])

    def test_discover_profiles_and_metrics_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tunnels").mkdir()
            (root / "runtime").mkdir()
            (root / "config.json").write_text(json.dumps({
                "name": "legacy-main", "role": "hub", "token": "DO_NOT_EXPOSE",
                "control_listen": "127.0.0.1:9443", "ports": []
            }))
            (root / "tunnels" / "edge-1.json").write_text(json.dumps({
                "name": "edge agent", "role": "agent", "token": "ANOTHER_SECRET",
                "hub_addr": "127.0.0.1:9443", "ports": [{"id": "app", "target": "127.0.0.1:3000"}]
            }))
            profiles = shah_panel.discover_profiles(root)
            self.assertEqual([p["id"] for p in profiles], ["legacy", "edge-1"])
            self.assertEqual(profiles[0]["unit"], "ravanreverse")
            self.assertEqual(profiles[0]["metrics_path"], root / "runtime.json")
            self.assertEqual(profiles[1]["unit"], "ravanreverse@edge-1")
            self.assertEqual(profiles[1]["metrics_path"], root / "runtime" / "edge-1.json")
            self.assertNotIn("token", {k: v for k, v in profiles[1].items() if k != "config"})

    def test_endpoint_probe_against_local_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        result = shah_panel.endpoint_probe(f"127.0.0.1:{port}", "test", timeout=0.5)
        self.assertTrue(result["ok"])
        self.assertIsNotNone(result["latency_ms"])
        server.close()

    def test_wildcard_address_probes_loopback(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        result = shah_panel.endpoint_probe(f"0.0.0.0:{port}", "wildcard", timeout=0.5)
        self.assertTrue(result["ok"])
        server.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
