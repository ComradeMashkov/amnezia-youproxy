import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import configure_proxy as cp


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "inbounds": [{"protocol": "vless", "settings": {"clients": [{"id": "example"}]}}],
            "outbounds": [{"protocol": "freedom"}],
        }

    def test_proxy_config_preserves_client_and_routes_dns_before_blocking_udp(self):
        source = copy.deepcopy(self.original)
        result = cp.make_config(source, "proxy.example", 1234, "user", "pass")
        self.assertEqual(source, self.original)
        self.assertEqual(result["inbounds"], source["inbounds"])
        self.assertEqual(result["outbounds"][0]["settings"]["address"], "proxy.example")
        self.assertEqual(result["outbounds"][0]["settings"]["port"], 1234)
        rules = result["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "isp-egress")
        self.assertEqual(rules[1]["outboundTag"], "isp-dns")
        self.assertEqual(rules[2]["outboundTag"], "blocked-udp")
        self.assertEqual(result["dns"]["tag"], rules[0]["inboundTag"][0])

    def test_existing_custom_routing_is_not_overwritten(self):
        self.original["routing"] = {"rules": [{"outboundTag": "direct"}]}
        with self.assertRaisesRegex(ValueError, "существующ"):
            cp.make_config(self.original, "proxy.example", 1234, "user", "pass")

    def test_existing_custom_outbound_is_not_overwritten(self):
        self.original["outbounds"] = [{"protocol": "freedom"}, {"protocol": "blackhole"}]
        with self.assertRaisesRegex(ValueError, "существующ"):
            cp.make_config(self.original, "proxy.example", 1234, "user", "pass")

    def test_existing_freedom_settings_are_not_overwritten(self):
        self.original["outbounds"][0]["settings"] = {"domainStrategy": "UseIPv4"}
        with self.assertRaisesRegex(ValueError, "существующ"):
            cp.make_config(self.original, "proxy.example", 1234, "user", "pass")

    def test_socks_credentials_must_fit_protocol(self):
        for user, password in [("", "pass"), ("user", ""), ("a" * 256, "pass")]:
            with self.subTest(user=user, password=password):
                with self.assertRaises(ValueError):
                    cp.validate_credentials(user, password)

    def test_restart_failure_restores_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_file = root / "server.json"
            config_file.write_text(json.dumps(self.original), encoding="utf-8")
            restarts = []

            def fake_docker(*args, **kwargs):
                if args[0] == "restart":
                    restarts.append(True)
                    if len(restarts) == 1:
                        raise subprocess.CalledProcessError(1, "docker")

            with patch.object(cp, "docker", side_effect=fake_docker):
                with self.assertRaises(subprocess.CalledProcessError):
                    cp.install_config(root, {"outbounds": []})
            self.assertEqual(json.loads(config_file.read_text(encoding="utf-8")), self.original)
            self.assertEqual(len(restarts), 2)

    def test_validation_failure_does_not_change_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_file = root / "server.json"
            config_file.write_text(json.dumps(self.original), encoding="utf-8")
            with patch.object(cp, "docker", side_effect=subprocess.CalledProcessError(1, "docker")):
                with self.assertRaises(subprocess.CalledProcessError):
                    cp.install_config(root, {"outbounds": []})
            self.assertEqual(json.loads(config_file.read_text(encoding="utf-8")), self.original)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["server.json"])

    def test_concurrent_change_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_file = root / "server.json"
            config_file.write_text('{"new": true}', encoding="utf-8")
            with patch.object(cp, "docker"):
                with self.assertRaisesRegex(RuntimeError, "изменились"):
                    cp.install_config(root, {}, b'{"old": true}')
            self.assertEqual(json.loads(config_file.read_text()), {"new": True})


if __name__ == "__main__":
    unittest.main()
