import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "exrecon" / "__main__.py"
spec = importlib.util.spec_from_file_location("exrecon_main", MODULE_PATH)
exrecon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exrecon)


class TargetValidationTests(unittest.TestCase):
    def test_accepts_ips_and_hostnames(self):
        valid_targets = ["127.0.0.1", "::1", "example.com", "sub-domain.example"]
        for target in valid_targets:
            with self.subTest(target=target):
                self.assertTrue(exrecon.validate_target(target))

    def test_rejects_invalid_targets(self):
        invalid_targets = ["", "all", "*.example.com", "example.com;id", "bad_label.example", "example.com/"]
        for target in invalid_targets:
            with self.subTest(target=target):
                self.assertFalse(exrecon.validate_target(target))


class ScanCommandTests(unittest.TestCase):
    @patch.object(exrecon, "run_cmd")
    def test_direct_scan_command(self, run_cmd):
        exrecon.run_scan_command("example.com", None, ["--top-ports", "10"], Path("out.nmap"))

        run_cmd.assert_called_once_with([
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "--host-timeout",
            "5m",
            "--top-ports",
            "10",
            "-oN",
            "out.nmap",
            "example.com",
        ])

    @patch.object(exrecon, "run_cmd")
    def test_proxy_scan_command(self, run_cmd):
        exrecon.run_scan_command(
            "example.com",
            Path("proxychains.conf"),
            ["--top-ports", "10"],
            Path("out.nmap"),
        )

        run_cmd.assert_called_once_with([
            "proxychains4",
            "-q",
            "-f",
            "proxychains.conf",
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "--host-timeout",
            "5m",
            "--top-ports",
            "10",
            "-oN",
            "out.nmap",
            "example.com",
        ])


class ParsingTests(unittest.TestCase):
    def test_detects_only_nmap_open_port_rows(self):
        self.assertTrue(exrecon.is_nmap_open_port_line("80/tcp open http"))
        self.assertTrue(exrecon.is_nmap_open_port_line("53/udp open domain"))
        self.assertFalse(exrecon.is_nmap_open_port_line("PORT STATE SERVICE"))
        self.assertFalse(exrecon.is_nmap_open_port_line("Host is open for testing"))
        self.assertFalse(exrecon.is_nmap_open_port_line("443/tcp closed https"))

    def test_generate_summary_includes_only_open_port_rows(self):
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            old_output_dir = exrecon.OUTPUT_DIR
            exrecon.OUTPUT_DIR = temp_path
            try:
                output_base = temp_path / "scan_123"
                (temp_path / "scan_123.1.nmap").write_text(
                    "PORT STATE SERVICE\n80/tcp open http\n443/tcp closed https\nHost is open for testing\n"
                )

                summary = exrecon.generate_summary("example.com", "direct", 123, ["1"], output_base)

                content = summary.read_text()
                self.assertIn("80/tcp open http", content)
                self.assertNotIn("443/tcp closed https", content)
                self.assertNotIn("Host is open for testing", content)
            finally:
                exrecon.OUTPUT_DIR = old_output_dir


class TorConfigTests(unittest.TestCase):
    def test_proxychains_conf_uses_socks5_and_custom_port(self):
        with tempfile.TemporaryDirectory() as tempdir:
            old_tor_user_dir = exrecon.TOR_USER_DIR
            exrecon.TOR_USER_DIR = Path(tempdir)
            try:
                conf = exrecon.write_proxychains_conf(19050)
                self.assertIn("socks5 127.0.0.1 19050", conf.read_text())
            finally:
                exrecon.TOR_USER_DIR = old_tor_user_dir


if __name__ == "__main__":
    unittest.main()
