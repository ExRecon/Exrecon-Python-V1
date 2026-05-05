#!/usr/bin/env python3
"""
ExRecon secure rewrite – User‑space Tor, no root, no silent system changes.

Usage:
  python exrecon.py -t <target> [-s <1,2,3,...>] [--no-tor] [--help]
"""

import argparse
import ipaddress
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = "2.2.0-secure"
OUTPUT_DIR = Path.home() / "tor_scan_logs"
TOR_USER_DIR = Path.home() / ".exrecon" / "tor"
TORRC_TEMPLATE = """\
DataDirectory {datadir}
SocksPort {socks_port}
ControlPort {control_port}
CookieAuthentication 1
CookieAuthFileGroupReadable 0
Log notice file {logfile}
"""

PROXYCHAINS_TEMPLATE = """\
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 {socks_port}
"""

# ANSI colours
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------
def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)

def color_print(color: str, *args) -> None:
    msg = ' '.join(str(a) for a in args)
    eprint(f"{color}{msg}{NC}")

def run_cmd(cmd: List[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run with argument list – no shell."""
    return subprocess.run(cmd, check=check, **kwargs)

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def validate_target(target: str) -> bool:
    """Allow a single IP address or DNS hostname."""
    if not target or target.lower() == 'all':
        return False
    if not re.fullmatch(r'[a-zA-Z0-9._\-:]+', target):
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    if len(target) > 253 or target.endswith('.'):
        return False
    labels = target.split('.')
    hostname_label = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
    return all(hostname_label.fullmatch(label) for label in labels)

def valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def read_cookie(cookie_path: Path) -> str:
    """Read hex cookie from Tor control auth file."""
    with open(cookie_path, 'rb') as f:
        return f.read().hex()

def tor_control_command(command: str, cookie_path: Path, control_port: int = 9051) -> None:
    """Send a single command to Tor control port using cookie auth."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
            s.connect(('127.0.0.1', control_port))
        except Exception:
            raise ConnectionError("Cannot connect to Tor ControlPort")
        # Read banner
        s.recv(1024)
        # Authenticate
        cookie_hex = read_cookie(cookie_path)
        s.sendall(f'AUTHENTICATE {cookie_hex}\r\n'.encode())
        resp = s.recv(1024)
        if not resp.startswith(b'250'):
            raise RuntimeError(f"Tor authentication failed: {resp.decode().strip()}")
        # Send command
        s.sendall(f'{command}\r\n'.encode())
        resp = s.recv(1024)
        if not resp.startswith(b'250'):
            raise RuntimeError(f"Tor command failed: {resp.decode().strip()}")

# ---------------------------------------------------------------------------
# User‑space Tor management
# ---------------------------------------------------------------------------
class UserTor:
    """Launch and control a user‑space Tor process."""

    def __init__(self, socks_port: int = 9050, control_port: int = 9051):
        self.process: Optional[subprocess.Popen] = None
        TOR_USER_DIR.mkdir(parents=True, exist_ok=True)
        self.datadir = TOR_USER_DIR / "data"
        self.datadir.mkdir(exist_ok=True)
        self.logfile = TOR_USER_DIR / "tor.log"
        self.socks_port = socks_port
        self.control_port = control_port
        self.cookie_file = self.datadir / "control_auth_cookie"
        self.torrc_path = TOR_USER_DIR / "torrc"

    def write_torrc(self) -> None:
        content = TORRC_TEMPLATE.format(
            datadir=self.datadir,
            socks_port=self.socks_port,
            control_port=self.control_port,
            logfile=self.logfile,
        )
        with open(self.torrc_path, 'w') as f:
            f.write(content)

    def start(self) -> None:
        """Start Tor process and wait until control port responds."""
        if not command_exists('tor'):
            raise RuntimeError("tor not found in PATH")
        self.write_torrc()
        # Remove any stale cookie so we can detect when new one is created
        self.cookie_file.unlink(missing_ok=True)
        self.process = subprocess.Popen(
            ['tor', '-f', str(self.torrc_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for cookie file to appear (Tor is ready)
        for _ in range(30):
            if self.cookie_file.exists():
                # Wait a bit more for control port to open
                time.sleep(1)
                break
            time.sleep(1)
        else:
            self.terminate()
            raise RuntimeError("User Tor process did not start in time")
        # Verify control port
        self._wait_for_control()

    def _wait_for_control(self) -> None:
        """Repeatedly try to connect to control port."""
        for _ in range(10):
            try:
                tor_control_command('GETINFO version', self.cookie_file, self.control_port)
                return
            except Exception:
                time.sleep(1)
        raise RuntimeError("Tor control port not reachable")

    def new_circuit(self) -> None:
        """Signal NEWNYM to build fresh circuits."""
        tor_control_command('SIGNAL NEWNYM', self.cookie_file, self.control_port)
        # Wait for circuits to be built
        time.sleep(5)
        # Verify we are still connected
        tor_control_command('GETINFO version', self.cookie_file, self.control_port)

    def terminate(self) -> None:
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

# ---------------------------------------------------------------------------
# Proxychains helper
# ---------------------------------------------------------------------------
def write_proxychains_conf(socks_port: int = 9050) -> Path:
    """Create a custom proxychains config for our user Tor."""
    conf_path = TOR_USER_DIR / "proxychains.conf"
    with open(conf_path, 'w') as f:
        f.write(PROXYCHAINS_TEMPLATE.format(socks_port=socks_port))
    return conf_path

# ---------------------------------------------------------------------------
# Tor connectivity checks
# ---------------------------------------------------------------------------
def check_tor_via_proxy(proxychains_conf: Path) -> bool:
    """Check if HTTP request to check.torproject.org succeeds over Tor."""
    try:
        res = run_cmd(
            ['proxychains4', '-q', '-f', str(proxychains_conf),
             'curl', '-s', 'https://check.torproject.org/'],
            capture_output=True, text=True, timeout=30
        )
        return 'Congratulations' in res.stdout
    except Exception:
        return False

def get_tor_exit_ip(proxychains_conf: Path) -> str:
    try:
        res = run_cmd(
            ['proxychains4', '-q', '-f', str(proxychains_conf),
             'curl', '-s', 'https://api.ipify.org'],
            capture_output=True, text=True, timeout=20
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"

# ---------------------------------------------------------------------------
# Safe Nmap scan functions – all use -sT (TCP connect)
# ---------------------------------------------------------------------------
def run_scan_command(
    target: str, proxychains_conf: Optional[Path], scan_args: List[str], output: Path
) -> None:
    """Execute an Nmap TCP connect scan, optionally through proxychains."""
    if proxychains_conf is None:
        cmd = ['nmap', '-sT']
    else:
        cmd = ['proxychains4', '-q', '-f', str(proxychains_conf), 'nmap', '-sT']
    cmd += ['-Pn', '-n', '--host-timeout', '5m']
    cmd += scan_args + ['-oN', str(output), target]
    run_cmd(cmd)

def scan_quick(target: str, conf: Optional[Path], out: Path) -> None:
    color_print(CYAN, "[*] Quick TCP Connect Scan (top 100 ports)")
    run_scan_command(
        target,
        conf,
        ['--top-ports', '100', '-T2', '--reason'],
        out,
    )

def scan_service(target: str, conf: Optional[Path], out: Path) -> None:
    color_print(CYAN, "[*] Service Version Detection")
    run_scan_command(
        target,
        conf,
        [
            '-sV',
            '-T2',
            '--script=banner,http-title,ssl-cert',
            '--script-args=http.useragent=Mozilla/5.0',
        ],
        out,
    )

def scan_full_tcp(target: str, conf: Optional[Path], out: Path) -> None:
    color_print(CYAN, "[*] Full TCP Port Scan (1-65535)")
    run_scan_command(
        target,
        conf,
        ['-p-', '-T2', '--reason'],
        out,
    )

def scan_web(target: str, conf: Optional[Path], out: Path) -> None:
    color_print(CYAN, "[*] Web Application Enumeration")
    nmap_out = out.with_name(out.stem + '.webnmap')
    run_scan_command(
        target,
        conf,
        ['-p', '80,443,8080,8443', '-sV', '--script=http-title,http-enum,ssl-cert'],
        nmap_out,
    )

    if command_exists('nikto'):
        nikto_out = out.with_name(out.stem + '.nikto')
        try:
            cmd = ['nikto', '-host', target, '-output', str(nikto_out)]
            if conf is not None:
                cmd = ['proxychains4', '-q', '-f', str(conf)] + cmd
            run_cmd(cmd)
        except subprocess.CalledProcessError:
            color_print(YELLOW, "[!] Nikto scan failed (possibly no web server).")
    else:
        color_print(YELLOW, "[!] Nikto not found, skipping web app scan.")


# Map safe scan numbers to (description, function)
SAFE_SCANS: Dict[str, Tuple[str, Callable[[str, Optional[Path], Path], None]]] = {
    '1': ('Quick TCP Connect Scan', scan_quick),
    '2': ('Service Version Detection', scan_service),
    '3': ('Full TCP Port Scan', scan_full_tcp),
    '4': ('Web Application Enumeration', scan_web),
}

# Unsafe scans – only allowed when --no-tor is given
UNSAFE_SCANS: Dict[str, str] = {
    '5': 'Stealth SYN Scan (-sS)',
    '6': 'UDP Scan (-sU)',
    '7': 'Aggressive Scan (-A)',
    '8': 'Firewall Evasion (fragmented SYN)',
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def is_nmap_open_port_line(line: str) -> bool:
    """Return True for Nmap port rows whose state is open."""
    columns = line.split()
    if len(columns) < 2:
        return False
    return bool(re.fullmatch(r'\d+/(tcp|udp|sctp)', columns[0])) and columns[1] == 'open'


def generate_summary(target: str, tor_exit_ip: str, timestamp: int,
                     selected_scans: List[str], output_base: Path) -> Path:
    summary_txt = OUTPUT_DIR / f"scan_summary_{timestamp}.txt"
    lines = [
        f"ExRecon Scan Report - {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp))}",
        "=" * 40,
        "",
        f"Target:      {target}",
        f"TOR Exit IP: {tor_exit_ip}" if tor_exit_ip != "unknown" else "TOR Exit IP: not available",
        "",
        "-- Scans Performed --",
    ]
    for s in selected_scans:
        name = SAFE_SCANS.get(s, UNSAFE_SCANS.get(s, 'Unknown'))
        lines.append(f"  [+] {name[0] if isinstance(name, tuple) else name}")
    lines.append("")
    lines.append("-- Nmap Open Ports --")
    found = False
    for log in sorted(output_base.parent.glob(f"{output_base.stem}.*")):
        if log.suffix in ('.nmap', '.webnmap') or log.name.endswith('.nmap'):
            try:
                with open(log, 'r') as f:
                    for line in f:
                        if is_nmap_open_port_line(line):
                            lines.append(line.rstrip())
                            found = True
            except Exception:
                pass
    if not found:
        lines.append("  No open ports detected.")
    lines.append("")

    # Nikto findings
    nikto = output_base.with_name(output_base.stem + '.nikto')
    if nikto.exists():
        lines.append("-- Nikto Highlights --")
        try:
            with open(nikto, 'r') as f:
                for line in f:
                    if line.startswith('+'):
                        lines.append(f"  {line.rstrip()}")
        except Exception:
            pass
        lines.append("")

    with open(summary_txt, 'w') as f:
        f.write('\n'.join(lines))
    return summary_txt

def delta_analysis(new_summary: Path, old_summary: Path) -> Optional[Path]:
    delta = new_summary.with_suffix('.delta')
    try:
        with open(delta, 'w') as f:
            run_cmd(['diff', str(old_summary), str(new_summary)],
                    stdout=f, stderr=subprocess.DEVNULL, check=False)
        return delta
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(
        description="ExRecon – Secure Tor Nmap Automation",
        add_help=False,
    )
    parser.add_argument('-t', '--target', help='Target IP or hostname')
    parser.add_argument('-s', '--scans', default='1,2,4',
                        help='Comma-separated scan numbers (default: 1,2,4)')
    parser.add_argument('--no-tor', action='store_true',
                        help='Disable Tor; run direct Nmap (no anonymity, safe scans only)')
    parser.add_argument('--socks-port', type=int, default=9050,
                        help='Tor SOCKS port to use when Tor is enabled (default: 9050)')
    parser.add_argument('--control-port', type=int, default=9051,
                        help='Tor control port to use when Tor is enabled (default: 9051)')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help')
    parser.add_argument('--version', action='store_true', help='Show version')
    args, _ = parser.parse_known_args()

    if args.version:
        print(f"ExRecon {VERSION}")
        return
    if args.help:
        parser.print_help()
        print()
        print("Safe scan types (work with Tor):")
        for num, (desc, _) in SAFE_SCANS.items():
            print(f"  {num} - {desc}")
        print("\nUnsafe scan types (only with --no-tor):")
        for num, desc in UNSAFE_SCANS.items():
            print(f"  {num} - {desc}")
        return

    target = args.target
    if not target:
        target = input("Target domain/IP: ").strip()
    if not validate_target(target):
        color_print(RED, "[!] Invalid target. Only IPs and hostnames allowed.")
        sys.exit(1)

    if not valid_port(args.socks_port) or not valid_port(args.control_port):
        color_print(RED, "[!] Tor ports must be between 1 and 65535.")
        sys.exit(1)
    if args.socks_port == args.control_port:
        color_print(RED, "[!] SOCKS port and control port must be different.")
        sys.exit(1)

    selected = [s.strip() for s in args.scans.split(',') if s.strip()]

    # Check if any selected scan is unsafe while Tor is enabled
    if not args.no_tor:
        unsafe_asked = [s for s in selected if s in UNSAFE_SCANS]
        if unsafe_asked:
            color_print(RED, "[!] The following scans require raw sockets and cannot anonymise:")
            for s in unsafe_asked:
                print(f"    {s} - {UNSAFE_SCANS[s]}")
            color_print(RED, "[!] Aborting. Use --no-tor if you understand the risks, or choose safe scans (1-4).")
            sys.exit(1)
        # Filter unknown numbers
        valid_scans = [s for s in selected if s in SAFE_SCANS]
    else:
        # With --no-tor we allow all, but we only implement safe scans in this script.
        # For unsafe ones we still don't run them – or we could implement basic direct Nmap commands.
        # For simplicity, only safe scans are actually coded; unsafe prompt is shown but not executed.
        # We'll just warn and run only safe ones.
        color_print(YELLOW, "[!] --no-tor selected: Traffic will NOT be anonymised.")
        valid_scans = [s for s in selected if s in SAFE_SCANS or s in UNSAFE_SCANS]
        if any(s in UNSAFE_SCANS for s in valid_scans):
            color_print(YELLOW, "[!] This script currently only automates safe TCP connect scans.")
            color_print(YELLOW, "[!] For other scan types, run Nmap manually with proxychains.")
            # Fallback to safe scans only
            valid_scans = [s for s in valid_scans if s in SAFE_SCANS]

    if not valid_scans:
        color_print(RED, "[!] No valid scan type selected.")
        sys.exit(1)

    # Check required tools
    required_tools = ['nmap'] if args.no_tor else ['nmap', 'proxychains4', 'curl']
    missing = [t for t in required_tools if not command_exists(t)]
    if missing:
        color_print(RED, f"[!] Missing tools: {', '.join(missing)}. Please install them manually.")
        sys.exit(1)

    # User‑space Tor (if not --no-tor)
    utor = None
    if args.no_tor:
        proxychains_conf = None  # no proxy
        tor_exit_ip = "direct (no Tor)"
    else:
        if not command_exists('tor'):
            color_print(RED, "[!] tor not found. Install tor or use --no-tor.")
            sys.exit(1)
        utor = UserTor(socks_port=args.socks_port, control_port=args.control_port)
        try:
            color_print(YELLOW, "[*] Starting user‑space Tor...")
            utor.start()
        except Exception as e:
            color_print(RED, f"[!] Failed to start Tor: {e}")
            sys.exit(1)
        # Create proxychains config
        proxychains_conf = write_proxychains_conf(args.socks_port)
        # Wait and verify Tor is working
        for attempt in range(3):
            if check_tor_via_proxy(proxychains_conf):
                break
            if attempt < 2:
                color_print(YELLOW, "[*] Waiting for Tor circuit...")
                time.sleep(5)
        else:
            color_print(RED, "[!] Tor is not routing traffic. Aborting.")
            utor.terminate()
            sys.exit(1)
        tor_exit_ip = get_tor_exit_ip(proxychains_conf)
        color_print(GREEN, f"[+] Tor Exit IP: {tor_exit_ip}")

    # Signal handler to clean up Tor
    def cleanup(signum, frame):
        color_print(RED, "\n[!] Interrupted. Cleaning up...")
        if utor:
            utor.terminate()
        sys.exit(1)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    timestamp = int(time.time())
    output_base = OUTPUT_DIR / f"scan_{timestamp}"

    try:
        for scan_id in valid_scans:
            if scan_id in SAFE_SCANS:
                if utor:
                    # Rotate circuit before each scan
                    try:
                        utor.new_circuit()
                    except Exception as e:
                        color_print(YELLOW, f"[!] Circuit rotation failed: {e}")
                func = SAFE_SCANS[scan_id][1]
                suffix = scan_id  # simple suffix, function handles its own file names
                out_path = output_base.with_name(f"{output_base.name}.{suffix}")
                func(target, proxychains_conf if not args.no_tor else None, out_path)
            # else unsafe – we have filtered them out
            # (could add direct Nmap calls without proxychains, but omitted for brevity)
    finally:
        if utor:
            utor.terminate()

    # Report
    summary_txt = generate_summary(target, tor_exit_ip, timestamp, valid_scans, output_base)
    color_print(GREEN, f"[+] Summary: {summary_txt}")

    # Delta analysis with previous summary
    summaries = sorted(OUTPUT_DIR.glob("scan_summary_*.txt"), reverse=True)
    prev = None
    for s in summaries:
        if s != summary_txt:
            prev = s
            break
    if prev:
        color_print(YELLOW, "[*] Comparing with previous scan...")
        delta = delta_analysis(summary_txt, prev)
        if delta:
            color_print(GREEN, f"[+] Delta file: {delta}")

    color_print(GREEN, f"[+] All scan logs saved in {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
