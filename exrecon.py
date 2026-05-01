#!/usr/bin/env python3
"""
ExRecon v2.1.0 – Ultimate TOR Nmap Automation (Python edition)
Strictly for Linux. Requires root for SYN scans.
"""

import argparse
import os
import re
import random
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

# =============================================================================
# Constants
# =============================================================================
VERSION = "2.1.0"
UA_STRING = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/124.0.0.0 Safari/537.36")
OUTPUT_DIR = Path.home() / "tor_scan_logs"
TORRC = "/etc/tor/torrc"
PROXYCHAINS_CONF = "/etc/proxychains4.conf"
TOR_CONTROL_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051
MAX_LOG_FILES = 20

# ANSI colors
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"

# =============================================================================
# Utility functions
# =============================================================================
def eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def color_print(color: str, *args):
    """Print a message with a color prefix."""
    msg = ' '.join(str(a) for a in args)
    eprint(f"{color}{msg}{NC}")

def run_cmd(cmd: List[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run."""
    return subprocess.run(cmd, check=check, **kwargs)

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def sudo_cmd(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with sudo."""
    return run_cmd(['sudo'] + cmd, **kwargs)

def prompt_yes_no(prompt: str) -> bool:
    while True:
        ans = input(f"{prompt} (y/n): ").strip().lower()
        if ans in ('y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False

# =============================================================================
# Signal handling
# =============================================================================
def handle_interrupt(signum, frame):
    eprint(f"\n{RED}[!]{NC} Interrupted. Partial results may exist in: {OUTPUT_DIR}")
    sys.exit(1)

signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)

# =============================================================================
# Dependency installation
# =============================================================================
def install_dependencies():
    required = ['nmap', 'tor', 'proxychains4', 'curl', 'gpg', 'nc',
                'tmux', 'coreutils', 'openssl', 'enscript', 'ghostscript',
                'pandoc', 'nikto']
    missing = [pkg for pkg in required if not command_exists(pkg)]
    if missing:
        color_print(YELLOW, f"[*] Missing packages: {', '.join(missing)}")
        if command_exists('apt'):
            color_print(YELLOW, "[*] Installing missing dependencies...")
            try:
                sudo_cmd(['apt', 'update'])
                sudo_cmd(['apt', 'install', '-y'] + missing)
            except subprocess.CalledProcessError:
                color_print(RED, "[!] Failed to install packages. Exiting.")
                sys.exit(1)
        else:
            color_print(RED, "[!] Package manager apt not found. Install manually.")
            sys.exit(1)

def configure_tor():
    """Ensure ControlPort and CookieAuthentication are set in torrc."""
    need_write = False
    try:
        with open(TORRC, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        content = ""
    if not re.search(r'^ControlPort\s+9051', content, re.MULTILINE):
        need_write = True
    if not re.search(r'^CookieAuthentication\s+0', content, re.MULTILINE):
        need_write = True
    if need_write:
        color_print(YELLOW, "[*] Updating /etc/tor/torrc...")
        # We'll use sudo to append the missing lines
        try:
            with subprocess.Popen(['sudo', 'tee', '-a', TORRC],
                                  stdin=subprocess.PIPE) as p:
                if 'ControlPort' not in content:
                    p.stdin.write(b"ControlPort 9051\n")
                if 'CookieAuthentication' not in content:
                    p.stdin.write(b"CookieAuthentication 0\n")
                p.stdin.close()
                p.wait()
        except Exception:
            color_print(RED, "[!] Cannot update torrc. Exiting.")
            sys.exit(1)

def check_proxychains():
    try:
        with open(PROXYCHAINS_CONF, 'r') as f:
            if 'socks5 127.0.0.1 9050' not in f.read():
                color_print(YELLOW,
                            f"[!] proxychains4 may not be configured for TOR. "
                            f"Check: {PROXYCHAINS_CONF}")
    except FileNotFoundError:
        color_print(YELLOW,
                    f"[!] proxychains4 configuration not found at {PROXYCHAINS_CONF}")

# =============================================================================
# TOR management
# =============================================================================
def start_tor():
    if subprocess.run(['pgrep', '-x', 'tor'], stdout=subprocess.DEVNULL).returncode != 0:
        color_print(YELLOW, "[*] Starting TOR...")
        try:
            sudo_cmd(['systemctl', 'start', 'tor'])
        except subprocess.CalledProcessError:
            color_print(RED, "[!] Failed to start TOR. Exiting.")
            sys.exit(1)
        color_print(YELLOW, "[*] Waiting for TOR control port...")
        for _ in range(30):
            if subprocess.run(['nc', '-z', TOR_CONTROL_HOST, str(TOR_CONTROL_PORT)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            color_print(RED, "[!] TOR control port not reachable.")
            sys.exit(1)

def rotate_tor_circuit():
    color_print(YELLOW, "[*] Rotating TOR circuit...")
    try:
        with subprocess.Popen(['nc', TOR_CONTROL_HOST, str(TOR_CONTROL_PORT)],
                              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as p:
            p.stdin.write(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
            p.stdin.close()
            p.wait()
    except Exception:
        color_print(RED, "[!] Failed to rotate TOR circuit.")
        sys.exit(1)
    time.sleep(2)
    color_print(GREEN, "[+] TOR circuit rotated.")

def check_tor() -> bool:
    """Check if traffic is routed through TOR using check.torproject.org."""
    try:
        result = subprocess.run(
            ['proxychains4', 'curl', '-s', 'https://check.torproject.org/'],
            capture_output=True, text=True)
        return "Congratulations" in result.stdout
    except Exception:
        return False

def get_tor_exit_ip() -> str:
    try:
        result = subprocess.run(
            ['proxychains4', 'curl', '-s', 'https://api.ipify.org'],
            capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception:
        return "unknown"

def verify_tor_routing():
    for attempt in range(1, 4):
        if check_tor():
            break
        elif attempt == 3:
            color_print(RED, "[!] TOR not routing traffic. Aborting.")
            sys.exit(1)
        else:
            color_print(YELLOW, f"[!] TOR check failed. Retrying ({attempt})...")
            time.sleep(3)
    ip = get_tor_exit_ip()
    color_print(GREEN, f"[+] Active TOR Exit IP: {ip}")
    return ip

# =============================================================================
# Decoy and utility functions
# =============================================================================
def generate_decoys() -> List[str]:
    decoys = []
    for _ in range(5):
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        decoys.append(f"{a}.{b}.{c}.{d}")
    return decoys

def check_decoy_supported() -> bool:
    try:
        result = subprocess.run(['nmap', '--help'], capture_output=True, text=True)
        return '-D' in result.stdout
    except Exception:
        return False

def check_nikto() -> bool:
    if not command_exists('nikto'):
        color_print(YELLOW, "[!] Nikto not found. Web App scan will be skipped.")
        return False
    return True

def view_results(filepath: Path):
    color_print(YELLOW, f"[*] Viewing: {filepath}")
    if command_exists('less'):
        run_cmd(['less', str(filepath)])
    else:
        # fallback to cat
        with open(filepath, 'r') as f:
            sys.stdout.write(f.read())

# =============================================================================
# Scan execution
# =============================================================================
def build_nmap_base(target: str, scan_type: str, output: Path) -> List[str]:
    """Build common nmap arguments. Returns the command list without proxychains."""
    cmd = ['nmap']
    # All scans use -Pn (no ping) and -n (no DNS resolution) unless otherwise
    cmd += ['-Pn', '-n', '--data-length', '50']  # default data-length; some override later
    cmd += ['--host-timeout', '5m']
    cmd += ['--dns-servers', '8.8.8.8']
    cmd += ['-oN', str(output)]
    cmd += [target]
    return cmd

def run_scan_1(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Quick Scan...")
    cmd = ['proxychains4', 'nmap', '-sT', '-Pn', '-n',
           '--top-ports', '100', '-T2', '--reason',
           '--data-length', '50'] + decoy_flag + \
           ['-f', '--host-timeout', '5m',
            '--dns-servers', '8.8.8.8',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_2(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Service Detection...")
    cmd = ['proxychains4', 'nmap', '-sT', '-Pn', '-sV', '-T2',
           '--script=banner,http-title,http-enum,ssl-cert',
           f'--script-args=http.useragent={UA_STRING}',
           '--data-length', '100'] + decoy_flag + \
           ['-f', '--host-timeout', '5m',
            '--dns-servers', '8.8.8.8',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_3(target: str, decoy_flag: list, output: Path):
    color_print(RED, "[!] WARNING: TOR is TCP-only. UDP scan may leak your real IP.")
    if not prompt_yes_no("Continue anyway?"):
        return
    color_print(CYAN, "[*] Running UDP Vuln Scan...")
    cmd = ['proxychains4', 'nmap', '-sU', '-sV', '-Pn',
           '--script', 'vuln',
           '--data-length', '120'] + decoy_flag + \
           ['-f', '--host-timeout', '5m', '-T2',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_4(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Full Port Scan...")
    cmd = ['proxychains4', 'nmap', '-sT', '-Pn', '-p-', '-T2',
           '--reason', '--data-length', '40'] + decoy_flag + \
           ['-f', '--host-timeout', '10m',
            '--dns-servers', '8.8.8.8',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_5(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Aggressive Scan...")
    cmd = ['proxychains4', 'nmap', '-A', '-T3', '-Pn', '--reason',
           '--data-length', '60'] + decoy_flag + \
           ['-f', '--host-timeout', '5m',
            '--dns-servers', '8.8.8.8',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_6(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Firewall Evasion Scan...")
    cmd = ['proxychains4', 'nmap', '-sT', '-Pn', '-T2', '--ttl', '65',
           '--reason', '--data-length', '80'] + decoy_flag + \
           ['-f', '--host-timeout', '5m',
            '--dns-servers', '1.1.1.1',
            '-oN', str(output), target]
    run_cmd(cmd)

def run_scan_7(target: str, decoy_flag: list, output: Path):
    color_print(CYAN, "[*] Running Web App Enumeration...")
    # Nmap scan for web ports
    nmap_cmd = ['proxychains4', 'nmap', '-sV', '-p', '80,443,8080', '-Pn',
                '--script=http-title,http-enum',
                f'--script-args=http.useragent={UA_STRING}',
                '--data-length', '100'] + decoy_flag + \
                ['--host-timeout', '5m',
                 '-oN', str(output.with_name(output.stem + '.webnmap')), target]
    run_cmd(nmap_cmd)
    if check_nikto():
        nikto_output = output.with_name(output.stem + '.nikto')
        nikto_cmd = ['proxychains4', 'nikto', '-host', target, '-output', str(nikto_output)]
        run_cmd(nikto_cmd)

def run_scan_8(target: str, decoy_flag: list, output: Path):
    color_print(RED, "[!] WARNING: SYN scans require raw sockets and may not route correctly through TOR.")
    if not prompt_yes_no("Continue anyway?"):
        return
    color_print(CYAN, "[*] Running Stealth SYN Scan...")
    cmd = ['proxychains4', 'nmap', '-sS', '-Pn', '-T1', '-n',
           '--top-ports', '100', '--reason',
           '--data-length', '60'] + decoy_flag + \
           ['-f', '--host-timeout', '5m',
            '--dns-servers', '8.8.8.8',
            '-oN', str(output), target]
    run_cmd(cmd)

SCAN_DISPATCH = {
    '1': run_scan_1,
    '2': run_scan_2,
    '3': run_scan_3,
    '4': run_scan_4,
    '5': run_scan_5,
    '6': run_scan_6,
    '7': run_scan_7,
    '8': run_scan_8,
}

# =============================================================================
# Report generation
# =============================================================================
def generate_summary(target: str, tor_exit_ip: str, timestamp: int, selected_scans: List[str],
                     output_base: Path) -> Path:
    summary_txt = OUTPUT_DIR / f"scan_summary_{timestamp}.txt"
    scan_logs = sorted(OUTPUT_DIR.glob(f"scan_{timestamp}.*"))
    lines = []
    lines.append(f"ExRecon Scan Report - Timestamp: {timestamp}")
    lines.append("=" * 40)
    lines.append("")
    lines.append(f"Target:      {target}")
    lines.append(f"TOR Exit IP: {tor_exit_ip}")
    lines.append(f"Scanned On:  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append("")
    lines.append("-- Scan Modules Executed --")
    scan_names = {
        '1': "Quick Scan (Top 100 TCP Ports)",
        '2': "Service Detection (Banner, SSL, HTTP)",
        '3': "UDP Vuln Detection",
        '4': "Full TCP Port Scan",
        '5': "Aggressive Mode",
        '6': "Firewall Evasion",
        '7': "Web App Enumeration (Nikto)",
        '8': "Stealth SYN Scan",
    }
    for s in selected_scans:
        lines.append(f"  [+] {scan_names.get(s, 'Unknown')}")
    lines.append("")
    lines.append("-- Nmap Findings --")
    found = False
    for log in scan_logs:
        if log.suffix in ('.nmap', '.webnmap') or 'scan_' in log.name:
            try:
                with open(log, 'r') as f:
                    for line in f:
                        if re.search(r'open|PORT|Service detection performed', line):
                            lines.append(line.rstrip())
                            found = True
            except Exception:
                pass
    if not found:
        lines.append("  No findings captured.")
    lines.append("")
    # Nikto findings
    nikto_file = output_base.with_name(output_base.stem + '.nikto')
    if nikto_file.exists():
        lines.append("-- Nikto Findings --")
        try:
            with open(nikto_file, 'r') as f:
                for line in f:
                    if re.search(r'\+|OSVDB|CVE', line):
                        lines.append(f"  {line.rstrip()}")
        except Exception:
            pass
        if not any("  " in l for l in lines[-5:]):  # simplistic check if no findings added
            lines.append("  No Nikto findings.")
        lines.append("")
    lines.append("-- Timeline --")
    lines.append(f"  [{timestamp}] TOR Circuit Established")
    lines.append(f"  [{timestamp}] Scans Executed: {','.join(selected_scans)}")
    lines.append(f"  [{time.strftime('%H:%M:%S', time.gmtime())}] Report Generated")
    lines.append("")
    lines.append("-- Notes --")
    lines.append("  Scan completed and stored locally.")
    with open(summary_txt, 'w') as f:
        f.write('\n'.join(lines))
    return summary_txt

def generate_pdf(summary_txt: Path) -> Optional[Path]:
    """Generate PDF using enscript+ps2pdf or pandoc."""
    pdf_path = summary_txt.with_suffix('.pdf')
    if command_exists('enscript') and command_exists('ps2pdf'):
        try:
            with open(summary_txt, 'r') as f:
                subprocess.run(['enscript', '-q', '-o', '-', str(summary_txt)],
                               stdout=subprocess.PIPE, check=True)
            # The original pipes directly; we'll adapt:
            ps_proc = subprocess.Popen(['enscript', '-q', str(summary_txt), '-o', '-'],
                                       stdout=subprocess.PIPE)
            subprocess.run(['ps2pdf', '-', str(pdf_path)], stdin=ps_proc.stdout, check=True)
            ps_proc.wait()
            return pdf_path
        except Exception:
            pass
    if command_exists('pandoc'):
        try:
            subprocess.run(['pandoc', str(summary_txt), '-o', str(pdf_path)], check=True)
            return pdf_path
        except Exception:
            pass
    return None

def delta_analysis(summary_txt: Path, prev_summary: Path) -> Optional[Path]:
    """Create diff between previous and current summary."""
    delta_file = summary_txt.with_suffix('.txt.delta')
    try:
        with open(delta_file, 'w') as f:
            subprocess.run(['diff', str(prev_summary), str(summary_txt)],
                           stdout=f, stderr=subprocess.DEVNULL)
        return delta_file
    except Exception:
        return None

# =============================================================================
# Log rotation
# =============================================================================
def rotate_logs():
    summaries = sorted(OUTPUT_DIR.glob("scan_summary_*.txt"))
    if len(summaries) > MAX_LOG_FILES:
        to_delete = summaries[:-MAX_LOG_FILES]
        for f in to_delete:
            f.unlink(missing_ok=True)
        color_print(YELLOW, f"[*] Old logs pruned. Keeping last {MAX_LOG_FILES} scans.")

# =============================================================================
# Main
# =============================================================================
def main():
    # ----- Pre-setup -----
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ----- Argument parsing -----
    parser = argparse.ArgumentParser(
        description="ExRecon - Ultimate TOR Nmap Automation",
        add_help=False)
    parser.add_argument('-t', '--target', help='Target domain or IP')
    parser.add_argument('-s', '--scan-types', help='Comma-separated scan types (1-8)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    parser.add_argument('--version', action='store_true', help='Show version')
    # Handle unknown arguments gracefully (like the original getopts)
    args, _ = parser.parse_known_args()

    if args.version:
        print(f"ExRecon v{VERSION}")
        sys.exit(0)
    if args.help:
        parser.print_help()
        print("\nExample: python exrecon.py -t example.com -s 1,2,5")
        sys.exit(0)

    target = args.target
    scan_types_str = args.scan_types

    # ----- Interactive fallback -----
    if not target:
        target = input("Target Domain/IP: ").strip()
    # Validate target format (simple)
    if not re.match(r'^[a-zA-Z0-9._:\-]+$', target):
        color_print(RED, "[!] Invalid target format. Aborting.")
        sys.exit(1)

    if not scan_types_str:
        print("Select scan types (comma-separated, e.g., 1,3,5):")
        print("  1) TOR Quick Scan")
        print("  2) TOR Service Detection")
        print("  3) TOR UDP Scan + Vuln Detection")
        print("  4) TOR Full TCP Port Scan")
        print("  5) TOR Aggressive Scan")
        print("  6) TOR Firewall Evasion Scan")
        print("  7) TOR Web App Enumeration (Nikto)")
        print("  8) TOR Stealth SYN Scan")
        scan_types_str = input("Enter selection: ").strip()
    selected_scans = [s.strip() for s in scan_types_str.split(',') if s.strip() in SCAN_DISPATCH]
    if not selected_scans:
        color_print(RED, "[!] No valid scan types selected.")
        sys.exit(1)

    # ----- Root check (warn) -----
    if os.geteuid() != 0:
        color_print(YELLOW, "[!] Warning: Not running as root. SYN scans will not work correctly.")

    # ----- Dependency installation -----
    color_print(GREEN, "[+] Checking for required dependencies...")
    install_dependencies()

    # ----- TOR & ProxyChains configuration -----
    configure_tor()
    check_proxychains()

    # ----- Header -----
    color_print(CYAN, f"=== ExRecon v{VERSION} : Ultimate TOR Nmap Automation ===")

    # ----- Start TOR -----
    start_tor()
    rotate_tor_circuit()

    # ----- Verify TOR routing -----
    tor_exit_ip = verify_tor_routing()

    # ----- Decoy setup -----
    decoy_flag = []
    if check_decoy_supported():
        decoys = generate_decoys()
        decoy_flag = ['-D', ','.join(decoys)]
    else:
        color_print(YELLOW, "[!] Nmap -D not supported. Proceeding without decoys.")

    # ----- Log rotation -----
    rotate_logs()

    # ----- Timestamp and output base -----
    timestamp = int(time.time())
    output_file_base = OUTPUT_DIR / f"scan_{timestamp}"

    # ----- Run scans -----
    for scan in selected_scans:
        rotate_tor_circuit()
        scan_func = SCAN_DISPATCH[scan]
        # Each scan function writes its own log file; we pass the base name with appropriate suffix.
        # Since SCAN_DISPATCH functions have specific naming, we'll pass the base path and they will
        # construct the right filename internally. Our previous functions already expect `output: Path`.
        # We'll map scan number to suffix:
        suffix_map = {
            '1': 'quick',
            '2': 'service',
            '3': 'udp',
            '4': 'full',
            '5': 'aggressive',
            '6': 'evasion',
            '7': 'web',      # actual files: .webnmap and .nikto
            '8': 'stealth',
        }
        out_path = output_file_base.with_name(output_file_base.name + '.' + suffix_map[scan])
        scan_func(target, decoy_flag, out_path)

    # ----- Summary and report -----
    summary_txt = generate_summary(target, tor_exit_ip, timestamp, selected_scans,
                                   output_file_base)
    pdf_path = generate_pdf(summary_txt)

    # ----- Delta analysis -----
    summaries = sorted(OUTPUT_DIR.glob("scan_summary_*.txt"), reverse=True)
    prev_summary = None
    if len(summaries) > 1:
        for f in summaries:
            if f != summary_txt:
                prev_summary = f
                break
    if prev_summary:
        color_print(YELLOW, "[*] Analyzing delta from last scan...")
        delta_file = delta_analysis(summary_txt, prev_summary)
    else:
        delta_file = None

    # ----- View results -----
    if prompt_yes_no("[*] View scan results now?"):
        for f in sorted(OUTPUT_DIR.glob(f"scan_{timestamp}.*")):
            if f.suffix in ('.pdf', '.delta', '.txt'):
                continue
            if f.exists() and f.stat().st_size > 0:
                view_results(f)
        view_results(summary_txt)

    if delta_file and delta_file.exists():
        if prompt_yes_no("[*] View change delta from last scan?"):
            view_results(delta_file)

    color_print(GREEN, f"[+] Scan complete. Results saved in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
