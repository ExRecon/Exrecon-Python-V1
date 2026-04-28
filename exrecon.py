#!/usr/bin/env python3
import argparse
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


VERSION = "2.1.0"

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
NC = "\033[0m"

OUTPUT_DIR = Path.home() / "tor_scan_logs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

UA_STRING = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

SCAN_LABELS = {
    "1": "Quick Scan (Top 100 TCP Ports)",
    "2": "Service Detection (Banner, SSL, HTTP)",
    "3": "UDP Vuln Detection",
    "4": "Full TCP Port Scan",
    "5": "Aggressive Mode",
    "6": "Firewall Evasion",
    "7": "Web App Enumeration (Nikto)",
    "8": "Stealth SYN Scan",
}


def print_color(message: str) -> None:
    print(message, flush=True)


def handle_interrupt(signum, frame) -> None:
    print_color(
        f"\n{RED}[!]{NC} Interrupted. Partial results may exist in: {OUTPUT_DIR}"
    )
    raise SystemExit(1)


signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)


def run_command(command: list[str], check: bool = True, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=capture,
    )
    if capture:
        return result.stdout.strip()
    return ""


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def package_installed(name: str) -> bool:
    if not command_exists("dpkg-query"):
        return False
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", name],
        text=True,
        capture_output=True,
    )
    return result.returncode == 0 and "install ok installed" in result.stdout


def check_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print_color(
            f"{YELLOW}[!]{NC} Warning: Not running as root. SYN scans will not work correctly."
        )


def check_dependencies() -> None:
    print_color(f"{GREEN}[+]{NC} Checking for required dependencies...")
    packages = [
        "nmap",
        "tor",
        "proxychains4",
        "curl",
        "gpg",
        "netcat-openbsd",
        "tmux",
        "coreutils",
        "openssl",
        "enscript",
        "ghostscript",
        "pandoc",
        "nikto",
    ]

    missing = [
        package
        for package in packages
        if not command_exists(package) and not package_installed(package)
    ]

    if missing:
        print_color(f"{YELLOW}[*]{NC} Missing packages: {' '.join(missing)}")
        print_color(f"{YELLOW}[*]{NC} Installing missing dependencies...")
        run_command(["sudo", "apt", "update"])
        run_command(["sudo", "apt", "install", "-y", *missing])


def ensure_line(path: Path, line: str) -> None:
    existing = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    if line not in existing.splitlines():
        subprocess.run(
            ["sudo", "tee", "-a", str(path)],
            input=f"{line}\n",
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )


def configure_tor() -> None:
    torrc = Path("/etc/tor/torrc")
    if torrc.exists():
        ensure_line(torrc, "ControlPort 9051")
        ensure_line(torrc, "CookieAuthentication 0")


def check_proxychains_config() -> None:
    conf = Path("/etc/proxychains4.conf")
    if not conf.exists():
        print_color(
            f"{YELLOW}[!]{NC} proxychains4 may not be configured for TOR. Check: {conf}"
        )
        return

    content = conf.read_text(encoding="utf-8", errors="ignore")
    if not re.search(r"socks5.*127\.0\.0\.1.*9050", content):
        print_color(
            f"{YELLOW}[!]{NC} proxychains4 may not be configured for TOR. Check: {conf}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ExRecon: Ultimate TOR Nmap Automation"
    )
    parser.add_argument("-t", "--target", help="Target domain or IP")
    parser.add_argument(
        "-s", "--scan-types", help="Comma-separated scan types (1-8)"
    )
    parser.add_argument(
        "--version", action="version", version=f"ExRecon v{VERSION}"
    )
    return parser.parse_args()


def prompt_target(initial: str | None) -> str:
    target = initial or input("Target Domain/IP: ").strip()
    if not re.fullmatch(r"[a-zA-Z0-9._:-]+", target):
        print_color(f"{RED}[!]{NC} Invalid target format. Aborting.")
        raise SystemExit(1)
    return target


def prompt_scan_types(initial: str | None) -> list[str]:
    if not initial:
        print("Select scan types (comma-separated, e.g., 1,3,5):")
        print("  1) TOR Quick Scan")
        print("  2) TOR Service Detection")
        print("  3) TOR UDP Scan + Vuln Detection")
        print("  4) TOR Full TCP Port Scan")
        print("  5) TOR Aggressive Scan")
        print("  6) TOR Firewall Evasion Scan")
        print("  7) TOR Web App Enumeration (Nikto)")
        print("  8) TOR Stealth SYN Scan")
        initial = input("Enter selection: ").strip()

    selected = [item.strip() for item in initial.split(",") if item.strip()]
    invalid = [item for item in selected if item not in SCAN_LABELS]
    if invalid:
        print_color(f"{RED}[!]{NC} Invalid scan selection(s): {', '.join(invalid)}")
        raise SystemExit(1)
    return selected


def prune_old_logs() -> None:
    summaries = sorted(OUTPUT_DIR.glob("scan_summary_*.txt"))
    if len(summaries) > 20:
        for path in summaries[:-20]:
            path.unlink(missing_ok=True)
        print_color(f"{YELLOW}[*]{NC} Old logs pruned. Keeping last 20 scans.")


def generate_decoys() -> str:
    decoys = []
    for _ in range(5):
        decoys.append(
            ".".join(
                [
                    str(random.randint(1, 223)),
                    str(random.randint(0, 255)),
                    str(random.randint(0, 255)),
                    str(random.randint(1, 254)),
                ]
            )
        )
    return ",".join(decoys)


def check_nikto() -> bool:
    if not command_exists("nikto"):
        print_color(f"{YELLOW}[!]{NC} Nikto not found. Web App scan will be skipped.")
        return False
    return True


def check_decoy_supported() -> bool:
    if not command_exists("nmap"):
        return False
    help_text = run_command(["nmap", "--help"], check=False, capture=True)
    return "-D" in help_text


def view_results(path: Path) -> None:
    print_color(f"\n{YELLOW}[*]{NC} Viewing: {path}")
    for viewer in ("batcat", "bat", "less", "xdg-open"):
        if command_exists(viewer):
            run_command([viewer, str(path)], check=False)
            return
    print(path.read_text(encoding="utf-8", errors="ignore"))


def rotate_tor_circuit() -> None:
    print_color(f"{YELLOW}[*]{NC} Rotating TOR circuit...")
    payload = 'AUTHENTICATE ""\nSIGNAL NEWNYM\nQUIT\n'
    subprocess.run(
        ["nc", "127.0.0.1", "9051"],
        input=payload,
        text=True,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    print_color(f"{GREEN}[+]{NC} TOR circuit rotated.")


def check_tor() -> bool:
    result = subprocess.run(
        ["proxychains4", "curl", "-s", "https://check.torproject.org/"],
        text=True,
        capture_output=True,
    )
    return "Congratulations" in result.stdout


def start_tor() -> None:
    if subprocess.run(["pgrep", "-x", "tor"], stdout=subprocess.DEVNULL).returncode == 0:
        return

    print_color(f"{YELLOW}[*]{NC} Starting TOR...")
    run_command(["sudo", "systemctl", "start", "tor"])
    print_color(f"{YELLOW}[*]{NC} Waiting for TOR to be ready...")
    for _ in range(30):
        if subprocess.run(
            ["nc", "-z", "127.0.0.1", "9051"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0:
            break
        time.sleep(1)


def verify_tor() -> str:
    for attempt in range(1, 4):
        if check_tor():
            break
        if attempt == 3:
            print_color(f"{RED}[!]{NC} TOR not routing traffic. Aborting.")
            raise SystemExit(1)
        print_color(f"{YELLOW}[!]{NC} TOR check failed. Retrying ({attempt})...")
        time.sleep(3)

    tor_ip = run_command(
        ["proxychains4", "curl", "-s", "https://api.ipify.org"],
        capture=True,
        check=False,
    )
    print_color(f"{GREEN}[+]{NC} Active TOR Exit IP: {tor_ip}")
    return tor_ip


def nmap_command(base_output: Path, suffix: str, args: list[str], target: str, decoys: list[str]) -> None:
    output_path = base_output.with_suffix(suffix)
    command = ["proxychains4", "nmap", *args, *decoys, "-oN", str(output_path), target]
    run_command(command)


def run_scans(selected_scans: list[str], target: str, output_base: Path, decoys: list[str]) -> None:
    for scan_type in selected_scans:
        rotate_tor_circuit()

        if scan_type == "1":
            print_color(f"{CYAN}[*]{NC} Running Quick Scan...")
            nmap_command(
                output_base,
                ".quick",
                [
                    "-sT",
                    "-Pn",
                    "-n",
                    "--top-ports",
                    "100",
                    "-T2",
                    "--reason",
                    "--data-length",
                    "50",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "--dns-servers",
                    "8.8.8.8",
                ],
                target,
                decoys,
            )
        elif scan_type == "2":
            print_color(f"{CYAN}[*]{NC} Running Service Detection...")
            nmap_command(
                output_base,
                ".service",
                [
                    "-sT",
                    "-Pn",
                    "-sV",
                    "-T2",
                    "--script=banner,http-title,http-enum,ssl-cert",
                    "--script-args",
                    f"http.useragent={UA_STRING}",
                    "--data-length",
                    "100",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "--dns-servers",
                    "8.8.8.8",
                ],
                target,
                decoys,
            )
        elif scan_type == "3":
            print_color(
                f"{RED}[!]{NC} WARNING: TOR is TCP-only. UDP scan may leak your real IP."
            )
            if input("Continue anyway? (y/n): ").strip().lower() != "y":
                continue
            print_color(f"{CYAN}[*]{NC} Running UDP Vuln Scan...")
            nmap_command(
                output_base,
                ".udp",
                [
                    "-sU",
                    "-sV",
                    "-Pn",
                    "--script",
                    "vuln",
                    "--data-length",
                    "120",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "-T2",
                ],
                target,
                decoys,
            )
        elif scan_type == "4":
            print_color(f"{CYAN}[*]{NC} Running Full Port Scan...")
            nmap_command(
                output_base,
                ".full",
                [
                    "-sT",
                    "-Pn",
                    "-p-",
                    "-T2",
                    "--reason",
                    "--data-length",
                    "40",
                    "-f",
                    "--host-timeout",
                    "10m",
                    "--dns-servers",
                    "8.8.8.8",
                ],
                target,
                decoys,
            )
        elif scan_type == "5":
            print_color(f"{CYAN}[*]{NC} Running Aggressive Scan...")
            nmap_command(
                output_base,
                ".aggressive",
                [
                    "-A",
                    "-T3",
                    "-Pn",
                    "--reason",
                    "--data-length",
                    "60",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "--dns-servers",
                    "8.8.8.8",
                ],
                target,
                decoys,
            )
        elif scan_type == "6":
            print_color(f"{CYAN}[*]{NC} Running Firewall Evasion Scan...")
            nmap_command(
                output_base,
                ".evasion",
                [
                    "-sT",
                    "-Pn",
                    "-T2",
                    "--ttl",
                    "65",
                    "--reason",
                    "--data-length",
                    "80",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "--dns-servers",
                    "1.1.1.1",
                ],
                target,
                decoys,
            )
        elif scan_type == "7":
            print_color(f"{CYAN}[*]{NC} Running Web App Enumeration...")
            nmap_command(
                output_base,
                ".webnmap",
                [
                    "-sV",
                    "-p",
                    "80,443,8080",
                    "-Pn",
                    "--script",
                    "http-title,http-enum",
                    "--script-args",
                    f"http.useragent={UA_STRING}",
                    "--data-length",
                    "100",
                    "--host-timeout",
                    "5m",
                ],
                target,
                decoys,
            )
            if check_nikto():
                run_command(
                    [
                        "proxychains4",
                        "nikto",
                        "-host",
                        target,
                        "-output",
                        str(output_base.with_suffix(".nikto")),
                    ],
                    check=False,
                )
        elif scan_type == "8":
            print_color(
                f"{RED}[!]{NC} WARNING: SYN scans require raw sockets and may not route correctly through TOR."
            )
            if input("Continue anyway? (y/n): ").strip().lower() != "y":
                continue
            print_color(f"{CYAN}[*]{NC} Running Stealth SYN Scan...")
            nmap_command(
                output_base,
                ".stealth",
                [
                    "-sS",
                    "-Pn",
                    "-T1",
                    "-n",
                    "--top-ports",
                    "100",
                    "--reason",
                    "--data-length",
                    "60",
                    "-f",
                    "--host-timeout",
                    "5m",
                    "--dns-servers",
                    "8.8.8.8",
                ],
                target,
                decoys,
            )


def collect_findings(timestamp: str) -> list[str]:
    findings = []
    pattern = re.compile(r"(open|PORT|Service detection performed)")
    for path in sorted(OUTPUT_DIR.glob(f"scan_{timestamp}.*")):
        if path.suffix in {".txt", ".pdf", ".delta", ".nikto"}:
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if pattern.search(line):
                findings.append(line)
    return findings


def collect_nikto_findings(timestamp: str) -> list[str]:
    nikto_path = OUTPUT_DIR / f"scan_{timestamp}.nikto"
    if not nikto_path.exists():
        return []
    matches = []
    pattern = re.compile(r"(\+|OSVDB|CVE)")
    for line in nikto_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if pattern.search(line):
            matches.append(f"  {line}")
    return matches


def generate_summary(timestamp: str, target: str, tor_ip: str, selected_scans: list[str]) -> Path:
    summary_txt = OUTPUT_DIR / f"scan_summary_{timestamp}.txt"
    findings = collect_findings(timestamp)
    nikto_findings = collect_nikto_findings(timestamp)
    now_utc = datetime.now(timezone.utc)

    lines = [
        f"ExRecon Scan Report - Timestamp: {timestamp}",
        "===========================================",
        "",
        f"Target:      {target}",
        f"TOR Exit IP: {tor_ip}",
        f"Scanned On:  {now_utc.strftime('%a %b %d %H:%M:%S UTC %Y')}",
        "",
        "Modules Executed",
    ]
    lines.extend(f"  [+] {SCAN_LABELS[scan]}" for scan in selected_scans)
    lines.extend(["", "Nmap Findings"])
    lines.extend(findings or ["  No findings captured."])

    if nikto_findings:
        lines.extend(["", "Nikto Findings"])
        lines.extend(nikto_findings)

    lines.extend(
        [
            "",
            "Timeline",
            f"  [{timestamp}] TOR Circuit Established",
            f"  [{timestamp}] Scans Executed: {' '.join(selected_scans)}",
            f"  [{now_utc.strftime('%H:%M:%S')}] Report Generated",
            "",
            "Notes",
            "  Scan completed and stored locally.",
            "",
        ]
    )

    summary_txt.write_text("\n".join(lines), encoding="utf-8")
    return summary_txt


def generate_pdf(summary_txt: Path) -> None:
    summary_pdf = summary_txt.with_suffix(".pdf")
    if command_exists("enscript") and command_exists("ps2pdf"):
        enscript = subprocess.Popen(
            ["enscript", "-q", str(summary_txt), "-o", "-"],
            stdout=subprocess.PIPE,
        )
        with summary_pdf.open("wb") as output_handle:
            subprocess.run(["ps2pdf", "-", str(summary_pdf)], stdin=enscript.stdout, check=False)
        if enscript.stdout is not None:
            enscript.stdout.close()
        enscript.wait()
    elif command_exists("pandoc"):
        run_command(["pandoc", str(summary_txt), "-o", str(summary_pdf)], check=False)


def generate_delta(summary_txt: Path) -> None:
    summaries = sorted(OUTPUT_DIR.glob("scan_summary_*.txt"), reverse=True)
    latest_summary = next((path for path in summaries if path != summary_txt), None)
    if latest_summary is None:
        return

    print_color(f"{YELLOW}[*]{NC} Analyzing delta from last scan...")
    result = subprocess.run(
        ["diff", str(latest_summary), str(summary_txt)],
        text=True,
        capture_output=True,
    )
    (summary_txt.parent / f"{summary_txt.name}.delta").write_text(
        result.stdout,
        encoding="utf-8",
    )


def maybe_view_results(timestamp: str, summary_txt: Path) -> None:
    if input("[*] View scan results now? (y/n): ").strip().lower() == "y":
        for path in sorted(OUTPUT_DIR.glob(f"scan_{timestamp}.*")):
            if path.suffix in {".pdf", ".delta", ".txt"}:
                continue
            if path.is_file():
                view_results(path)
        view_results(summary_txt)

    delta_path = summary_txt.parent / f"{summary_txt.name}.delta"
    if delta_path.exists():
        if input("[*] View change delta from last scan? (y/n): ").strip().lower() == "y":
            view_results(delta_path)


def main() -> None:
    args = parse_args()

    check_root()
    check_dependencies()
    configure_tor()
    check_proxychains_config()

    print_color(f"{CYAN}=== ExRecon v{VERSION} : Ultimate TOR Nmap Automation ==={NC}")

    target = prompt_target(args.target)
    selected_scans = prompt_scan_types(args.scan_types)

    timestamp = str(int(time.time()))
    output_base = OUTPUT_DIR / f"scan_{timestamp}"

    prune_old_logs()
    start_tor()
    rotate_tor_circuit()
    tor_ip = verify_tor()

    decoys: list[str] = []
    if check_decoy_supported():
        decoys = ["-D", generate_decoys()]
    else:
        print_color(
            f"{YELLOW}[!]{NC} Nmap -D not supported on this system. Proceeding without decoys."
        )

    run_scans(selected_scans, target, output_base, decoys)
    summary_txt = generate_summary(timestamp, target, tor_ip, selected_scans)
    generate_pdf(summary_txt)
    generate_delta(summary_txt)
    maybe_view_results(timestamp, summary_txt)

    print_color(f"{GREEN}[+]{NC} Scan complete. Results saved in: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
