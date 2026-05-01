#!/usr/bin/env python3
"""
ExRecon – TOR + Proxychains Auto Fix & Test (Python edition)
Strictly for Linux.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOGFILE = Path.home() / "tor_proxychains_fix.log"
TORRC = Path("/etc/tor/torrc")
PROXYCHAINS_TEST_URL = "https://check.torproject.org"

# ANSI
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log(msg: str, tee: bool = True):
    """Write message to logfile and optionally print."""
    if tee:
        print(msg)
    with open(LOGFILE, 'a') as f:
        f.write(msg + '\n')

def run(cmd: list, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, **kwargs)

def sudo(cmd: list):
    """Run a command with sudo."""
    return run(['sudo'] + cmd)

def is_service_active(service: str) -> bool:
    """Check if a systemd service is active."""
    try:
        res = subprocess.run(
            ['systemctl', 'is-active', '--quiet', service],
            check=False
        )
        return res.returncode == 0
    except Exception:
        return False

def backup_file(path: Path):
    """Create a timestamped backup."""
    timestamp = int(time.time())
    backup_name = f"{path.name}.bak_{timestamp}"
    backup_path = path.with_name(backup_name)
    try:
        sudo(['cp', str(path), str(backup_path)])
        return True
    except Exception:
        return False

def fix_torrc():
    """
    Remove duplicate ControlPort / CookieAuthentication entries and
    append fresh ones.
    """
    log("[-] Fixing TOR configuration...")
    if not TORRC.exists():
        log(f"[!] {TORRC} not found – cannot fix.", tee=False)
        return False

    # Read content (need sudo for read? The file is world-readable usually, but for safety we'll use sudo cat)
    try:
        res = subprocess.run(['sudo', 'cat', str(TORRC)], capture_output=True, text=True, check=True)
        content = res.stdout
    except Exception as e:
        log(f"[!] Failed to read torrc: {e}")
        return False

    # Remove lines starting with ControlPort or CookieAuthentication
    lines = content.splitlines()
    new_lines = [line for line in lines
                 if not line.strip().startswith(('ControlPort', 'CookieAuthentication'))]
    if not new_lines:
        new_lines = []  # just in case file was empty

    # Append the required lines
    new_lines.append("")
    new_lines.append("ControlPort 9051")
    new_lines.append("CookieAuthentication 1")
    new_lines.append("")

    # Write back with sudo
    new_content = '\n'.join(new_lines) + '\n'
    try:
        # Use sudo tee to overwrite the file
        with subprocess.Popen(['sudo', 'tee', str(TORRC)], stdin=subprocess.PIPE) as proc:
            proc.stdin.write(new_content.encode())
            proc.stdin.close()
            proc.wait()
        log("[+] torrc updated.")
        return True
    except Exception as e:
        log(f"[!] Failed to write torrc: {e}")
        return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log("\n[+] Starting TOR & Proxychains auto-check...")

    # ---- Step 1: start tor@default or fix config ----
    log("[*] Attempting to start tor@default.service...")
    try:
        sudo(['systemctl', 'start', 'tor@default'])
    except subprocess.CalledProcessError:
        log("[!] systemctl start failed – will attempt config fix.")
    time.sleep(1)  # allow service to try starting

    if not is_service_active('tor@default'):
        log(f"{YELLOW}[!] TOR failed to start. Attempting config fix...{NC}")

        backup_file(TORRC)
        fix_torrc()

        log("[*] Restarting tor@default after config fix...")
        try:
            sudo(['systemctl', 'restart', 'tor@default'])
            time.sleep(2)
        except subprocess.CalledProcessError:
            log(f"{RED}[!] Failed to restart TOR. Aborting.{NC}")
            sys.exit(1)

        if not is_service_active('tor@default'):
            log(f"{RED}[!] TOR still inactive after fix. Review log.{NC}")
            sys.exit(1)
    else:
        log("[+] tor@default is already active.")

    # ---- Step 2: Test TOR routing via Proxychains ----
    log("[*] Testing proxychains with TOR network...")
    try:
        result = subprocess.run(
            ['proxychains', 'curl', '-s', PROXYCHAINS_TEST_URL],
            capture_output=True, text=True, check=False
        )
        if "Congratulations" in result.stdout:
            log(f"{GREEN}[+] TOR is working through Proxychains!{NC}")
        else:
            log(f"{RED}[!] TOR check failed after fix. Please review {LOGFILE}.{NC}")
    except Exception as e:
        log(f"{RED}[!] Error running proxychains test: {e}{NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
