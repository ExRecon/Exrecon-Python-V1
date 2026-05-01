#!/usr/bin/env python3
"""
ExRecon Dependencies Installer – Python edition
Installs all required tools for ExRecon to function.
Strictly for Linux.
"""

import os
import subprocess
import sys
from pathlib import Path

REQUIRED_PACKAGES = [
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

TORRC = Path("/etc/tor/torrc")

def run(cmd: list, check: bool = True):
    """Execute a command, optionally checking for errors."""
    try:
        subprocess.run(cmd, check=check)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)}")
        if check:
            sys.exit(e.returncode)

def sudo(cmd: list):
    """Run a command with sudo."""
    return run(["sudo"] + cmd)

def main():
    print("[+] Updating package list...")
    sudo(["apt", "update"])
    sudo(["apt", "upgrade", "-y"])  # added -y to avoid prompt

    print(f"[+] Installing packages: {' '.join(REQUIRED_PACKAGES)}")
    sudo(["apt", "install", "-y"] + REQUIRED_PACKAGES)

    # Ensure TOR control config
    print("[*] Configuring TOR control port...")
    try:
        with open(TORRC, 'r') as f:
            torrc_content = f.read()
    except FileNotFoundError:
        torrc_content = ""

    modified = False
    if "ControlPort 9051" not in torrc_content:
        sudo(["tee", "-a", str(TORRC)], input=b"ControlPort 9051\n")
        modified = True
    if "CookieAuthentication 0" not in torrc_content:
        sudo(["tee", "-a", str(TORRC)], input=b"CookieAuthentication 0\n")
        modified = True

    if modified:
        print("[+] TOR config updated.")

    print("[+] Restarting TOR service...")
    sudo(["systemctl", "restart", "tor"])

    print("[✓] All dependencies installed. ExRecon is ready to go.")

if __name__ == "__main__":
    # Ensure we are on Linux
    if sys.platform != "linux":
        print("[!] This script is intended for Linux only.")
        sys.exit(1)
    main()
