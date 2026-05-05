# ExRecon Python

ExRecon is a defensive, user-space Tor/Nmap automation CLI for authorized OSINT and reconnaissance workflows.

## Safety model

- Runs Tor in user space; it does not install packages, edit system services, or require root.
- Uses TCP connect scans (`-sT`) for Tor-compatible scan automation.
- Blocks raw-socket scan selections while Tor is enabled.
- Uses subprocess argument lists rather than shell command strings.

## Usage

```bash
python -m exrecon -t example.com
python -m exrecon -t example.com -s 1,2,4
python -m exrecon -t example.com --no-tor
```

Custom Tor ports can be set when the defaults conflict with another local Tor process:

```bash
python -m exrecon -t example.com --socks-port 19050 --control-port 19051
```

Only scan systems you own or have explicit permission to test.
