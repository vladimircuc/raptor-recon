

# RaptorRecon

`raptor-recon.sh` is a Bash script that automates **OSCP-style enumeration** for one or more targets.
It wraps RustScan, Nmap, HTTP/S enumeration tools, SMB/FTP/RPC checks, and a few service-specific
helpers, and saves everything into a clean per-host folder structure with timestamps and full commands.

> **Use only on systems you own or have explicit permission to test.**

## Features

- Reads a list of targets from a text file (one IP per line).
- Runs **RustScan** (TCP) and **Nmap** (top 100 UDP ports).
- Generates comma-separated lists of open TCP/UDP ports.
- Automatically detects services from RustScan output and launches:
  - **HTTP** enum:
    - `whatweb`
    - `cmseek`
    - `dirsearch` (3 wordlists: default, `common.txt`, and `directory-list-2.3-medium.txt`)
    - `gobuster dir`
  - **SMB** enum (service or ports 445/139):
    - `enum4linux-ng`
    - `smbclient` (with and without Guest)
    - `smbmap`
  - **FTP** enum (service or port 21):
    - Anonymous login test via `ftp`
  - **RPC** enum (service or port 135):
    - Windows: `rpcclient enumdomusers` + extracted user list
    - Linux: `rpcinfo -p`
  - **IDENT** enum (port 113):  
    - `ident-user-enum`
  - **NTP** enum (UDP 123):  
    - `ntpdate`
- Every command is logged with:
  - the **exact command** run
  - a **timestamp**
  - **stdout + stderr** redirected into a file
- Safe-ish behavior: individual tool failures don’t kill the whole run.

## Requirements

Tested primarily on **Kali Linux**. You’ll need:

- `bash`
- `rustscan` (aliased/linked as `rust` in the script – adjust if needed)
- `nmap`
- `whatweb`
- `cmseek`
- `dirsearch`
- `gobuster`
- `enum4linux-ng`
- `smbclient`
- `smbmap`
- `rpcclient`
- `rpcinfo`
- `ident-user-enum`
- `ntpdate`
- `ftp`
- Wordlists:
  - `/usr/share/seclists/Discovery/Web-Content/common.txt`
  - `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
  - `/usr/share/wordlists/dirb/big.txt`

Adjust the wordlist paths in the script if your distro stores them differently.

## Usage

```bash
chmod +x raptor-recon.sh

# targets.txt: one IP/host per line
cat targets.txt
10.10.11.123
10.10.11.124

# run the script from the directory where you want results saved
./raptor-recon.sh targets.txt
```

For each target X.X.X.X, the script creates:

```bash
X.X.X.X/
├── port-enum/
│   ├── rust.txt
│   ├── udp.txt
│   ├── tcp_open_ports.txt
│   ├── udp_open_ports.txt
│   └── .raw/
│       ├── rust.txt
│       └── udp.txt
├── http/
│   └── <port>/
│       ├── dirsearch/
│       │   ├── output-default.txt
│       │   ├── output-common.txt
│       │   └── output-dirbuster.txt
│       ├── gobuster/
│       │   └── gobuster.txt
│       ├── scanners/
│       │   ├── whatweb.txt
│       │   └── cmseek.txt
│       └── .raw/
│           ├── dirsearch-default.txt
│           ├── dirsearch-common.txt
│           └── dirsearch-dirbuster.txt
├── smb/
│   ├── enum4linux-ng.txt
│   ├── smbclient.txt
│   ├── smbclient-guest.txt
│   └── smbmap.txt
├── ftp/
│   └── ftp-anon.txt
├── rpc/
│   ├── rpc-windows.txt         (Windows targets)
│   ├── rpc-users-list.txt      (extracted users, Windows)
│   └── rpc-linux.txt           (Linux targets)
├── ident/
│   └── ident.txt
└── ntp/
    └── ntp.txt
```

## How Output Files Are Structured

Every generated `.txt` file starts with metadata at the top:

COMMAND RAN: <exact command executed>    
RUN AT: <ISO-8601 timestamp>   

This makes it easy to replay, debug, or modify the commands later.

## Notes

- The script uses `set -euo pipefail`, but most enumeration commands are wrapped in `|| true`,
  preventing a single tool failure from stopping the entire run.
- RustScan is invoked via the `rust` command. If your system uses `rustscan` instead,
  update the corresponding line in the script.
- HTTP enumeration automatically skips WinRM ports (`5985`, `47001`) to avoid irrelevant scans.

## Disclaimer

This tool is intended **only for legal penetration testing and ethical security research**.  
Do **NOT** use it on systems without explicit, written authorization.  
You are solely responsible for how you use this script.
