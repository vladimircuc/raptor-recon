# oscp-auto-enum

`oscp-auto-enum.sh` is a Bash script that automates **OSCP-style enumeration** for one or more targets.
It wraps RustScan, Nmap, HTTP/S enumeration tools, SMB/FTP/RPC checks, and a few service-specific
helpers, and saves everything into a clean per-host folder structure with timestamps and full commands.

> **Use only on systems you own or have explicit permission to test.**

---

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

---

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

---

## Usage

```bash
chmod +x oscp-auto-enum.sh

# targets.txt: one IP/host per line
cat targets.txt
10.10.11.123
10.10.11.124

# run the script from the directory where you want results saved
./oscp-auto-enum.sh targets.txt
```

ceva

