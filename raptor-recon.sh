#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

banner() {
    clear
    cat << 'EOF'

██████╗  █████╗ ██████╗ ████████╗ ██████╗  ██████╗       ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗ ██╔══██╗      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝███████║██████╔╝   ██║   ██║   ██║ ██████╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║ ██╔══██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║██║  ██║██║        ██║   ╚██████╔╝ ██║  ██║      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝  ╚═╝  ╚═╝      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

                                      OSCP-STYLE NETWORK ENUM TOOL

EOF

    # subtle green status line under the banner
    echo -e "\e[32m[+] RaptorRecon initialized – hunting targets...\e[0m"
}


if [ $# -ne 1 ]; then
    echo "Usage: $0 <targets.txt>"
    exit 1
fi

banner

inputfile="$1"
base_dir="$(pwd)"

log() { echo -e "\n[+] $1"; }

# generic helper for MOST commands (not the rust/nmap ones)
run_and_log() {
    local cmd="$1"
    local out="$2"

    mkdir -p "$(dirname "$out")"

    {
        echo "# COMMAND RAN: $cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
    } > "$out"

    bash -lc "$cmd" >> "$out" 2>&1 || true
}

while read -r ip; do
    [ -z "$ip" ] && continue

    log "Target: $ip"

    ip_dir="$base_dir/$ip"
    port_dir="$ip_dir/port-enum"
    raw_dir="$port_dir/.raw"
    mkdir -p "$port_dir" "$raw_dir"

    ###########################################################
    # 1) RUSTSCAN (TCP)  — special case, to avoid double output
    ###########################################################
    raw_rust="$raw_dir/rust.txt"
    rust_cmd="rust -a \"$ip\" -- -A -v -oN \"$raw_rust\""

    # run rustscan once — it writes REAL output only to .raw/rust.txt
    log "Running RustScan on $ip..."
    bash -lc "$rust_cmd" >/dev/null 2>&1 || true

    # now build the visible rust.txt
    rust_out="$port_dir/rust.txt"
    {
        echo "# COMMAND RAN: $rust_cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
        cat "$raw_rust" 2>/dev/null || true
    } > "$rust_out"

    ###########################################################
    # 2) UDP NMAP (top 100) — same pattern
    ###########################################################
    raw_udp="$raw_dir/udp.txt"
    udp_cmd="nmap -Pn -n \"$ip\" -sU --top-ports 100 -v -oN \"$raw_udp\""

    log "Running UDP top-100 scan on $ip..."
    bash -lc "$udp_cmd" >/dev/null 2>&1 || true

    udp_out="$port_dir/udp.txt"
    {
        echo "# COMMAND RAN: $udp_cmd"
        echo "# RUN AT: $(date --iso-8601=seconds)"
        echo "--------------------------------------------------"
        cat "$raw_udp" 2>/dev/null || true
    } > "$udp_out"

    ###########################################################
    # 3) TCP / UDP port lists (comma-separated, no dups)
    ###########################################################
    tcp_ports_file="$port_dir/tcp_open_ports.txt"
    udp_ports_file="$port_dir/udp_open_ports.txt"

    # from rust raw
    run_and_log \
        "grep -Eo '^[0-9]+/tcp\\s+open' \"$raw_rust\" 2>/dev/null | grep -Eo '^[0-9]+' | sort -nu | paste -sd, - || true" \
        "$tcp_ports_file"

    # from udp raw
    run_and_log \
        "grep -Eo '^[0-9]+/udp\\s+open' \"$raw_udp\" 2>/dev/null | grep -Eo '^[0-9]+' | sort -nu | paste -sd, - || true" \
        "$udp_ports_file"

    ###########################################################
    # 4) Parse services (for HTTP/SMB/RPC/etc.)
    ###########################################################
    # format like "80/tcp|http"
    services=$(grep -Eo '^[0-9]+/tcp\s+open\s+\S+' "$raw_rust" 2>/dev/null | awk '{print $1 "|" $3}')
    # full text used for port-only checks
    rust_full="$(cat "$raw_rust" 2>/dev/null || true)"

    ###########################################################
    # 5) HTTP ENUM — ONLY if service name says http/https/ssl-http
    ###########################################################
    echo "$services" | grep -Ei '\|http|\|https|\|ssl/http' >/dev/null && \
    echo "$services" | grep -Ei '\|http|\|https|\|ssl/http' | while IFS='|' read -r port service; do
        portnum="${port%/*}"

        if [[ "$portnum" == "5985" || "$portnum" == "47001" ]]; then
                log "Skipping HTTP enumeration on WinRM port $portnum ($ip:$portnum)"
                continue
        fi

        http_dir="$ip_dir/http/$portnum"
        mkdir -p "$http_dir/dirsearch" "$http_dir/gobuster" "$http_dir/scanners" "$http_dir/.raw"

        log "HTTP service on $ip:$portnum — enumerating"

        # WhatWeb
        run_and_log "whatweb \"http://$ip:$portnum\"" "$http_dir/scanners/whatweb.txt"

        # CMSeeK
        run_and_log "cmseek -u \"http://$ip:$portnum\" --random-agent --batch" "$http_dir/scanners/cmseek.txt"

        # --- Dirsearch: write real results to .raw via -o, keep console quiet/no-color ---
        # default
        ds_cmd_1="dirsearch -u \"http://$ip:$portnum\" -t 100 -r -x 404,405,403,503,400 -R 1 --no-color -q -o \"$http_dir/.raw/dirsearch-default.txt\""
        bash -lc "$ds_cmd_1" >/dev/null 2>&1 || true
        {
            echo "# COMMAND RAN: $ds_cmd_1"
            echo "# RUN AT: $(date --iso-8601=seconds)"
            echo "--------------------------------------------------"
            cat "$http_dir/.raw/dirsearch-default.txt" 2>/dev/null || true
        } > "$http_dir/dirsearch/output-default.txt"

        # common
        ds_cmd_2="dirsearch -u \"http://$ip:$portnum\" -t 100 -r -x 404,405,403,503,400 -R 1 --no-color -q \
                  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
                  -o \"$http_dir/.raw/dirsearch-common.txt\""
        bash -lc "$ds_cmd_2" >/dev/null 2>&1 || true
        {
            echo "# COMMAND RAN: $ds_cmd_2"
            echo "# RUN AT: $(date --iso-8601=seconds)"
            echo "--------------------------------------------------"
            cat "$http_dir/.raw/dirsearch-common.txt" 2>/dev/null || true
        } > "$http_dir/dirsearch/output-common.txt"

        # dirbuster
        ds_cmd_3="dirsearch -u \"http://$ip:$portnum\" -t 100 -r -x 404,405,403,503,400 -R 1 --no-color -q \
                  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
                  -o \"$http_dir/.raw/dirsearch-dirbuster.txt\""
        bash -lc "$ds_cmd_3" >/dev/null 2>&1 || true
        {
            echo "# COMMAND RAN: $ds_cmd_3"
            echo "# RUN AT: $(date --iso-8601=seconds)"
            echo "--------------------------------------------------"
            cat "$http_dir/.raw/dirsearch-dirbuster.txt" 2>/dev/null || true
        } > "$http_dir/dirsearch/output-dirbuster.txt"

        # Gobuster (keep your behavior; we still build visible from .raw)
        run_and_log "gobuster dir -u \"http://$ip:$portnum/\" -w /usr/share/wordlists/dirb/big.txt -t 100 -r -o \"$http_dir/.raw/gobuster.txt\"" \
            "$http_dir/gobuster/gobuster.txt"

    done

    ###########################################################
    # 6) SMB ENUM — service OR ports 445/139
    ###########################################################
    if echo "$services" | grep -E '\|smb|\|microsoft-ds|\|netbios' >/dev/null \
       || echo "$rust_full" | grep -E '^445/tcp\s+open|^139/tcp\s+open' >/dev/null; then
        smb_dir="$ip_dir/smb"
        mkdir -p "$smb_dir"

        log "SMB service on $ip — enumerating"
        run_and_log "enum4linux-ng \"$ip\"" "$smb_dir/enum4linux-ng.txt"
        run_and_log "echo \"exit\" | smbclient -L \"//$ip/\" -N" "$smb_dir/smbclient.txt"
        run_and_log "echo \"exit\" | smbclient -L \"//$ip/\" -U Guest%\"\"" "$smb_dir/smbclient-guest.txt"
        run_and_log "smbmap -H \"$ip\"" "$smb_dir/smbmap.txt"
    fi

    ###########################################################
    # 7) FTP ENUM — service OR 21/tcp
    ###########################################################
    if echo "$services" | grep -E '\|ftp' >/dev/null \
       || echo "$rust_full" | grep -E '^21/tcp\s+open' >/dev/null; then
        ftp_dir="$ip_dir/ftp"
        mkdir -p "$ftp_dir"
        log "FTP detected — testing anonymous login"
        run_and_log "printf \"anonymous\nanonymous\nquit\n\" | ftp -inv \"$ip\"" "$ftp_dir/ftp-anon.txt"
    fi

    ###########################################################
    # 8) RPC ENUM — service OR 135/tcp
    ###########################################################
    if echo "$services" | grep -E '\|rpc|\|msrpc|\|rpcbind|\|ncacn_http' >/dev/null \
       || echo "$rust_full" | grep -E '^135/tcp\s+open' >/dev/null; then
        rpc_dir="$ip_dir/rpc"
        mkdir -p "$rpc_dir"

        if echo "$rust_full" | grep -qi "windows"; then
            log "Windows RPC — enumdomusers"
            run_and_log "rpcclient -U '' -N \"$ip\" -c enumdomusers" "$rpc_dir/rpc-windows.txt"
            # extract list to a second file (same as your old script) (new command)
            run_and_log "grep -oP '(?<=user:\\[)[^\\]]+' \"$rpc_dir/rpc-windows.txt\" | sort -u" "$rpc_dir/rpc-users-list.txt"
        else
            log "Linux RPC — rpcinfo"
            run_and_log "rpcinfo -p \"$ip\"" "$rpc_dir/rpc-linux.txt"
        fi
    fi

    ###########################################################
    # 9) IDENT ENUM — 113/tcp
    ###########################################################
    if echo "$rust_full" | grep -E '^113/tcp\s+open' >/dev/null; then
        ident_dir="$ip_dir/ident"
        mkdir -p "$ident_dir"
        log "IDENT service found — running ident-user-enum"
        run_and_log "ident-user-enum \"$ip\" 113" "$ident_dir/ident.txt"
    fi

    ###########################################################
    # 10) NTP ENUM — from UDP scan
    ###########################################################
    if grep -E '^123/udp\s+open' "$raw_udp" >/dev/null 2>&1; then
        ntp_dir="$ip_dir/ntp"
        mkdir -p "$ntp_dir"
        log "NTP UDP port 123 open — running ntpdate"
        run_and_log "ntpdate \"$ip\"" "$ntp_dir/ntp.txt"
    fi

    log "✅ Finished enumeration for $ip"

done < "$inputfile"

echo -e "\n🎉 All targets processed. Results saved in: $(pwd)"
