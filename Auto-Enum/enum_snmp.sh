#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — SNMP (UDP 161)        ║
# ║   Usage: ./enum_snmp.sh <TARGET> [COMMUNITY]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
COMMUNITY="${2:-}"

require_target "$TARGET"
banner "SNMP (UDP 161/162)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "snmp")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap UDP SNMP" "$OUTDIR/nmap_snmp.txt" \
    sudo nmap -sU -p161 -sV \
    --script snmp-info,snmp-sysdescr \
    -oN "$OUTDIR/nmap_snmp_raw.txt" \
    "$TARGET"

# ─── 2. COMMUNITY STRINGS ───────────────────────────────────
section "2. COMMUNITY STRINGS BRUTEFORCE"

COMM_LIST=""
for wl in \
    "/opt/useful/seclists/Discovery/SNMP/snmp.txt" \
    "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt" \
    "/usr/share/seclists/Discovery/SNMP/snmp.txt"; do
    [[ -f "$wl" ]] && COMM_LIST="$wl" && break
done

if [[ -z "$COMM_LIST" ]]; then
    cat > /tmp/snmp_communities.txt << 'EOF'
public
private
community
manager
secret
snmp
admin
default
cisco
router
switch
internal
monitor
supervisor
EOF
    COMM_LIST="/tmp/snmp_communities.txt"
    warn "Wordlist seclists non trouvée — utilisation liste minimale"
fi

if [[ -n "$COMMUNITY" ]]; then
    info "Community string fournie : $COMMUNITY"
    echo "$COMMUNITY" >> "$OUTDIR/valid_communities.txt"
else
    if check_tool onesixtyone; then
        info "onesixtyone — bruteforce community strings"
        run_long "onesixtyone" "$OUTDIR/onesixtyone.txt" 60 \
            onesixtyone -c "$COMM_LIST" "$TARGET"

        # Extraire les valides
        grep -v "^$\|Scanning\|Trying" "$OUTDIR/onesixtyone.txt" 2>/dev/null | \
            grep -oP '(?<=\[)\w+(?=\])' | sort -u | tee "$OUTDIR/valid_communities.txt"

        COMM_COUNT=$(wc -l < "$OUTDIR/valid_communities.txt" 2>/dev/null || echo 0)
        if [[ "$COMM_COUNT" -gt 0 ]]; then
            success "$COMM_COUNT community string(s) trouvée(s) !"
            cat "$OUTDIR/valid_communities.txt"
        fi
    else
        # Test manuel des strings communes
        info "Test manuel community strings (onesixtyone non disponible)"
        > "$OUTDIR/valid_communities.txt"
        while IFS= read -r comm; do
            RESULT=$(timeout 3 snmpwalk -v2c -c "$comm" "$TARGET" 1.3.6.1.2.1.1.1.0 2>&1)
            if echo "$RESULT" | grep -v "Timeout\|No Response\|Error" | grep -q "."; then
                success "Community string valide : $comm"
                echo "$comm" >> "$OUTDIR/valid_communities.txt"
            fi
        done < "$COMM_LIST"
    fi
fi

# ─── 3. SNMPWALK — MIB WALK ─────────────────────────────────
if [[ -s "$OUTDIR/valid_communities.txt" ]] || [[ -n "$COMMUNITY" ]]; then
    [[ -n "$COMMUNITY" ]] || COMMUNITY=$(head -1 "$OUTDIR/valid_communities.txt")

    section "3. MIB WALK (community: $COMMUNITY)"

    if check_tool snmpwalk; then
        # Walk complet
        run_long "snmpwalk — walk complet" "$OUTDIR/snmpwalk_full.txt" 120 \
            snmpwalk -v2c -c "$COMMUNITY" "$TARGET"

        # OIDs spécifiques ciblés
        declare -A OIDS=(
            ["system_info"]="1.3.6.1.2.1.1"
            ["running_processes"]="1.3.6.1.2.1.25.4.2"
            ["installed_software"]="1.3.6.1.2.1.25.6.3"
            ["windows_users"]="1.3.6.1.4.1.77.1.2.25"
            ["tcp_connections"]="1.3.6.1.2.1.6.13"
            ["network_interfaces"]="1.3.6.1.2.1.2.2"
            ["ip_addresses"]="1.3.6.1.2.1.4.34"
            ["storage"]="1.3.6.1.2.1.25.2"
        )

        section "OIDs CIBLÉS"
        for label in "${!OIDS[@]}"; do
            oid="${OIDS[$label]}"
            info "OID: $label ($oid)"
            timeout 15 snmpwalk -v2c -c "$COMMUNITY" "$TARGET" "$oid" 2>&1 | \
                tee "$OUTDIR/oid_${label}.txt"
            echo ""
        done

        # Extraire hostname
        HOSTNAME=$(snmpwalk -v2c -c "$COMMUNITY" "$TARGET" 1.3.6.1.2.1.1.5.0 2>&1 | \
            grep -oP '"[^"]+"' | tr -d '"' | head -1)
        [[ -n "$HOSTNAME" ]] && finding "Hostname SNMP : $HOSTNAME"

        # Extraire OS
        OS=$(snmpwalk -v2c -c "$COMMUNITY" "$TARGET" 1.3.6.1.2.1.1.1.0 2>&1 | \
            grep -oP '"[^"]+"' | tr -d '"' | head -1)
        [[ -n "$OS" ]] && finding "Système : $OS"

        # Chercher passwords dans les processus
        section "RECHERCHE PASSWORDS DANS LES PROCESSUS"
        grep -iE "pass|pwd|password|secret|key|credential|token" \
            "$OUTDIR/oid_running_processes.txt" 2>/dev/null | tee "$OUTDIR/process_creds.txt"
        if [[ -s "$OUTDIR/process_creds.txt" ]]; then
            success "Passwords potentiels dans les arguments de processus !"
            cat "$OUTDIR/process_creds.txt"
        fi

        # Chercher users Windows
        section "UTILISATEURS WINDOWS (si Windows)"
        grep -v "^$" "$OUTDIR/oid_windows_users.txt" 2>/dev/null | \
            grep -oP '"[^"]+"' | tr -d '"' | sort -u | tee "$OUTDIR/windows_users.txt"
        USER_COUNT=$(wc -l < "$OUTDIR/windows_users.txt" 2>/dev/null || echo 0)
        [[ "$USER_COUNT" -gt 0 ]] && success "$USER_COUNT users Windows trouvés"

    else
        warn "snmpwalk non disponible — installer avec: apt install snmp"
    fi

    # braa pour enum rapide multi-OIDs
    if check_tool braa; then
        info "braa — enum rapide"
        run_long "braa" "$OUTDIR/braa.txt" 30 \
            braa "${COMMUNITY}@${TARGET}:.1.3.6.*"
    fi

else
    warn "Aucune community string valide trouvée — SNMP inaccessible"
fi

# ─── 4. SNMPV3 CHECK ────────────────────────────────────────
section "4. SNMPv3 ENUM"

run "SNMPv3 — enum users" "$OUTDIR/snmpv3.txt" \
    nmap -sU -p161 --script snmp-brute "$TARGET"

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -s "$OUTDIR/valid_communities.txt" ]] && {
    success "Community strings valides :"
    cat "$OUTDIR/valid_communities.txt"
}
[[ -n "$HOSTNAME" ]] && finding "Hostname : $HOSTNAME"
[[ -n "$OS" ]] && finding "OS : $OS"
[[ -s "$OUTDIR/windows_users.txt" ]] && {
    echo ""
    success "Users Windows :"
    cat "$OUTDIR/windows_users.txt"
}
[[ -s "$OUTDIR/process_creds.txt" ]] && {
    echo ""
    warn "CREDENTIALS POTENTIELS DANS LES PROCESSUS :"
    cat "$OUTDIR/process_creds.txt"
}
