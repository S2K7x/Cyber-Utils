#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — DNS (53)              ║
# ║   Usage: ./enum_dns.sh <TARGET> [DOMAIN]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
DOMAIN="${2:-}"

require_target "$TARGET"
banner "DNS (port 53)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "dns")

# Auto-detect domain si non fourni
if [[ -z "$DOMAIN" ]]; then
    info "Tentative de détection automatique du domaine"
    _raw=$(dig +short -x "$TARGET" @"$TARGET" 2>/dev/null | grep -v "^;;" | sed 's/\.$//' | head -1)
    if [[ "$_raw" =~ ^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$ ]]; then
        DOMAIN="$_raw"
        finding "Domaine détecté : $DOMAIN"
    else
        warn "DNS ne répond pas ou pas de PTR record — passer le domaine en argument : $0 TARGET DOMAIN"
    fi
fi

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — scan DNS" "$OUTDIR/nmap_dns.txt" \
    nmap -n -p53 -sU -sT \
    --script dns-nsid,dns-random-txid,dns-random-srcport \
    -oN "$OUTDIR/nmap_dns_raw.txt" \
    "$TARGET"

info "Version BIND"
dig version.bind CHAOS TXT @"$TARGET" 2>&1 | tee "$OUTDIR/version_bind.txt"
BIND_VERSION=$(grep -oP '"BIND\s+\S+"' "$OUTDIR/version_bind.txt" 2>/dev/null | head -1)
[[ -n "$BIND_VERSION" ]] && finding "Version BIND : $BIND_VERSION"

info "Test récursion (ne doit pas résoudre google.com)"
RECURSION=$(dig google.com @"$TARGET" 2>&1)
echo "$RECURSION" | tee "$OUTDIR/recursion_test.txt"
if echo "$RECURSION" | grep -q "ANSWER SECTION"; then
    warn "RÉCURSION OUVERTE — résout des domaines externes (misconfiguration)"
    echo "RECURSIVE DNS" >> "$OUTDIR/findings.txt"
else
    info "Récursion restreinte (correct)"
fi

# ─── 2. RECORDS DE BASE ─────────────────────────────────────
section "2. RECORDS DNS"

if [[ -n "$DOMAIN" ]]; then
    for TYPE in A AAAA MX NS TXT SOA ANY; do
        info "Record $TYPE pour $DOMAIN"
        dig "$TYPE" "$DOMAIN" @"$TARGET" 2>&1 | tee "$OUTDIR/record_${TYPE,,}.txt"
    done

    info "Reverse lookup du target"
    dig -x "$TARGET" @"$TARGET" 2>&1 | tee "$OUTDIR/reverse_lookup.txt"

    # Extraire IPs intéressantes
    grep -E "^\S+\s+\d+\s+IN\s+(A|AAAA)" "$OUTDIR/record_a.txt" 2>/dev/null | \
        grep -v '^;' | tee "$OUTDIR/ips_found.txt"
fi

# ─── 3. ZONE TRANSFER ───────────────────────────────────────
section "3. ZONE TRANSFER (AXFR)"

if [[ -n "$DOMAIN" ]]; then
    info "Tentative AXFR sur $DOMAIN"
    AXFR_RESULT=$(dig axfr "$DOMAIN" @"$TARGET" 2>&1)
    echo "$AXFR_RESULT" | tee "$OUTDIR/zone_transfer.txt"

    if echo "$AXFR_RESULT" | grep -q "XFR size\|Transfer complete\|IN\s*A"; then
        success "ZONE TRANSFER AUTORISÉ !"
        finding "Zone transfer réussi — tous les records DNS récupérés"
        echo "AXFR_ALLOWED" >> "$OUTDIR/findings.txt"

        # Extraire tous les hosts et IPs
        grep "IN\s*A\b" "$OUTDIR/zone_transfer.txt" 2>/dev/null | \
            grep -v '^;' | tee "$OUTDIR/all_hosts_axfr.txt"

        HOST_COUNT=$(wc -l < "$OUTDIR/all_hosts_axfr.txt" 2>/dev/null || echo 0)
        success "$HOST_COUNT hosts DNS récupérés"
    else
        info "Zone transfer refusé (REFUSED ou NOTIMP)"
    fi
else
    info "Tentative AXFR sans domaine spécifié"
    dig axfr @"$TARGET" 2>&1 | tee "$OUTDIR/zone_transfer_nodom.txt"
fi

# ─── 4. SUBDOMAIN BRUTEFORCE ────────────────────────────────
section "4. SUBDOMAIN BRUTEFORCE"

if [[ -n "$DOMAIN" ]]; then
    WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ ! -f "$WORDLIST" ]]; then
        WORDLIST="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
    fi
    if [[ ! -f "$WORDLIST" ]]; then
        WORDLIST="/usr/share/wordlists/dirb/small.txt"
    fi

    if [[ -f "$WORDLIST" ]] && check_tool dnsenum; then
        info "dnsenum — bruteforce subdomains"
        run_long "dnsenum" "$OUTDIR/dnsenum.txt" 120 \
            dnsenum --dnsserver "$TARGET" --enum \
            -f "$WORDLIST" \
            --noreverse \
            "$DOMAIN"

        # Extraire les subdomains trouvés
        grep -oP '\S+\.'${DOMAIN} "$OUTDIR/dnsenum.txt" 2>/dev/null | \
            sort -u | tee "$OUTDIR/subdomains_found.txt"
        SUB_COUNT=$(wc -l < "$OUTDIR/subdomains_found.txt" 2>/dev/null || echo 0)
        [[ "$SUB_COUNT" -gt 0 ]] && success "$SUB_COUNT subdomains trouvés"

    elif check_tool dnsrecon; then
        info "dnsrecon — bruteforce subdomains"
        run_long "dnsrecon" "$OUTDIR/dnsrecon.txt" 120 \
            dnsrecon -d "$DOMAIN" -t brt \
            -D "$WORDLIST" \
            -n "$TARGET"
    else
        warn "dnsenum et dnsrecon non disponibles — bruteforce ignoré"
    fi
fi

# ─── 5. ENUM AD (SRV RECORDS) ───────────────────────────────
section "5. ACTIVE DIRECTORY (SRV RECORDS)"

if [[ -n "$DOMAIN" ]]; then
    > "$OUTDIR/ad_records.txt"
    for SRV in \
        "_ldap._tcp.dc._msdcs" \
        "_kerberos._tcp" \
        "_kerberos._udp" \
        "_gc._tcp" \
        "_ldap._tcp"; do
        RESULT=$(dig SRV "${SRV}.${DOMAIN}" @"$TARGET" 2>&1)
        if echo "$RESULT" | grep -q "ANSWER SECTION"; then
            echo "$RESULT" | tee -a "$OUTDIR/ad_records.txt"
            finding "SRV Record trouvé : $SRV"
        fi
    done

    DC_COUNT=$(grep -c "ANSWER SECTION" "$OUTDIR/ad_records.txt" 2>/dev/null) || DC_COUNT=0
    [[ "${DC_COUNT:-0}" -gt 0 ]] && success "Infrastructure AD détectée ($DC_COUNT services)"
fi

# ─── 6. NSEC WALKING ────────────────────────────────────────
section "6. DNSSEC / NSEC WALKING"

if [[ -n "$DOMAIN" ]]; then
    if check_tool ldns-walk; then
        run "NSEC Walking (ldns-walk)" "$OUTDIR/nsec_walk.txt" \
            ldns-walk @"$TARGET" "$DOMAIN"
    else
        run "NSEC enum (nmap)" "$OUTDIR/nsec_nmap.txt" \
            nmap -sSU -p53 \
            --script dns-nsec-enum \
            --script-args "dns-nsec-enum.domains=$DOMAIN" \
            "$TARGET"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$DOMAIN" ]] && info "Domaine : $DOMAIN"
[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}

[[ -s "$OUTDIR/subdomains_found.txt" ]] && {
    echo ""
    success "Subdomains trouvés :"
    cat "$OUTDIR/subdomains_found.txt"
}

[[ -s "$OUTDIR/all_hosts_axfr.txt" ]] && {
    echo ""
    success "Hosts via Zone Transfer :"
    head -20 "$OUTDIR/all_hosts_axfr.txt"
}

# Générer entrées /etc/hosts
if [[ -s "$OUTDIR/subdomains_found.txt" ]]; then
    echo ""
    info "Entrées /etc/hosts suggérées :"
    while read -r sub; do
        IP=$(dig +short "$sub" @"$TARGET" 2>/dev/null | head -1)
        [[ -n "$IP" ]] && echo "  $IP  $sub"
    done < "$OUTDIR/subdomains_found.txt" | tee "$OUTDIR/hosts_entries.txt"
fi
