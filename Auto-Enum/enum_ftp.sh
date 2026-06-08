#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — FTP (21)              ║
# ║   Usage: ./enum_ftp.sh <TARGET> [USER] [PASS]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-anonymous}"
PASS="${3:-anonymous}"

require_target "$TARGET"
banner "FTP (port 21)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "ftp")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — version + scripts FTP" "$OUTDIR/nmap_ftp.txt" \
    nmap -sV -p21 \
    --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor \
    -oN "$OUTDIR/nmap_ftp_raw.txt" \
    "$TARGET"

info "Banner grabbing"
cmd "nc -vn $TARGET 21"
echo -e "QUIT\r\n" | timeout 5 nc -vn "$TARGET" 21 2>&1 | tee "$OUTDIR/banner.txt"

# Détecter version
FTP_SERVER=$(grep -oP '(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP|Serv-U)\s*[\d.]+' "$OUTDIR/nmap_ftp.txt" 2>/dev/null | head -1)
[[ -n "$FTP_SERVER" ]] && finding "Serveur : $FTP_SERVER"

# ─── 2. ANONYMOUS LOGIN ──────────────────────────────────────
section "2. ANONYMOUS LOGIN"

info "Test connexion anonyme"
ANON_RESULT=$(echo -e "USER anonymous\r\nPASS anonymous\r\nLIST\r\nQUIT\r\n" | \
    timeout 10 nc -vn "$TARGET" 21 2>&1)
echo "$ANON_RESULT" | tee "$OUTDIR/anonymous_test.txt"

if echo "$ANON_RESULT" | grep -q "230"; then
    success "LOGIN ANONYME AUTORISÉ !"
    finding "Anonymous FTP = accès sans credentials"
    echo "anonymous:anonymous" > "$OUTDIR/valid_creds.txt"

    # Mirror complet en anonyme
    section "MIRROR — Téléchargement complet"
    if check_tool wget; then
        info "wget mirror du FTP anonyme"
        cmd "wget -m ftp://anonymous:anonymous@$TARGET -P $OUTDIR/mirror/"
        timeout 60 wget -m \
            --no-passive-ftp \
            ftp://anonymous:anonymous@"$TARGET" \
            -P "$OUTDIR/mirror/" 2>&1 | tail -20 | tee "$OUTDIR/wget_mirror.txt"

        if [[ -d "$OUTDIR/mirror" ]]; then
            FILE_COUNT=$(find "$OUTDIR/mirror" -type f | wc -l)
            success "$FILE_COUNT fichiers téléchargés"
            find "$OUTDIR/mirror" -type f | tee "$OUTDIR/mirror_filelist.txt"
        fi
    fi
else
    warn "Login anonyme refusé (code 530)"
fi

# ─── 3. TEST CREDENTIALS ────────────────────────────────────
section "3. TEST CREDENTIALS"

if [[ "$USER" != "anonymous" ]]; then
    info "Test credentials : $USER:$PASS"
    CRED_RESULT=$(echo -e "USER $USER\r\nPASS $PASS\r\nPWD\r\nLIST\r\nQUIT\r\n" | \
        timeout 10 nc -vn "$TARGET" 21 2>&1)
    echo "$CRED_RESULT" | tee "$OUTDIR/cred_test.txt"

    if echo "$CRED_RESULT" | grep -q "230"; then
        success "CONNEXION RÉUSSIE : $USER:$PASS"
        echo "$USER:$PASS" >> "$OUTDIR/valid_creds.txt"

        # Mirror avec creds
        if check_tool wget; then
            info "Mirror avec credentials"
            timeout 60 wget -m \
                --no-passive-ftp \
                "ftp://$USER:$PASS@$TARGET" \
                -P "$OUTDIR/mirror_auth/" 2>&1 | tail -10 | tee -a "$OUTDIR/wget_mirror.txt"
        fi
    else
        error "Connexion échouée"
    fi
fi

# ─── 4. BRUTE FORCE ─────────────────────────────────────────
section "4. BRUTE FORCE"

if check_tool hydra; then
    WORDLIST="/usr/share/wordlists/rockyou.txt"
    if [[ ! -f "$WORDLIST" ]]; then
        WORDLIST="/usr/share/wordlists/fasttrack.txt"
    fi

    if [[ -f "$WORDLIST" ]]; then
        warn "Brute force FTP (timeout 60s)"
        run_long "Hydra — FTP brute force" "$OUTDIR/hydra.txt" 60 \
            hydra -l "${USER:-admin}" -P "$WORDLIST" -t 4 -V "$TARGET" ftp
    fi
fi

# ─── 5. WRITE ACCESS TEST ───────────────────────────────────
section "5. TEST ACCÈS EN ÉCRITURE"

if check_tool ftp || check_tool curl; then
    info "Test upload fichier test"
    echo "test_write_$(date +%s)" > /tmp/enum_ftp_test.txt

    # Test write via curl
    WRITE_RESULT=$(timeout 10 curl -s -T /tmp/enum_ftp_test.txt \
        "ftp://$USER:$PASS@$TARGET/enum_ftp_test.txt" 2>&1)

    if [[ -z "$WRITE_RESULT" ]] || echo "$WRITE_RESULT" | grep -q "226\|200"; then
        success "ÉCRITURE AUTORISÉE !"
        finding "FTP write access → possible webshell upload"
        # Nettoyer
        timeout 5 curl -s "ftp://$USER:$PASS@$TARGET/" --quote "DELE enum_ftp_test.txt" 2>/dev/null
    else
        info "Écriture refusée ou non testable"
    fi
    rm -f /tmp/enum_ftp_test.txt
fi

# ─── 6. VULNÉRABILITÉS ──────────────────────────────────────
section "6. VULNÉRABILITÉS"

if check_tool searchsploit && [[ -n "$FTP_SERVER" ]]; then
    run "Searchsploit" "$OUTDIR/searchsploit.txt" \
        searchsploit "$FTP_SERVER" --colour
fi

# Résultats vuln nmap
echo -e "${GRAY}Résultats checks vulnérabilités nmap :${NC}"
grep -E "VULNERABLE|backdoor|CVE" "$OUTDIR/nmap_ftp.txt" 2>/dev/null | tee "$OUTDIR/vulns_found.txt"
if [[ -s "$OUTDIR/vulns_found.txt" ]]; then
    finding "Vulnérabilités détectées !"
else
    info "Aucune vulnérabilité évidente détectée par nmap"
fi

# ─── 7. ANALYSE DES FICHIERS RÉCUPÉRÉS ──────────────────────
section "7. ANALYSE FICHIERS INTÉRESSANTS"

if [[ -d "$OUTDIR/mirror" ]] || [[ -d "$OUTDIR/mirror_auth" ]]; then
    info "Recherche de fichiers sensibles dans les mirrors"
    MIRROR_BASE="$OUTDIR/mirror"
    [[ -d "$OUTDIR/mirror_auth" ]] && MIRROR_BASE="$OUTDIR/mirror_auth"

    # Patterns intéressants
    grep -rl "password\|passwd\|secret\|api_key\|token\|credentials" \
        "$MIRROR_BASE" 2>/dev/null | tee "$OUTDIR/interesting_files.txt"

    # Extensions sensibles
    find "$MIRROR_BASE" \( \
        -name "*.env" -o -name "*.bak" -o -name "*.config" \
        -o -name "*.conf" -o -name "id_rsa" -o -name "*.key" \
        -o -name "*.pem" -o -name "*.log" \
        \) 2>/dev/null | tee -a "$OUTDIR/interesting_files.txt"

    FILE_COUNT=$(wc -l < "$OUTDIR/interesting_files.txt" 2>/dev/null || echo 0)
    if [[ "$FILE_COUNT" -gt 0 ]]; then
        finding "$FILE_COUNT fichiers intéressants trouvés !"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
grep -h "open\|230\|Login" "$OUTDIR/nmap_ftp.txt" "$OUTDIR/anonymous_test.txt" 2>/dev/null | head -5
[[ -f "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials valides :"
    cat "$OUTDIR/valid_creds.txt"
}
