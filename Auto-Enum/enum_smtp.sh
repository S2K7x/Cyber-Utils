#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — SMTP (25/465/587)     ║
# ║   Usage: ./enum_smtp.sh <TARGET> [DOMAIN] [USER] [PASS]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
DOMAIN="${2:-}"
USER="${3:-}"
PASS="${4:-}"

require_target "$TARGET"
banner "SMTP (ports 25/465/587)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "smtp")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — scan SMTP" "$OUTDIR/nmap_smtp.txt" \
    nmap -p25,465,587 -sV \
    --script smtp-commands,smtp-open-relay,smtp-ntlm-info \
    -oN "$OUTDIR/nmap_smtp_raw.txt" \
    "$TARGET"

info "Banner grabbing port 25"
BANNER=$(echo -e "EHLO test\r\nQUIT\r\n" | timeout 8 nc -vn "$TARGET" 25 2>&1)
echo "$BANNER" | tee "$OUTDIR/banner_25.txt"

# Auto-detect domaine depuis la bannière
if [[ -z "$DOMAIN" ]]; then
    DOMAIN=$(echo "$BANNER" | grep -oP '(?<=220 )\S+' | head -1 | sed 's/\..*//')
    FULL_DOMAIN=$(echo "$BANNER" | grep -oP '(?<=220 )\S+' | head -1)
    [[ -n "$FULL_DOMAIN" ]] && {
        finding "Domaine détecté : $FULL_DOMAIN"
        DOMAIN="$FULL_DOMAIN"
    }
fi

# Extraire version serveur
SMTP_SERVER=$(grep -oP '(Postfix|Sendmail|Exim|Exchange|OpenSMTPD|hMailServer)[^\n]*' \
    "$OUTDIR/nmap_smtp.txt" "$OUTDIR/banner_25.txt" 2>/dev/null | head -1)
[[ -n "$SMTP_SERVER" ]] && finding "Serveur : $SMTP_SERVER"

# STARTTLS
STARTTLS=$(grep -i "STARTTLS" "$OUTDIR/nmap_smtp.txt" "$OUTDIR/banner_25.txt" 2>/dev/null | head -1)
[[ -n "$STARTTLS" ]] && info "STARTTLS supporté"

# ─── 2. OPEN RELAY ──────────────────────────────────────────
section "2. OPEN RELAY CHECK"

info "Vérification open relay via nmap"
RELAY_RESULT=$(grep -i "open relay\|relay access" "$OUTDIR/nmap_smtp.txt" 2>/dev/null)
if echo "$RELAY_RESULT" | grep -qi "open relay\|open for relaying"; then
    success "OPEN RELAY DÉTECTÉ !"
    finding "SMTP Open Relay → envoi de mails au nom d'autres domaines"
    echo "OPEN_RELAY" >> "$OUTDIR/findings.txt"
else
    info "Pas d'open relay détecté par nmap (vérifier manuellement)"
fi

# Test manuel
info "Test open relay manuel"
RELAY_TEST=$(echo -e "HELO test.com\r\nMAIL FROM: fake@external.com\r\nRCPT TO: test@victim.com\r\nQUIT\r\n" | \
    timeout 8 nc -vn "$TARGET" 25 2>&1)
echo "$RELAY_TEST" | tee "$OUTDIR/relay_test.txt"
if echo "$RELAY_TEST" | grep -q "^250" | grep -v "sender\|from"; then
    warn "Possible open relay — vérifier manuellement"
fi

# ─── 3. ENUM UTILISATEURS ───────────────────────────────────
section "3. ÉNUMÉRATION UTILISATEURS"

USERLIST=""
for wl in \
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" \
    "/usr/share/seclists/Usernames/Names/names.txt" \
    "/usr/share/wordlists/metasploit/unix_users.txt"; do
    [[ -f "$wl" ]] && USERLIST="$wl" && break
done

if [[ -z "$USERLIST" ]]; then
    # Créer liste minimale
    cat > /tmp/enum_smtp_users.txt << 'EOF'
root
admin
administrator
mail
postmaster
info
support
user
test
www
ftp
nobody
daemon
manager
webmaster
EOF
    USERLIST="/tmp/enum_smtp_users.txt"
    warn "Wordlist seclists non trouvée — utilisation liste minimale"
fi

if check_tool smtp-user-enum; then
    # VRFY
    info "VRFY method"
    run_long "smtp-user-enum VRFY" "$OUTDIR/enum_vrfy.txt" 60 \
        smtp-user-enum -M VRFY -U "$USERLIST" -t "$TARGET" -p 25

    # RCPT (plus fiable)
    if [[ -n "$DOMAIN" ]]; then
        info "RCPT method (plus fiable)"
        run_long "smtp-user-enum RCPT" "$OUTDIR/enum_rcpt.txt" 60 \
            smtp-user-enum -M RCPT -U "$USERLIST" -D "$DOMAIN" -t "$TARGET" -p 25
    fi

    # Extraire users valides
    grep "exists\|250\|\[+\]" "$OUTDIR/enum_vrfy.txt" "$OUTDIR/enum_rcpt.txt" 2>/dev/null | \
        grep -oP '\b\w+@?\w*\b' | sort -u | tee "$OUTDIR/users_found.txt"

    USER_COUNT=$(wc -l < "$OUTDIR/users_found.txt" 2>/dev/null || echo 0)
    [[ "$USER_COUNT" -gt 0 ]] && {
        success "$USER_COUNT utilisateurs valides trouvés !"
        cat "$OUTDIR/users_found.txt"
    }
else
    warn "smtp-user-enum non disponible — enum manuelle"
    # Enum manuelle VRFY
    > "$OUTDIR/users_found.txt"
    while IFS= read -r u; do
        RESULT=$(echo -e "HELO test\r\nVRFY $u\r\nQUIT\r\n" | \
            timeout 5 nc -vn "$TARGET" 25 2>&1)
        if echo "$RESULT" | grep -q "^252\|^250"; then
            success "User valide : $u"
            echo "$u" >> "$OUTDIR/users_found.txt"
        fi
    done < "$USERLIST"
fi

# ─── 4. AUTHENTIFICATION ────────────────────────────────────
section "4. AUTHENTIFICATION"

if [[ -n "$USER" && -n "$PASS" ]]; then
    info "Test credentials : $USER:$PASS"

    NXC=$(command -v nxc || command -v crackmapexec)
    if [[ -n "$NXC" ]]; then
        $NXC smtp "$TARGET" -u "$USER" -p "$PASS" 2>&1 | tee "$OUTDIR/auth_test.txt"
        if grep -q "\[+\]" "$OUTDIR/auth_test.txt"; then
            success "CREDENTIALS VALIDES !"
            echo "$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
        fi
    fi

    # Brute force si credentials pas valides
    if check_tool hydra; then
        warn "Brute force SMTP (timeout 60s)"
        run_long "Hydra — SMTP brute force" "$OUTDIR/hydra.txt" 60 \
            hydra -l "$USER" -P /usr/share/wordlists/rockyou.txt \
            smtp://"$TARGET"
    fi
else
    if [[ -s "$OUTDIR/users_found.txt" ]] && check_tool hydra; then
        info "Brute force des users trouvés avec password courants"
        PASS_LIST="/tmp/smtp_common_pass.txt"
        echo -e "password\n123456\nadmin\nletmein\nPassword1\n${DOMAIN%%.*}@123\nWelcome1" > "$PASS_LIST"

        hydra -L "$OUTDIR/users_found.txt" -P "$PASS_LIST" \
            -t 4 smtp://"$TARGET" 2>&1 | tee "$OUTDIR/hydra_quick.txt"

        grep "\[25\]\|login:\|password:" "$OUTDIR/hydra_quick.txt" 2>/dev/null | \
            tee -a "$OUTDIR/valid_creds.txt"
    fi
fi

# ─── 5. VULNÉRABILITÉS ──────────────────────────────────────
section "5. VULNÉRABILITÉS"

if [[ -n "$SMTP_SERVER" ]] && check_tool searchsploit; then
    run "Searchsploit" "$OUTDIR/searchsploit.txt" \
        searchsploit "$SMTP_SERVER" --colour
fi

# Check versions vulnérables connues
if echo "$SMTP_SERVER" | grep -qi "OpenSMTPD"; then
    warn "OpenSMTPD détecté — vérifier CVE-2020-7247 (RCE pré-auth)"
    echo "CHECK: OpenSMTPD CVE-2020-7247" >> "$OUTDIR/findings.txt"
fi
if echo "$SMTP_SERVER" | grep -qi "Exim"; then
    EXIM_VER=$(echo "$SMTP_SERVER" | grep -oP '[\d.]+' | head -1)
    warn "Exim détecté (v$EXIM_VER) — vérifier CVE-2019-10149 (< 4.92)"
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$SMTP_SERVER" ]] && info "Serveur : $SMTP_SERVER"
[[ -n "$DOMAIN" ]] && info "Domaine : $DOMAIN"

[[ -s "$OUTDIR/users_found.txt" ]] && {
    echo ""
    success "Users SMTP valides :"
    cat "$OUTDIR/users_found.txt"
}

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
