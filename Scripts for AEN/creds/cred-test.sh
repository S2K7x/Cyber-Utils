#!/bin/bash
# cred-test.sh — Tester 1 credential sur TOUS les services en parallèle
# Usage: ./cred-test.sh <user> <pass> <IP> [domain]
# Exemple: ./cred-test.sh srvadm 'ILFreightnixadm!' 10.129.20.33
#          ./cred-test.sh john 'Welcome1' 10.129.20.3 INLANEFREIGHT.LOCAL
#
# Teste simultanément : SSH, SMB, WinRM, FTP, RDP, MSSQL, LDAP, MySQL
# Affiche immédiatement les succès en rouge (urgent → 03_LOOT.md)

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 3 ]]; then
    echo -e "${R}Usage: $0 <user> <pass> <IP> [domain]${NC}"
    echo ""
    echo "  Ex: $0 srvadm 'ILFreightnixadm!' 10.129.20.33"
    echo "  Ex: $0 john 'Welcome1' 10.129.20.3 INLANEFREIGHT.LOCAL"
    exit 1
fi

USER="$1"
PASS="$2"
IP="$3"
DOMAIN="${4:-WORKGROUP}"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M")

echo -e "${B}${C}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   cred-test.sh"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   User   : $USER"
echo "║   Pass   : $PASS"
echo "║   IP     : $IP"
echo "║   Domain : $DOMAIN"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

RESULTS=()
declare -A STATUS

# Fonction pour tester un service
test_service() {
    local name="$1"
    local result
    shift

    printf "  %-10s " "$name"

    if timeout 10 "$@" &>/dev/null; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["$name"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["$name"]="FAIL"
    fi
}

# ── SSH
printf "  %-10s " "SSH"
if command -v ssh &>/dev/null; then
    ssh_out=$(timeout 10 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PasswordAuthentication=yes -o BatchMode=no \
        "$USER@$IP" "whoami" 2>&1 <<< "$PASS" 2>/dev/null || true)
    if echo "$ssh_out" | grep -qv "Permission denied\|refused\|timeout"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["SSH"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["SSH"]="FAIL"
    fi
else
    echo -e "${Y}[~ N/A]${NC}"
fi

# ── SMB (avec et sans domaine)
printf "  %-10s " "SMB"
if command -v nxc &>/dev/null; then
    if nxc smb "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep -q "Pwn3d\|\[+\]"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["SMB"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["SMB"]="FAIL"
    fi
elif command -v crackmapexec &>/dev/null; then
    if crackmapexec smb "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep -q "Pwn3d\|\[+\]"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["SMB"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["SMB"]="FAIL"
    fi
else
    # Fallback smbclient
    if smbclient -U "$DOMAIN\\$USER%$PASS" -L "//$IP" &>/dev/null; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["SMB"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["SMB"]="FAIL"
    fi
fi

# ── WinRM
printf "  %-10s " "WinRM"
if command -v nxc &>/dev/null; then
    if nxc winrm "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep -q "\[+\]"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["WinRM"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["WinRM"]="FAIL"
    fi
else
    echo -e "${Y}[~ nxc N/A]${NC}"
fi

# ── FTP
printf "  %-10s " "FTP"
if timeout 8 ftp -n "$IP" 2>/dev/null <<EOF | grep -q "230"
user $USER $PASS
quit
EOF
then
    echo -e "${G}[✓ SUCCESS]${NC}"
    STATUS["FTP"]="SUCCESS"
else
    echo -e "${R}[✗ FAIL]${NC}"
    STATUS["FTP"]="FAIL"
fi

# ── LDAP
printf "  %-10s " "LDAP"
if command -v ldapsearch &>/dev/null; then
    BASE_DN=$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++) printf "DC="$i (i==NF?"":",")}')
    if timeout 8 ldapsearch -x -H "ldap://$IP" \
        -D "$USER@$DOMAIN" -w "$PASS" \
        -b "$BASE_DN" "(objectClass=*)" dn 2>/dev/null | grep -q "dn:"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["LDAP"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["LDAP"]="FAIL"
    fi
else
    echo -e "${Y}[~ N/A]${NC}"
fi

# ── MSSQL
printf "  %-10s " "MSSQL"
if command -v nxc &>/dev/null; then
    if nxc mssql "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep -q "\[+\]"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["MSSQL"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["MSSQL"]="FAIL"
    fi
else
    echo -e "${Y}[~ nxc N/A]${NC}"
fi

# ── MySQL
printf "  %-10s " "MySQL"
if command -v mysql &>/dev/null; then
    if timeout 8 mysql -h "$IP" -u "$USER" -p"$PASS" -e "SELECT 1" &>/dev/null; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["MySQL"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["MySQL"]="FAIL"
    fi
else
    echo -e "${Y}[~ N/A]${NC}"
fi

# ── RDP check (seulement vérifier si le port est ouvert + cred valide via nxc)
printf "  %-10s " "RDP"
if command -v nxc &>/dev/null; then
    if nxc rdp "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep -q "\[+\]"; then
        echo -e "${G}[✓ SUCCESS]${NC}"
        STATUS["RDP"]="SUCCESS"
    else
        echo -e "${R}[✗ FAIL]${NC}"
        STATUS["RDP"]="FAIL"
    fi
else
    echo -e "${Y}[~ N/A]${NC}"
fi

# ───────────────────────────────────────
# RÉSUMÉ
# ───────────────────────────────────────
echo ""
echo -e "${B}━━━ RÉSUMÉ ━━━${NC}"
echo ""

SUCCESSES=()
for svc in "${!STATUS[@]}"; do
    [[ "${STATUS[$svc]}" == "SUCCESS" ]] && SUCCESSES+=("$svc")
done

if [[ ${#SUCCESSES[@]} -eq 0 ]]; then
    echo -e "${Y}Aucun service accessible avec ces credentials.${NC}"
else
    echo -e "${R}${B}[!!!] CREDENTIALS VALIDES SUR :${NC}"
    for svc in "${SUCCESSES[@]}"; do
        echo -e "  ${G}✓${NC} ${B}$svc${NC}"
    done
    echo ""

    # Output markdown pour 03_LOOT.md
    echo -e "${C}── Markdown pour 03_LOOT.md ──${NC}"
    echo ""
    echo "| $USER | $PASS | $DOMAIN | ${SUCCESSES[*]} | $IP | $(date +%Y-%m-%d) |"
    echo ""

    # Commandes de connexion rapide
    echo -e "${C}── Connexions rapides ──${NC}"
    for svc in "${SUCCESSES[@]}"; do
        case "$svc" in
            SSH)   echo "  ssh $USER@$IP  # pass: $PASS" ;;
            SMB)   echo "  nxc smb $IP -u '$USER' -p '$PASS' --shares" ;;
            WinRM) echo "  evil-winrm -i $IP -u '$USER' -p '$PASS'" ;;
            LDAP)  echo "  ldapsearch -x -H ldap://$IP -D '$USER@$DOMAIN' -w '$PASS' -b 'DC=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | sed "s/\./,DC=/g")' '(objectClass=*)'" ;;
            MSSQL) echo "  impacket-mssqlclient '$DOMAIN/$USER:$PASS'@$IP" ;;
            RDP)   echo "  xfreerdp /v:$IP /u:$USER /p:'$PASS' /d:$DOMAIN /dynamic-resolution" ;;
        esac
    done
fi
echo ""
