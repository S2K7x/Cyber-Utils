#!/bin/bash
# recon.sh — Recon initiale complète : nmap → DNS → service enum automatique
# Usage: ./recon.sh <IP> [domaine]
# Exemple: ./recon.sh 10.129.20.33 inlanefreight.local
#
# Ce que ça fait :
#   1. Nmap quick scan (TCP top 1000)
#   2. Nmap full scan en arrière-plan (tous les ports)
#   3. Zone transfer DNS si domaine fourni
#   4. service-enum.sh sur chaque port ouvert trouvé
#   5. Résumé markdown final prêt à coller dans 04_External_Recon.md

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_ENUM="$SCRIPT_DIR/../pentest/service-enum.sh"

banner() { echo -e "${B}${C}"; echo "╔══════════════════════════════════════════╗"; echo "║  $1"; echo "╚══════════════════════════════════════════╝"; echo -e "${NC}"; }

if [[ $# -lt 1 ]]; then
    echo -e "${R}Usage: $0 <IP> [domaine]${NC}"
    echo "  Ex: $0 10.129.20.33 inlanefreight.local"
    exit 1
fi

IP="$1"
DOMAIN="${2:-}"
OUTDIR="./recon-$(echo "$IP" | tr '.' '-')"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M")

mkdir -p "$OUTDIR/nmap" "$OUTDIR/services"

banner "recon.sh — $IP ${DOMAIN:+| $DOMAIN}"
echo -e "  Output : ${B}$OUTDIR/${NC}"
echo -e "  Début  : $TIMESTAMP"
echo ""

# ───────────────────────────────────────
# 1. NMAP QUICK SCAN
# ───────────────────────────────────────
echo -e "${C}[1/4] Nmap quick scan (top 1000 TCP)...${NC}"
nmap -sV --open -T4 -oN "$OUTDIR/nmap/quick.txt" "$IP" 2>/dev/null
echo -e "${G}[✓] Quick scan terminé${NC}"

# Extraire les ports ouverts
OPEN_PORTS=$(grep "^[0-9]" "$OUTDIR/nmap/quick.txt" | grep "open" | awk -F'/' '{print $1}')
PORT_LIST=$(echo "$OPEN_PORTS" | tr '\n' ',' | sed 's/,$//')

echo ""
echo -e "${B}Ports ouverts détectés :${NC} $PORT_LIST"
echo ""

# ───────────────────────────────────────
# 2. NMAP FULL SCAN (arrière-plan)
# ───────────────────────────────────────
echo -e "${C}[2/4] Nmap full scan (tous les ports) — lancé en arrière-plan...${NC}"
sudo nmap -sC -sV -p- --min-rate 5000 -oA "$OUTDIR/nmap/full" "$IP" > /dev/null 2>&1 &
NMAP_FULL_PID=$!
echo -e "${Y}[~] Full scan PID: $NMAP_FULL_PID — continuera en arrière-plan${NC}"
echo ""

# ───────────────────────────────────────
# 3. DNS
# ───────────────────────────────────────
echo -e "${C}[3/4] Enumération DNS...${NC}"
{
    echo "# DNS Enumeration — $IP | ${DOMAIN:-?}"
    echo ""
    echo "## Records de base"
    echo '```'

    if [[ -n "$DOMAIN" ]]; then
        echo "=== A ===" && dig +short A "$DOMAIN" @"$IP" 2>/dev/null || dig +short A "$DOMAIN" 2>/dev/null
        echo "=== MX ===" && dig +short MX "$DOMAIN" @"$IP" 2>/dev/null
        echo "=== NS ===" && dig +short NS "$DOMAIN" @"$IP" 2>/dev/null
        echo "=== TXT ===" && dig +short TXT "$DOMAIN" @"$IP" 2>/dev/null
    else
        dig +short "$IP" 2>/dev/null || true
    fi
    echo '```'
    echo ""

    if [[ -n "$DOMAIN" ]]; then
        echo "## Zone Transfer (AXFR)"
        echo '```'
        NAMESERVER=$(dig +short NS "$DOMAIN" 2>/dev/null | head -1)
        echo "Nameserver : $NAMESERVER"
        if [[ -n "$NAMESERVER" ]]; then
            dig AXFR "@$IP" "$DOMAIN" 2>/dev/null
            dig AXFR "@$NAMESERVER" "$DOMAIN" 2>/dev/null || true
        else
            dig AXFR "@$IP" "$DOMAIN" 2>/dev/null
        fi
        echo '```'

        echo ""
        echo "## Subdomains (dnsenum)"
        echo '```'
        dnsenum --dnsserver "$IP" --enum -p 0 -s 0 \
            -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            "$DOMAIN" 2>/dev/null | grep -v "^$" || echo "(dnsenum non disponible)"
        echo '```'
    fi
} > "$OUTDIR/dns.md" 2>/dev/null

# Extraire les subdomains découverts
if [[ -n "$DOMAIN" ]]; then
    SUBDOMAINS=$(grep -oP '[a-zA-Z0-9-]+\.'$(echo "$DOMAIN" | sed 's/\./\\./g') "$OUTDIR/dns.md" 2>/dev/null | sort -u | grep -v "^$DOMAIN" || true)
    SUBDOMAIN_COUNT=$(echo "$SUBDOMAINS" | grep -c '.' 2>/dev/null || echo 0)
    echo -e "${G}[✓] DNS terminé — $SUBDOMAIN_COUNT subdomains trouvés${NC}"
    if [[ -n "$SUBDOMAINS" ]]; then
        echo -e "${Y}    Subdomains :${NC}"
        echo "$SUBDOMAINS" | while read -r s; do echo "      - $s"; done
    fi
else
    echo -e "${G}[✓] DNS terminé (pas de domaine fourni)${NC}"
fi
echo ""

# ───────────────────────────────────────
# 4. SERVICE ENUM PAR PORT
# ───────────────────────────────────────
echo -e "${C}[4/4] Service enum sur chaque port ouvert...${NC}"
echo ""

SERVICES_MD="$OUTDIR/services-summary.md"
{
    echo "# Services — $IP"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo ""
} > "$SERVICES_MD"

if [[ -z "$OPEN_PORTS" ]]; then
    echo -e "${Y}[~] Aucun port ouvert détecté dans le quick scan${NC}"
else
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        echo -e "  ${C}→${NC} Port ${B}$port${NC}..."
        {
            echo "---"
            echo ""
            if [[ -x "$SERVICE_ENUM" ]]; then
                bash "$SERVICE_ENUM" "$IP" "$port" 2>/dev/null
            else
                echo "## Port $port"
                echo "service-enum.sh non trouvé — lancer manuellement : nmap -sV -p $port $IP"
            fi
            echo ""
        } >> "$SERVICES_MD"
    done <<< "$OPEN_PORTS"
    echo -e "${G}[✓] Service enum terminé${NC}"
fi
echo ""

# ───────────────────────────────────────
# RÉSUMÉ MARKDOWN
# ───────────────────────────────────────
SUMMARY="$OUTDIR/SUMMARY.md"
{
    echo "# 🔭 Recon Summary — \`$IP\`"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo "**IP :** \`$IP\`"
    [[ -n "$DOMAIN" ]] && echo "**Domaine :** \`$DOMAIN\`"
    echo ""
    echo "---"
    echo ""
    echo "## Ports ouverts"
    echo ""
    echo "\`\`\`"
    grep "^[0-9]" "$OUTDIR/nmap/quick.txt" | grep "open" 2>/dev/null || echo "(voir nmap/quick.txt)"
    echo "\`\`\`"
    echo ""
    echo "## Next steps"
    echo ""

    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        # Générer l'action selon le port
        case "$port" in
            21)  echo "- [ ] Port 21 FTP — tester anonymous login" ;;
            22)  echo "- [ ] Port 22 SSH — noter pour plus tard (besoin creds)" ;;
            25|465|587) echo "- [ ] Port $port SMTP — smtp-user-enum + VRFY" ;;
            53)  echo "- [ ] Port 53 DNS — zone transfer + brute subdomains" ;;
            80|443|8080|8443) echo "- [ ] Port $port HTTP — **05_Web_Surface.md** → fingerprint + ffuf" ;;
            110|995) echo "- [ ] Port $port POP3 — capabilities + creds" ;;
            111) echo "- [ ] Port 111 RPC — rpcinfo + showmount (NFS ?)" ;;
            139|445) echo "- [ ] Port $port SMB — null session + enum4linux" ;;
            161) echo "- [ ] Port 161 SNMP — onesixtyone + snmpwalk" ;;
            389|636) echo "- [ ] Port $port LDAP — anonymous bind → si AD → 06_AD_Enum.md" ;;
            993|143) echo "- [ ] Port $port IMAP — capabilities + cert subdomains" ;;
            1433) echo "- [ ] Port 1433 MSSQL — SA empty password ? xp_cmdshell ?" ;;
            2049) echo "- [ ] Port 2049 NFS — **./recon/nfs-hunt.sh $IP** IMMÉDIATEMENT" ;;
            3306) echo "- [ ] Port 3306 MySQL — tester anonymous" ;;
            3389) echo "- [ ] Port 3389 RDP — NLA check + creds si disponibles" ;;
            5985|5986) echo "- [ ] Port $port WinRM — evil-winrm si creds" ;;
            623)  echo "- [ ] Port 623 IPMI — dump hashes sans auth (cipher 0)" ;;
            *) echo "- [ ] Port $port — nmap -sV + searchsploit" ;;
        esac
    done <<< "$OPEN_PORTS"

    echo ""
    echo "## Fichiers générés"
    echo ""
    echo "\`\`\`"
    ls -1 "$OUTDIR/" 2>/dev/null
    echo "\`\`\`"
    echo ""
    echo "> **Coller dans** : \`04_External_Recon.md\` → section Port Scan"
} > "$SUMMARY"

echo ""
echo -e "${B}${G}╔══════════════════════════════════════════╗${NC}"
echo -e "${B}${G}║              RECON TERMINÉE              ║${NC}"
echo -e "${B}${G}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dossier de sortie : ${B}$OUTDIR/${NC}"
echo -e "  Résumé            : ${B}$OUTDIR/SUMMARY.md${NC}"
echo -e "  DNS               : ${B}$OUTDIR/dns.md${NC}"
echo -e "  Services          : ${B}$OUTDIR/services-summary.md${NC}"
echo ""
echo -e "${Y}[~] Full scan nmap toujours en cours (PID $NMAP_FULL_PID)${NC}"
echo -e "    Résultat dans : $OUTDIR/nmap/full.xml"
echo -e "    Parser avec  : python3 ../pentest/parse-nmap.py $OUTDIR/nmap/full.xml"
echo ""

# Si NFS est ouvert, rappel prioritaire
if echo "$OPEN_PORTS" | grep -q "^2049\|^111"; then
    echo -e "${R}[!!!] NFS DÉTECTÉ — Lancer IMMÉDIATEMENT :${NC}"
    echo -e "    ${B}./recon/nfs-hunt.sh $IP${NC}"
    echo ""
fi

echo -e "${G}[✓] Coller le résumé dans 04_External_Recon.md :${NC}"
echo -e "    cat $SUMMARY"
