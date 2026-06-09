#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   AUTO-ENUM MASTER — CPTS / CTF / Pentest                   ║
# ║                                                              ║
# ║   Usage: ./enum_all.sh <TARGET> [USER] [PASS] [DOMAIN]      ║
# ║   Exemples:                                                  ║
# ║     ./enum_all.sh 10.10.10.10                               ║
# ║     ./enum_all.sh 10.10.10.10 admin Password123             ║
# ║     ./enum_all.sh 10.10.10.10 admin Password123 CORP.LOCAL  ║
# ╚══════════════════════════════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
DOMAIN="${4:-}"

require_target "$TARGET"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$SCRIPT_DIR/results/$TARGET"
mkdir -p "$OUTDIR"

# ─── BANNER ────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'BANNER'
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║    █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗███╗   ║
  ║   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝████╗  ║
  ║   ███████║██║   ██║   ██║   ██║   ██║    █████╗  ██╔██╗ ║
  ║   ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══╝  ██║╚██╗║
  ║   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ███████╗██║ ╚██║
  ║   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝╚═╝  ╚═╝
  ║                  CPTS Auto-Enum v1.0                      ║
  ╚═══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo -e "${WHITE}  Target : ${CYAN}$TARGET${NC}"
[[ -n "$USER" ]] && echo -e "${WHITE}  User   : ${CYAN}$USER${NC}"
[[ -n "$PASS" ]] && echo -e "${WHITE}  Pass   : ${CYAN}$PASS${NC}"
[[ -n "$DOMAIN" ]] && echo -e "${WHITE}  Domain : ${CYAN}$DOMAIN${NC}"
echo -e "${WHITE}  Date   : ${GRAY}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# ─── PHASE 1 : NMAP DÉCOUVERTE ────────────────────────────────
section "PHASE 1 — NMAP : DÉCOUVERTE DES PORTS"

NMAP_OUTDIR="$OUTDIR/00_nmap"
mkdir -p "$NMAP_OUTDIR"

# Scan rapide all ports TCP
info "Scan TCP all ports (SYN scan rapide)"
cmd "nmap -p- --min-rate 5000 --open -n $TARGET"
timeout 180 nmap -p- --min-rate 5000 --open -n "$TARGET" \
    -oG "$NMAP_OUTDIR/all_ports.gnmap" \
    -oN "$NMAP_OUTDIR/all_ports.txt" 2>&1 | \
    grep -E "open|filtered" | tee "$NMAP_OUTDIR/open_ports_quick.txt"

# Extraire les ports ouverts
OPEN_PORTS=$(grep -oP '\d+(?=/tcp.*open)' "$NMAP_OUTDIR/all_ports.txt" 2>/dev/null | \
    tr '\n' ',' | sed 's/,$//')

if [[ -z "$OPEN_PORTS" ]]; then
    warn "Aucun port TCP détecté — essai scan UDP top 10"
    timeout 60 sudo nmap -sU --top-ports 10 -n "$TARGET" \
        -oN "$NMAP_OUTDIR/udp_top10.txt" 2>&1
    OPEN_PORTS=$(grep -oP '\d+(?=/udp.*open)' "$NMAP_OUTDIR/udp_top10.txt" 2>/dev/null | \
        tr '\n' ',' | sed 's/,$//')
fi

if [[ -z "$OPEN_PORTS" ]]; then
    error "Aucun port ouvert détecté. Vérifier la connectivité vers $TARGET"
    exit 1
fi

finding "Ports ouverts : $OPEN_PORTS"

# Scan détaillé sur les ports ouverts
info "Scan détaillé (version + scripts) sur : $OPEN_PORTS"
cmd "nmap -p$OPEN_PORTS -sC -sV -A $TARGET"
timeout 180 nmap -p"$OPEN_PORTS" -sC -sV -A "$TARGET" \
    -oN "$NMAP_OUTDIR/detailed.txt" \
    -oX "$NMAP_OUTDIR/detailed.xml" 2>&1 | tee "$NMAP_OUTDIR/detailed_console.txt"

# Scan UDP top 20
info "Scan UDP top 20 (SNMP, TFTP, DNS...)"
timeout 120 sudo nmap -sU --top-ports 20 -n "$TARGET" \
    -oN "$NMAP_OUTDIR/udp_top20.txt" 2>&1

# Extraire infos système
OS_INFO=$(grep -oP "OS details: \K.+" "$NMAP_OUTDIR/detailed.txt" 2>/dev/null | head -1)
[[ -n "$OS_INFO" ]] && finding "OS détecté : $OS_INFO"

# ─── PHASE 2 : ANALYSE ET DISPATCH ───────────────────────────
section "PHASE 2 — ANALYSE DES SERVICES DÉTECTÉS"

declare -A SERVICES_FOUND=()

check_port() {
    local port="$1"
    local label="$2"
    # TCP confirmé depuis le scan all-ports
    if echo "$OPEN_PORTS" | grep -qE "(^|,)${port}(,|$)"; then
        success "Port $port ouvert — $label"
        SERVICES_FOUND["$port"]="$label"
        return 0
    fi
    # TCP depuis le scan détaillé
    if grep -qP "^${port}/tcp\s+open\s" "$NMAP_OUTDIR/detailed.txt" 2>/dev/null; then
        success "Port $port ouvert — $label"
        SERVICES_FOUND["$port"]="$label"
        return 0
    fi
    # UDP : seulement "open" confirmé (PAS open|filtered — trop de faux positifs)
    if grep -qP "^${port}/udp\s+open\s" "$NMAP_OUTDIR/udp_top20.txt" 2>/dev/null; then
        success "Port $port ouvert UDP confirmé — $label"
        SERVICES_FOUND["$port"]="$label"
        return 0
    fi
    return 1
}

check_port 21   "FTP"
check_port 22   "SSH"
check_port 23   "Telnet"
check_port 25   "SMTP"
check_port 53   "DNS"
check_port 69   "TFTP"
check_port 80   "HTTP"
check_port 88   "Kerberos (AD)"
check_port 110  "POP3"
check_port 111  "RPCbind/NFS"
check_port 135  "MSRPC/WMI"
check_port 139  "NetBIOS"
check_port 143  "IMAP"
check_port 161  "SNMP"
check_port 389  "LDAP"
check_port 443  "HTTPS"
check_port 445  "SMB"
check_port 465  "SMTPS"
check_port 587  "SMTP Submission"
check_port 623  "IPMI"
check_port 631  "IPP"
check_port 993  "IMAPS"
check_port 995  "POP3S"
check_port 1433 "MSSQL"
check_port 1521 "Oracle TNS"
check_port 2049 "NFS"
check_port 3306 "MySQL"
check_port 3389 "RDP"
check_port 5432 "PostgreSQL"
check_port 5985 "WinRM HTTP"
check_port 5986 "WinRM HTTPS"
check_port 6379  "Redis"
check_port 8080  "HTTP-Alt"
check_port 8443  "HTTPS-Alt"
check_port 8888  "HTTP-Alt"
check_port 9090  "HTTP-Alt"
check_port 50000 "HTTP-Alt (Jetty/Jenkins)"

echo ""
info "Services détectés : ${#SERVICES_FOUND[@]}"

# ─── PHASE 3 : ENUM AUTOMATIQUE PAR SERVICE ───────────────────
section "PHASE 3 — ÉNUMÉRATION PAR SERVICE"

run_enum() {
    local script="$1"
    local label="$2"
    shift 2

    if [[ -f "$SCRIPT_DIR/${script}" ]]; then
        echo ""
        echo -e "${MAGENTA}━━━ LANCEMENT : $label ━━━${NC}"
        bash "$SCRIPT_DIR/${script}" "$@"
    else
        warn "Script non trouvé : $script"
    fi
}

# FTP
[[ -n "${SERVICES_FOUND[21]}" ]] && \
    run_enum "enum_ftp.sh" "FTP" "$TARGET" "$USER" "$PASS"

# SSH
[[ -n "${SERVICES_FOUND[22]}" ]] && \
    run_enum "enum_ssh.sh" "SSH" "$TARGET" "$USER" "$PASS"

# DNS
[[ -n "${SERVICES_FOUND[53]}" ]] && \
    run_enum "enum_dns.sh" "DNS" "$TARGET" "$DOMAIN"

# TFTP
[[ -n "${SERVICES_FOUND[69]}" ]] && \
    run_enum "enum_tftp.sh" "TFTP" "$TARGET"

# HTTP / HTTPS — détection dynamique de tous les ports HTTP
# Extraire tous les ports HTTP depuis le scan nmap détaillé
HTTP_PORTS_DETECTED=$(grep -oP '\d+(?=/tcp\s+open\s+https?)' "$NMAP_OUTDIR/detailed.txt" 2>/dev/null | sort -nu | tr '\n' ' ')
# Ajouter aussi les ports HTTP-Alt connus trouvés dans SERVICES_FOUND
for _p in 80 443 8080 8443 8888 9090 50000; do
    [[ -n "${SERVICES_FOUND[$_p]}" ]] && HTTP_PORTS_DETECTED="$HTTP_PORTS_DETECTED $_p"
done
HTTP_PORTS_DETECTED=$(echo "$HTTP_PORTS_DETECTED" | tr ' ' '\n' | sort -nu | tr '\n' ' ')

if [[ -n "$HTTP_PORTS_DETECTED" ]]; then
    section "HTTP/HTTPS — Enum Web"
    for PORT_HTTP in $HTTP_PORTS_DETECTED; do
        PROTO="http"
        [[ "$PORT_HTTP" == "443" || "$PORT_HTTP" == "8443" ]] && PROTO="https"
        # Tester HTTPS si nmap a détecté ssl
        grep -q "${PORT_HTTP}/tcp.*ssl\|${PORT_HTTP}/tcp.*https" "$NMAP_OUTDIR/detailed.txt" 2>/dev/null && PROTO="https"

        info "Web enum sur ${PROTO}://$TARGET:$PORT_HTTP"
        WEB_OUTDIR="$OUTDIR/web_${PORT_HTTP}"
        mkdir -p "$WEB_OUTDIR"

        # whatweb
        if check_tool whatweb; then
            timeout 30 whatweb -a 3 "${PROTO}://${TARGET}:${PORT_HTTP}" \
                2>&1 | tee "$WEB_OUTDIR/whatweb.txt"
        else
            curl -sIL --max-time 10 "${PROTO}://${TARGET}:${PORT_HTTP}" 2>&1 | \
                tee "$WEB_OUTDIR/curl_headers.txt"
        fi

        # nikto
        if check_tool nikto; then
            info "nikto scan"
            timeout 120 nikto -h "${PROTO}://${TARGET}:${PORT_HTTP}" \
                -output "$WEB_OUTDIR/nikto.txt" 2>&1 | tail -10
        fi

        # Jenkins / Jetty detection
        if grep -qi "Jetty\|Jenkins" "$WEB_OUTDIR/whatweb.txt" "$NMAP_OUTDIR/detailed.txt" 2>/dev/null; then
            info "Jenkins/Jetty détecté — enum spécifique"
            curl -s --max-time 10 "${PROTO}://${TARGET}:${PORT_HTTP}/api/json?pretty=true" \
                2>/dev/null | tee "$WEB_OUTDIR/jenkins_api.txt"
            curl -s --max-time 10 "${PROTO}://${TARGET}:${PORT_HTTP}/script" \
                2>/dev/null | grep -i "groovy\|script\|jenkins" | head -5 | \
                tee "$WEB_OUTDIR/jenkins_script.txt"
            WORDLIST_WEB="/usr/share/seclists/Discovery/Web-Content/common.txt"
            [[ ! -f "$WORDLIST_WEB" ]] && WORDLIST_WEB="/usr/share/wordlists/dirb/common.txt"
            [[ -f "$WORDLIST_WEB" ]] && check_tool ffuf && {
                run_long "ffuf Jenkins" "$WEB_OUTDIR/ffuf_jenkins.txt" 60 \
                    ffuf -u "${PROTO}://${TARGET}:${PORT_HTTP}/FUZZ" \
                    -w "$WORDLIST_WEB" -mc 200,301,302,403 -t 30 -s
            }
        fi

        # feroxbuster / gobuster
        if check_tool feroxbuster; then
            WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
            [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
            [[ -f "$WORDLIST" ]] && {
                info "Directory fuzzing (feroxbuster)"
                run_long "feroxbuster" "$WEB_OUTDIR/feroxbuster.txt" 90 \
                    feroxbuster --url "${PROTO}://${TARGET}:${PORT_HTTP}" \
                    --wordlist "$WORDLIST" \
                    --no-recursion \
                    --quiet
            }
        elif check_tool gobuster; then
            WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
            [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
            [[ -f "$WORDLIST" ]] && {
                info "Directory fuzzing (gobuster)"
                run_long "gobuster dir" "$WEB_OUTDIR/gobuster.txt" 90 \
                    gobuster dir \
                    -u "${PROTO}://${TARGET}:${PORT_HTTP}" \
                    -w "$WORDLIST" \
                    --no-error -q
            }
        fi
    done
fi

# SMTP
if [[ -n "${SERVICES_FOUND[25]}" ]] || [[ -n "${SERVICES_FOUND[465]}" ]] || \
   [[ -n "${SERVICES_FOUND[587]}" ]]; then
    run_enum "enum_smtp.sh" "SMTP" "$TARGET" "$DOMAIN" "$USER" "$PASS"
fi

# SNMP
[[ -n "${SERVICES_FOUND[161]}" ]] && \
    run_enum "enum_snmp.sh" "SNMP" "$TARGET"

# IMAP/POP3
if [[ -n "${SERVICES_FOUND[110]}" ]] || [[ -n "${SERVICES_FOUND[143]}" ]] || \
   [[ -n "${SERVICES_FOUND[993]}" ]] || [[ -n "${SERVICES_FOUND[995]}" ]]; then
    run_enum "enum_imap.sh" "IMAP/POP3" "$TARGET" "$USER" "$PASS"
fi

# SMB
if [[ -n "${SERVICES_FOUND[139]}" ]] || [[ -n "${SERVICES_FOUND[445]}" ]]; then
    run_enum "enum_smb.sh" "SMB" "$TARGET" "$USER" "$PASS" "$DOMAIN"
fi

# NFS
if [[ -n "${SERVICES_FOUND[111]}" ]] || [[ -n "${SERVICES_FOUND[2049]}" ]]; then
    run_enum "enum_nfs.sh" "NFS" "$TARGET"
fi

# RDP
[[ -n "${SERVICES_FOUND[3389]}" ]] && \
    run_enum "enum_rdp.sh" "RDP" "$TARGET" "$USER" "$PASS" "$DOMAIN"

# WinRM
if [[ -n "${SERVICES_FOUND[5985]}" ]] || [[ -n "${SERVICES_FOUND[5986]}" ]]; then
    run_enum "enum_winrm.sh" "WinRM" "$TARGET" "$USER" "$PASS" "$DOMAIN"
fi

# MySQL
[[ -n "${SERVICES_FOUND[3306]}" ]] && \
    run_enum "enum_mysql.sh" "MySQL" "$TARGET" "$USER" "$PASS"

# MSSQL
[[ -n "${SERVICES_FOUND[1433]}" ]] && \
    run_enum "enum_mssql.sh" "MSSQL" "$TARGET" "$USER" "$PASS" "$DOMAIN"

# Oracle TNS
[[ -n "${SERVICES_FOUND[1521]}" ]] && \
    run_enum "enum_oracle.sh" "Oracle TNS" "$TARGET"

# IPMI
[[ -n "${SERVICES_FOUND[623]}" ]] && \
    run_enum "enum_ipmi.sh" "IPMI" "$TARGET"

# LDAP (AD)
[[ -n "${SERVICES_FOUND[389]}" ]] && {
    section "LDAP — Active Directory"
    LDAP_OUTDIR="$OUTDIR/ldap"
    mkdir -p "$LDAP_OUTDIR"

    if check_tool ldapsearch; then
        info "ldapsearch — base DN et null bind"
        timeout 20 ldapsearch -x -H "ldap://$TARGET" -b "" \
            -s base namingContexts 2>&1 | tee "$LDAP_OUTDIR/base_dn.txt"

        BASE_DN=$(grep -oP 'DC=\S+' "$LDAP_OUTDIR/base_dn.txt" 2>/dev/null | head -1)
        if [[ -n "$BASE_DN" ]]; then
            finding "Base DN : $BASE_DN"
            timeout 30 ldapsearch -x -H "ldap://$TARGET" -b "$BASE_DN" 2>&1 | \
                tee "$LDAP_OUTDIR/anon_dump.txt"
        fi
    fi

    if check_tool enum4linux; then
        info "enum4linux — enum AD"
        run_long "enum4linux" "$LDAP_OUTDIR/enum4linux.txt" 120 \
            enum4linux -a "$TARGET"
    fi
}

# Kerberos (AD)
[[ -n "${SERVICES_FOUND[88]}" ]] && {
    section "KERBEROS — Active Directory"
    KERB_OUTDIR="$OUTDIR/kerberos"
    mkdir -p "$KERB_OUTDIR"

    if check_tool kerbrute; then
        USERLIST=""
        for wl in \
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt" \
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"; do
            [[ -f "$wl" ]] && USERLIST="$wl" && break
        done

        [[ -n "$USERLIST" ]] && {
            info "kerbrute — enum users Kerberos"
            run_long "kerbrute userenum" "$KERB_OUTDIR/kerbrute.txt" 120 \
                kerbrute userenum \
                --dc "$TARGET" \
                -d "${DOMAIN:-$(hostname -d 2>/dev/null)}" \
                "$USERLIST"

            # Extraire users valides
            grep "VALID USERNAME" "$KERB_OUTDIR/kerbrute.txt" 2>/dev/null | \
                grep -oP '\S+@\S+' | tee "$KERB_OUTDIR/valid_users.txt"
        }
    fi

    # AS-REP Roasting (sans credentials)
    if [[ -s "$KERB_OUTDIR/valid_users.txt" ]] && check_tool GetNPUsers.py; then
        info "AS-REP Roasting (utilisateurs sans Kerberos preauth)"
        DOMAIN_GUESS="${DOMAIN:-$(grep -oP '@\K\S+' "$KERB_OUTDIR/valid_users.txt" | head -1)}"
        run_long "GetNPUsers" "$KERB_OUTDIR/asrep_hashes.txt" 60 \
            GetNPUsers.py "${DOMAIN_GUESS}/" \
            -usersfile "$KERB_OUTDIR/valid_users.txt" \
            -no-pass -dc-ip "$TARGET"
        grep "\$krb5asrep" "$KERB_OUTDIR/asrep_hashes.txt" 2>/dev/null && \
            success "AS-REP hashes récupérés → hashcat -m 18200"
    fi
}

# ─── PHASE 4 : RAPPORT FINAL ──────────────────────────────────
section "PHASE 4 — RAPPORT FINAL"

REPORT="$OUTDIR/RAPPORT_$(date +%Y%m%d_%H%M%S).md"
cat > "$REPORT" << REPORT_HEADER
# Auto-Enum Report — $TARGET
**Date :** $(date '+%Y-%m-%d %H:%M:%S')
**Target :** $TARGET
**User :** ${USER:-N/A}
**Domain :** ${DOMAIN:-N/A}

---

## Ports ouverts

\`\`\`
$OPEN_PORTS
\`\`\`

## Services détectés

REPORT_HEADER

for port in "${!SERVICES_FOUND[@]}"; do
    echo "- Port $port : ${SERVICES_FOUND[$port]}" >> "$REPORT"
done

echo "" >> "$REPORT"
echo "## Credentials trouvés" >> "$REPORT"
echo "" >> "$REPORT"

# Agréger tous les valid_creds
find "$OUTDIR" -name "valid_creds.txt" -exec cat {} \; 2>/dev/null | \
    sort -u | tee -a "$REPORT"

echo "" >> "$REPORT"
echo "## Hashes NTLM" >> "$REPORT"
echo "" >> "$REPORT"
find "$OUTDIR" -name "hashes_found.txt" -exec cat {} \; 2>/dev/null | \
    sort -u | tee -a "$REPORT"

echo "" >> "$REPORT"
echo "## Findings importants" >> "$REPORT"
echo "" >> "$REPORT"
find "$OUTDIR" -name "findings.txt" -exec cat {} \; 2>/dev/null | \
    sort -u | tee -a "$REPORT"

# ─── SUMMARY FINAL ────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ AUTO-ENUM TERMINÉ — $TARGET${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${WHITE}  Ports ouverts  : ${CYAN}$OPEN_PORTS${NC}"
echo -e "${WHITE}  Services       : ${CYAN}${#SERVICES_FOUND[@]}${NC}"
echo -e "${WHITE}  Résultats      : ${CYAN}$OUTDIR${NC}"
echo -e "${WHITE}  Rapport        : ${CYAN}$REPORT${NC}"
echo ""

# Credentials agrégés
ALL_CREDS=$(find "$OUTDIR" -name "valid_creds.txt" -exec cat {} \; 2>/dev/null | sort -u)
if [[ -n "$ALL_CREDS" ]]; then
    echo -e "${GREEN}  ★ CREDENTIALS VALIDES TROUVÉS :${NC}"
    echo "$ALL_CREDS" | while read -r line; do
        echo -e "    ${YELLOW}$line${NC}"
    done
fi

ALL_FINDINGS=$(find "$OUTDIR" -name "findings.txt" -exec cat {} \; 2>/dev/null | sort -u)
if [[ -n "$ALL_FINDINGS" ]]; then
    echo ""
    echo -e "${YELLOW}  ⚠ FINDINGS IMPORTANTS :${NC}"
    echo "$ALL_FINDINGS" | while read -r line; do
        echo -e "    ${RED}$line${NC}"
    done
fi

echo ""
