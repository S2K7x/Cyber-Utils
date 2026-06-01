#!/bin/bash
# hash-crack.sh — Détection auto du type de hash + cracking hashcat
# Usage: ./hash-crack.sh <hash-file> [wordlist]
# Exemple: ./hash-crack.sh hashes.txt
#          ./hash-crack.sh ntlm.txt /usr/share/wordlists/rockyou.txt
#
# Détecte automatiquement : NTLM, NTLMv2, SHA-512 crypt, MD5, TGS (Kerberoast),
#                           AS-REP, bcrypt, SHA-1, etc.
# Lance hashcat avec rockyou + règles best64

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo -e "${R}Usage: $0 <hash-file> [wordlist]${NC}"
    echo ""
    echo "  Ex: $0 hashes.txt"
    echo "  Ex: $0 ntlm_hashes.txt /custom/wordlist.txt"
    exit 1
fi

HASH_FILE="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"

if [[ ! -f "$HASH_FILE" ]]; then
    echo -e "${R}[!] Fichier introuvable : $HASH_FILE${NC}"
    exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
    # Chercher rockyou compressé
    if [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
        echo -e "${Y}[~] Décompression rockyou.txt...${NC}"
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        WORDLIST="/usr/share/wordlists/rockyou.txt"
    else
        echo -e "${R}[!] Wordlist introuvable : $WORDLIST${NC}"
        exit 1
    fi
fi

RULES="/usr/share/hashcat/rules/best64.rule"
OUTFILE="./cracked-$(date +%Y%m%d-%H%M).txt"

echo -e "${B}${C}"
echo "╔══════════════════════════════════════════════════╗"
echo "║   hash-crack.sh"
echo "╠══════════════════════════════════════════════════╣"
echo "║   Fichier   : $HASH_FILE"
echo "║   Wordlist  : $WORDLIST"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Lire le premier hash pour détecter le type
FIRST_HASH=$(grep -v "^$\|^#" "$HASH_FILE" | head -1)
echo -e "${C}Exemple de hash : ${NC}${FIRST_HASH:0:80}..."
echo ""

# ───────────────────────────────────────
# Détection du type de hash
# ───────────────────────────────────────
detect_mode() {
    local h="$1"

    # NTLMv2 (Responder / Inveigh)
    if echo "$h" | grep -qP "^[^:]+::[^:]+:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$"; then
        echo "5600"; return
    fi

    # AS-REP Roast (krb5asrep)
    if echo "$h" | grep -qP "^\$krb5asrep\$"; then
        echo "18200"; return
    fi

    # TGS Kerberoast (krb5tgs)
    if echo "$h" | grep -qP "^\$krb5tgs\$"; then
        echo "13100"; return
    fi

    # RAKP (IPMI)
    if echo "$h" | grep -qP "^[0-9a-f]{20}:[0-9a-f]{40}"; then
        echo "7300"; return
    fi

    # bcrypt $2y$ ou $2b$
    if echo "$h" | grep -qP "^\\\$2[yb]\\\$"; then
        echo "3200"; return
    fi

    # SHA-512 crypt $6$
    if echo "$h" | grep -qP "^\\\$6\\\$"; then
        echo "1800"; return
    fi

    # SHA-256 crypt $5$
    if echo "$h" | grep -qP "^\\\$5\\\$"; then
        echo "7400"; return
    fi

    # MD5 crypt $1$ ou $apr1$
    if echo "$h" | grep -qP "^\\\$(1|apr1)\\\$"; then
        echo "500"; return
    fi

    # NetNTLMv1
    if echo "$h" | grep -qP "^[^:]+:[0-9]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:"; then
        echo "5500"; return
    fi

    # NTLM pur (32 hex)
    if echo "$h" | grep -qP "^[a-fA-F0-9]{32}$"; then
        echo "1000"; return
    fi

    # MD5 pur (32 hex) - même regex, hashcat distingue par le contexte
    if echo "$h" | grep -qP "^[a-fA-F0-9]{32}$"; then
        echo "0"; return
    fi

    # SHA-1 (40 hex)
    if echo "$h" | grep -qP "^[a-fA-F0-9]{40}$"; then
        echo "100"; return
    fi

    # SHA-256 (64 hex)
    if echo "$h" | grep -qP "^[a-fA-F0-9]{64}$"; then
        echo "1400"; return
    fi

    # SHA-512 (128 hex)
    if echo "$h" | grep -qP "^[a-fA-F0-9]{128}$"; then
        echo "1700"; return
    fi

    # Format user:hash (SAM / impacket-secretsdump)
    if echo "$h" | grep -qP "^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$"; then
        echo "1000:SAM"; return
    fi

    echo "UNKNOWN"
}

MODE=$(detect_mode "$FIRST_HASH")

# Table des modes hashcat
declare -A MODE_NAMES=(
    ["0"]="MD5"
    ["100"]="SHA-1"
    ["1000"]="NTLM"
    ["1000:SAM"]="NTLM (format SAM — extraction des hashes)"
    ["1400"]="SHA-256"
    ["1700"]="SHA-512"
    ["1800"]="SHA-512 crypt (\$6\$)"
    ["3200"]="bcrypt"
    ["5500"]="NetNTLMv1"
    ["5600"]="NetNTLMv2 (Responder/Inveigh)"
    ["7300"]="RAKP (IPMI)"
    ["7400"]="SHA-256 crypt (\$5\$)"
    ["13100"]="TGS-REP (Kerberoast)"
    ["18200"]="AS-REP Roast (krb5asrep)"
    ["UNKNOWN"]="Type inconnu"
)

echo -e "${B}Type détecté : ${G}${MODE_NAMES[$MODE]:-$MODE}${NC}"
echo ""

if [[ "$MODE" == "UNKNOWN" ]]; then
    echo -e "${Y}[~] Hash non reconnu. Essayer hashcat --identify :${NC}"
    hashcat --identify "$HASH_FILE" 2>/dev/null || true
    echo ""
    read -r -p "Entrer le mode hashcat manuellement : " MODE
fi

# Si format SAM → extraire uniquement les hashes NT
if [[ "$MODE" == "1000:SAM" ]]; then
    echo -e "${Y}[~] Format SAM détecté — extraction des hashes NT...${NC}"
    CLEAN_FILE="$HASH_FILE.nt"
    grep -oP "[a-fA-F0-9]{32}(?=:::$)" "$HASH_FILE" > "$CLEAN_FILE" 2>/dev/null
    echo -e "${G}[✓] Hashes NT extraits dans : $CLEAN_FILE${NC}"
    HASH_FILE="$CLEAN_FILE"
    MODE="1000"
fi

# ───────────────────────────────────────
# Lancement hashcat
# ───────────────────────────────────────
echo -e "${C}Lancement hashcat (mode $MODE)...${NC}"
echo ""

# Méthode 1 : Wordlist sans règles
echo -e "${B}[1/3] Attaque dictionnaire simple (rockyou)${NC}"
hashcat -m "$MODE" "$HASH_FILE" "$WORDLIST" \
    --quiet --status --status-timer=30 \
    -o "$OUTFILE" --outfile-format=2 \
    --potfile-path="./hashcat-$(date +%Y%m%d).pot" \
    2>/dev/null | tail -5 || true

# Méthode 2 : Wordlist + règles best64
echo ""
echo -e "${B}[2/3] Attaque dictionnaire + règles best64${NC}"
if [[ -f "$RULES" ]]; then
    hashcat -m "$MODE" "$HASH_FILE" "$WORDLIST" \
        -r "$RULES" \
        --quiet --status --status-timer=30 \
        -o "$OUTFILE" --outfile-format=2 \
        --potfile-path="./hashcat-$(date +%Y%m%d).pot" \
        2>/dev/null | tail -5 || true
else
    echo -e "${Y}[~] Règles best64 non trouvées${NC}"
fi

# Méthode 3 : Wordlist + règles d2wb (si dispo)
echo ""
echo -e "${B}[3/3] Attaque avec règles dive${NC}"
DIVE_RULES="/usr/share/hashcat/rules/dive.rule"
if [[ -f "$DIVE_RULES" ]]; then
    hashcat -m "$MODE" "$HASH_FILE" "$WORDLIST" \
        -r "$DIVE_RULES" \
        --quiet --status --status-timer=30 \
        -o "$OUTFILE" --outfile-format=2 \
        --potfile-path="./hashcat-$(date +%Y%m%d).pot" \
        2>/dev/null | tail -5 || true
fi

# ───────────────────────────────────────
# Afficher les résultats
# ───────────────────────────────────────
echo ""
echo -e "${B}━━━ RÉSULTATS ━━━${NC}"
echo ""

if [[ -f "$OUTFILE" && -s "$OUTFILE" ]]; then
    CRACKED=$(wc -l < "$OUTFILE")
    echo -e "${G}[✓] $CRACKED hash(es) cracké(s) !${NC}"
    echo ""
    cat "$OUTFILE"
    echo ""
    echo -e "${C}── Markdown pour 03_LOOT.md ──${NC}"
    echo ""
    echo "| Hash | Password | Source |"
    echo "|---|---|---|"
    while IFS=: read -r hash pass; do
        echo "| \`${hash:0:20}...\` | \`$pass\` | $1 |"
    done < "$OUTFILE"
    echo ""
    echo -e "${R}[!!!] Reporter dans 03_LOOT.md IMMÉDIATEMENT${NC}"
else
    echo -e "${Y}[~] Aucun hash cracké avec rockyou.${NC}"
    echo ""
    echo -e "${C}Suggestions :${NC}"
    echo "  1. Wordlist plus grande : /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"
    echo "  2. CeWL sur le site cible : cewl http://TARGET/ -d 5 -m 8 -w custom.txt"
    echo "  3. Générer des patterns : hashcat --stdout -a 3 ?u?l?l?l?d?d?d?d! | hashcat -m $MODE $HASH_FILE --stdin"
    echo "  4. username-anarchy : ./username-anarchy FirstName LastName"
fi

echo ""
echo -e "  Fichier cracked : ${B}$OUTFILE${NC}"
