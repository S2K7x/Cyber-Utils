#!/usr/bin/env bash
# Fonctions et couleurs communes à tous les scripts Auto-Enum

# ─── Couleurs ───────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ─── Compatibilité macOS ────────────────────────────────────
# Bug fix: macOS n'a pas `timeout` natif (c'est GNU coreutils)
# Priorité : gtimeout (brew install coreutils) → implémentation bash pure
if ! command -v timeout &>/dev/null; then
    if command -v gtimeout &>/dev/null; then
        timeout() { gtimeout "$@"; }
        export -f timeout 2>/dev/null || true
    else
        # Implémentation bash pure sans GNU coreutils
        timeout() {
            local _secs="$1"; shift
            (
                "$@" &
                local _pid=$!
                ( sleep "$_secs" && kill -TERM "$_pid" 2>/dev/null ) &
                local _kill_pid=$!
                wait "$_pid" 2>/dev/null
                local _rc=$?
                kill "$_kill_pid" 2>/dev/null
                wait "$_kill_pid" 2>/dev/null
                return "$_rc"
            )
        }
        export -f timeout 2>/dev/null || true
    fi
fi

# ─── Helpers ────────────────────────────────────────────────
banner() {
    local service="$1"
    local target="$2"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}  🔍 AUTO-ENUM — ${service}${NC}"
    echo -e "${CYAN}║${GRAY}  Target : ${target}${NC}"
    echo -e "${CYAN}║${GRAY}  Date   : $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  ▶ ${WHITE}${1}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

info()    { echo -e "${CYAN}[*]${NC} ${1}"; }
success() { echo -e "${GREEN}[+]${NC} ${1}"; }
warn()    { echo -e "${YELLOW}[!]${NC} ${1}"; }
error()   { echo -e "${RED}[-]${NC} ${1}"; }
cmd()     { echo -e "${GRAY}    \$ ${1}${NC}"; }
finding() { echo -e "${MAGENTA}[★]${NC} ${WHITE}${1}${NC}"; }

# ─── Setup répertoire de sortie ─────────────────────────────
setup_outdir() {
    local target="$1"
    local service="$2"
    local outdir="$(dirname "$0")/results/${target}/${service}"
    mkdir -p "$outdir"
    echo "$outdir"
}

# ─── Vérifier si un outil est disponible ────────────────────
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "Outil manquant : ${YELLOW}${1}${NC} — section ignorée"
        return 1
    fi
    return 0
}

# ─── Run command avec timeout et sauvegarde ─────────────────
run() {
    local label="$1"
    local outfile="$2"
    shift 2
    info "$label"
    cmd "$*"
    timeout 30 "$@" 2>&1 | tee "$outfile"
    echo ""
}

run_long() {
    local label="$1"
    local outfile="$2"
    local timeout_sec="$3"
    shift 3
    info "$label"
    cmd "$*"
    timeout "$timeout_sec" "$@" 2>&1 | tee "$outfile"
    echo ""
}

# ─── Résumé final ───────────────────────────────────────────
summary() {
    local outdir="$1"
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ÉNUMÉRATION TERMINÉE${NC}"
    echo -e "${GREEN}║${GRAY}  Résultats : ${outdir}${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}Fichiers générés :${NC}"
    ls -lh "$outdir" 2>/dev/null | grep -v "^total" | awk '{print "  " $NF " (" $5 ")"}'
    echo ""
}

# ─── Vérification des arguments ─────────────────────────────
require_target() {
    if [[ -z "$1" ]]; then
        echo -e "${RED}Usage : $0 <TARGET> [USER] [PASS] [DOMAIN]${NC}"
        echo -e "${GRAY}  TARGET : IP ou hostname${NC}"
        echo -e "${GRAY}  USER   : Nom d'utilisateur (optionnel)${NC}"
        echo -e "${GRAY}  PASS   : Mot de passe (optionnel)${NC}"
        echo -e "${GRAY}  DOMAIN : Domaine AD (optionnel)${NC}"
        exit 1
    fi
}
