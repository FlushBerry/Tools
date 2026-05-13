#!/bin/bash

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 -f <fichier_ips> [-k <clef_ssh>] [-p <password>] [-P <passphrase>] [-u <user>] [-o <port>]

Options:
  -f <fichier_ips>   Fichier contenant la liste des IPs (obligatoire)
  -k <clef_ssh>      Chemin vers la clef SSH privée
  -p <password>      Mot de passe SSH (auth par mot de passe)
  -P <passphrase>    Passphrase de la clef SSH (si la clef est protégée)
  -u <user>          Utilisateur SSH (défaut: root)
  -o <port>          Port SSH (défaut: 22)
  -h                 Affiche cette aide

Exemples:
  $0 -f ips.txt -k ~/.ssh/id_rsa
  $0 -f ips.txt -k ~/.ssh/id_rsa -P "ma_passphrase"
  $0 -f ips.txt -p "mon_password" -u ubuntu
EOF
    exit 1
}

# Valeurs par défaut
SSH_USER="root"
SSH_PORT="22"
SSH_KEY=""
SSH_PASSWORD=""
SSH_PASSPHRASE=""
IP_LIST=""
TIMEOUT=3

# Parsing des arguments
while getopts "f:k:p:P:u:o:h" opt; do
    case $opt in
        f) IP_LIST="$OPTARG" ;;
        k) SSH_KEY="$OPTARG" ;;
        p) SSH_PASSWORD="$OPTARG" ;;
        P) SSH_PASSPHRASE="$OPTARG" ;;
        u) SSH_USER="$OPTARG" ;;
        o) SSH_PORT="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# Vérifications de base
[ -z "$IP_LIST" ] && echo -e "${RED}Erreur: fichier IPs requis (-f)${NC}" && usage
[ ! -f "$IP_LIST" ] && echo -e "${RED}Fichier IPs introuvable: $IP_LIST${NC}" && exit 1

if [ -z "$SSH_KEY" ] && [ -z "$SSH_PASSWORD" ]; then
    echo -e "${RED}Erreur: il faut au moins -k (clef) ou -p (password)${NC}"
    usage
fi

# Vérification de la clef SSH
if [ -n "$SSH_KEY" ]; then
    if [ ! -f "$SSH_KEY" ]; then
        echo -e "${RED}Clef SSH introuvable: $SSH_KEY${NC}"
        exit 1
    fi

    # Vérification des permissions (doit être 600 ou 400)
    PERMS=$(stat -c "%a" "$SSH_KEY" 2>/dev/null || stat -f "%A" "$SSH_KEY" 2>/dev/null)
    if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ]; then
        echo -e "${YELLOW}⚠ Permissions incorrectes sur $SSH_KEY ($PERMS). Correction en 600...${NC}"
        chmod 600 "$SSH_KEY" || { echo -e "${RED}Impossible de corriger les permissions${NC}"; exit 1; }
        echo -e "${GREEN}✓ Permissions corrigées${NC}"
    fi
fi

# Vérification de sshpass si nécessaire
if [ -n "$SSH_PASSWORD" ] || [ -n "$SSH_PASSPHRASE" ]; then
    if ! command -v sshpass >/dev/null 2>&1; then
        echo -e "${RED}Erreur: sshpass est requis pour l'authentification par password/passphrase${NC}"
        echo -e "${YELLOW}Installation: apt install sshpass  |  brew install hudochenkov/sshpass/sshpass${NC}"
        exit 1
    fi
fi

# Fonction de check
check_ssh() {
    local ip=$1

    # Pré-check du port TCP
    if ! timeout 2 bash -c "</dev/tcp/$ip/$SSH_PORT" 2>/dev/null; then
        echo -e "${RED}[✗] $ip - NOK (port $SSH_PORT fermé/injoignable)${NC}"
        return
    fi

    local ssh_opts="-o BatchMode=no -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=publickey,password -o PubkeyAuthentication=yes -p $SSH_PORT"
    local result=1

    if [ -n "$SSH_KEY" ] && [ -n "$SSH_PASSPHRASE" ]; then
        # Clef + passphrase
        sshpass -P "passphrase" -p "$SSH_PASSPHRASE" \
            ssh -i "$SSH_KEY" $ssh_opts "$SSH_USER@$ip" "exit" 2>/dev/null
        result=$?
    elif [ -n "$SSH_KEY" ]; then
        # Clef seule
        ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=$TIMEOUT \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR -p "$SSH_PORT" "$SSH_USER@$ip" "exit" 2>/dev/null
        result=$?
    elif [ -n "$SSH_PASSWORD" ]; then
        # Password
        sshpass -p "$SSH_PASSWORD" \
            ssh $ssh_opts -o PubkeyAuthentication=no "$SSH_USER@$ip" "exit" 2>/dev/null
        result=$?
    fi

    if [ $result -eq 0 ]; then
        echo -e "${GREEN}[✓] $ip - OK${NC}"
    else
        echo -e "${RED}[✗] $ip - NOK (auth/connexion échouée)${NC}"
    fi
}

export -f check_ssh
export SSH_KEY SSH_PASSWORD SSH_PASSPHRASE SSH_USER SSH_PORT TIMEOUT
export GREEN RED YELLOW BLUE NC

echo -e "${BLUE}=== Test SSH sur les IPs de $IP_LIST ===${NC}"
echo -e "${BLUE}User: $SSH_USER | Port: $SSH_PORT${NC}"
echo ""

# Lance les checks en parallèle
grep -v '^\s*#\|^\s*$' "$IP_LIST" | xargs -I {} -P 20 bash -c 'check_ssh "$@"' _ {}

echo ""
echo -e "${BLUE}=== Terminé ===${NC}"
