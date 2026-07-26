#!/usr/bin/env bash

################################################################################
# Script d'installation de Ghostwriter (SpecterOps) via Docker
# Ghostwriter : plateforme de gestion d'engagements de pentest/red team
# Compatible : Debian / Ubuntu / Kali Linux / Fedora / Arch
################################################################################

set -euo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
GHOSTWRITER_DIR="${HOME}/ghostwriter"
REPO_URL="https://github.com/GhostManager/Ghostwriter.git"
DOCKER_GROUP_ADDED="false"

################################################################################
# Fonctions utilitaires
################################################################################

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERREUR]${NC} $1"; }

# Vérifie que le script n'est pas lancé en root
check_not_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        log_warn "Il est déconseillé de lancer ce script en root."
        read -rp "Continuer quand même ? (y/N) : " answer
        [[ "${answer,,}" == "y" ]] || exit 1
    fi
}

# Détecte le gestionnaire de paquets
detect_package_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
    else
        log_error "Gestionnaire de paquets non supporté."
        exit 1
    fi
    log_info "Gestionnaire de paquets détecté : ${PKG_MANAGER}"
}

# Détecte la distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_ID_LIKE="${ID_LIKE:-}"
        DISTRO_CODENAME="${VERSION_CODENAME:-}"
    else
        DISTRO_ID="unknown"
        DISTRO_ID_LIKE=""
        DISTRO_CODENAME=""
    fi
    log_info "Distribution détectée : ${DISTRO_ID}"
}

################################################################################
# Nettoyage préalable des dépôts Docker mal configurés (ex: kali-rolling)
################################################################################

cleanup_bad_docker_repo() {
    log_info "Vérification des dépôts Docker existants..."

    local bad_files
    bad_files=$(grep -rl "download.docker.com" \
        /etc/apt/sources.list.d/ /etc/apt/sources.list 2>/dev/null || true)

    if [[ -n "${bad_files}" ]]; then
        if echo "${bad_files}" | xargs grep -l "kali-rolling" &>/dev/null; then
            log_warn "Dépôt Docker invalide (kali-rolling) détecté. Suppression..."
        fi
        sudo rm -f /etc/apt/sources.list.d/docker.list
        log_success "Ancien dépôt Docker nettoyé."
    else
        log_info "Aucun dépôt Docker à nettoyer."
    fi
}

################################################################################
# Installation des dépendances de base
################################################################################

install_dependencies() {
    log_info "Installation des dépendances de base (git, curl)..."
    case "${PKG_MANAGER}" in
        apt)
            sudo apt-get update -qq
            sudo apt-get install -y git curl ca-certificates gnupg lsb-release
            ;;
        dnf|yum)
            sudo "${PKG_MANAGER}" install -y git curl ca-certificates
            ;;
        pacman)
            sudo pacman -Sy --noconfirm git curl ca-certificates
            ;;
    esac
    log_success "Dépendances de base installées."
}

################################################################################
# Installation de Docker
################################################################################

# Détermine le codename Debian à utiliser (Kali -> bookworm)
get_debian_codename() {
    case "${DISTRO_ID}" in
        kali)
            echo "bookworm"
            ;;
        debian)
            # Si testing/sid ou codename inconnu du dépôt Docker, fallback bookworm
            case "${DISTRO_CODENAME}" in
                bookworm|bullseye|buster) echo "${DISTRO_CODENAME}" ;;
                *) echo "bookworm" ;;
            esac
            ;;
        *)
            echo "${DISTRO_CODENAME:-bookworm}"
            ;;
    esac
}

install_docker() {
    if command -v docker &>/dev/null && docker --version &>/dev/null; then
        log_success "Docker est déjà installé ($(docker --version))."
    else
        log_info "Installation de Docker..."

        case "${PKG_MANAGER}" in
            apt)
                # Distinction : Debian ou Ubuntu comme base du dépôt
                local docker_distro="debian"
                if [[ "${DISTRO_ID}" == "ubuntu" ]] || echo "${DISTRO_ID_LIKE}" | grep -q "ubuntu"; then
                    docker_distro="ubuntu"
                fi

                local codename
                codename=$(get_debian_codename)
                log_info "Dépôt Docker : ${docker_distro} / ${codename}"

                # Clé GPG officielle Docker
                sudo install -m 0755 -d /etc/apt/keyrings
                sudo curl -fsSL "https://download.docker.com/linux/${docker_distro}/gpg" \
                    -o /etc/apt/keyrings/docker.asc
                sudo chmod a+r /etc/apt/keyrings/docker.asc

                # Ajout du dépôt avec le bon codename
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${docker_distro} ${codename} stable" \
                    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

                sudo apt-get update -qq
                sudo apt-get install -y \
                    docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin
                ;;
            dnf|yum)
                sudo "${PKG_MANAGER}" -y install dnf-plugins-core || true
                sudo "${PKG_MANAGER}" config-manager --add-repo \
                    https://download.docker.com/linux/fedora/docker-ce.repo || true
                sudo "${PKG_MANAGER}" install -y \
                    docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin
                ;;
            pacman)
                sudo pacman -Sy --noconfirm docker docker-compose docker-buildx
                ;;
        esac
        log_success "Docker installé ($(docker --version))."
    fi

    # Activer le service Docker
    if command -v systemctl &>/dev/null; then
        sudo systemctl enable --now docker || true
    fi

    # Ajouter l'utilisateur au groupe docker
    if ! groups "${USER}" | grep -qw docker; then
        log_info "Ajout de ${USER} au groupe docker..."
        sudo usermod -aG docker "${USER}"
        DOCKER_GROUP_ADDED="true"
        log_warn "Vous devrez vous reconnecter (ou 'newgrp docker') pour utiliser docker sans sudo."
    fi
}

# Exécute une commande docker en gérant le cas "groupe pas encore actif"
run_docker_cmd() {
    if [[ "${DOCKER_GROUP_ADDED}" == "true" ]] && ! groups | grep -qw docker; then
        sg docker -c "$*"
    else
        eval "$@"
    fi
}

################################################################################
# Vérification de Docker Compose v2
################################################################################

check_docker_compose() {
    log_info "Vérification de Docker Compose v2..."
    if run_docker_cmd "docker compose version" &>/dev/null; then
        log_success "Docker Compose v2 disponible."
    else
        log_error "Docker Compose v2 (plugin) introuvable. Ghostwriter en a besoin."
        log_info "Tentative d'installation du plugin compose..."
        case "${PKG_MANAGER}" in
            apt) sudo apt-get install -y docker-compose-plugin ;;
            dnf|yum) sudo "${PKG_MANAGER}" install -y docker-compose-plugin ;;
            pacman) sudo pacman -Sy --noconfirm docker-compose ;;
        esac
    fi
}

################################################################################
# Clonage du dépôt Ghostwriter
################################################################################

clone_ghostwriter() {
    if [[ -d "${GHOSTWRITER_DIR}/.git" ]]; then
        log_info "Ghostwriter déjà cloné. Mise à jour..."
        git -C "${GHOSTWRITER_DIR}" pull --ff-only || \
            log_warn "Impossible de mettre à jour (modifications locales ?)."
    else
        log_info "Clonage de Ghostwriter dans ${GHOSTWRITER_DIR}..."
        git clone "${REPO_URL}" "${GHOSTWRITER_DIR}"
    fi
    log_success "Dépôt Ghostwriter prêt."
}

################################################################################
# Installation / lancement de Ghostwriter
################################################################################

run_ghostwriter_install() {
    log_info "Lancement de l'installation de Ghostwriter (peut prendre plusieurs minutes)..."
    cd "${GHOSTWRITER_DIR}"

    # Rendre le CLI exécutable
    if [[ -f "./ghostwriter-cli-linux" ]]; then
        chmod +x ./ghostwriter-cli-linux
        run_docker_cmd "./ghostwriter-cli-linux install"
    else
        log_error "ghostwriter-cli-linux introuvable dans le dépôt."
        log_info "Vérifiez la documentation officielle : https://ghostwriter.wiki"
        exit 1
    fi

    log_success "Ghostwriter installé et démarré."
}

################################################################################
# Affichage des informations finales
################################################################################

show_final_info() {
    echo
    log_success "=========================================="
    log_success " Ghostwriter est installé !"
    log_success "=========================================="
    echo
    log_info "Accès : https://127.0.0.1 (ou https://<IP_serveur>)"
    log_info "Utilisateur admin : admin"
    echo

    if [[ -f "${GHOSTWRITER_DIR}/ghostwriter-cli-linux" ]]; then
        echo -n "Mot de passe admin : "
        (cd "${GHOSTWRITER_DIR}" && \
            run_docker_cmd "./ghostwriter-cli-linux config get admin_password" 2>/dev/null) \
            || log_warn "Récupérez-le manuellement : ./ghostwriter-cli-linux config get admin_password"
    fi

    if [[ "${DOCKER_GROUP_ADDED}" == "true" ]]; then
        echo
        log_warn "IMPORTANT : reconnectez-vous ou lancez 'newgrp docker' pour utiliser docker sans sudo."
    fi
}

################################################################################
# Programme principal
################################################################################

main() {
    log_info "Démarrage de l'installation de Ghostwriter (SpecterOps)..."
    echo

    check_not_root
    detect_package_manager
    detect_distro
    cleanup_bad_docker_repo
    install_dependencies
    install_docker
    check_docker_compose
    clone_ghostwriter
    run_ghostwriter_install
    show_final_info

    log_success "Terminé."
}

main "$@"
