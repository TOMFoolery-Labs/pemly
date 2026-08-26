#!/bin/bash
# =============================================================================
# Pemly Certificate Manager - Installer
# =============================================================================
# Installs Docker if it is missing, fetches the Pemly compose stack, generates
# secrets, and starts it.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/install.sh | sudo bash
#
# Options:
#   --domain <fqdn>       Hostname Pemly is served on (prompted if omitted)
#   --tls <mode>          selfsigned (default) | acme-dns | file | pemly
#   --acme-email <email>  Contact address for ACME  (required for --tls acme-dns)
#   --acme-provider <id>  lego DNS provider id      (required for --tls acme-dns)
#   --external-db         Use an existing PostgreSQL server instead of the bundled one
#   --dir <path>          Install location (default /opt/pemly)
#   --ref <git-ref>       Branch or tag to install from (default main)
#   --upgrade             Pull the latest images and restart
#   --uninstall           Stop Pemly and remove the install directory
#   --non-interactive     Never prompt
#   -h, --help            Show this help
#
# Everything Pemly needs to run lives in containers, so this script does not
# install Python, Node, PostgreSQL, nginx, certbot or CFSSL on the host.
# =============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/pemly}"
REPO_URL="${PEMLY_REPO_URL:-https://github.com/TOMFoolery-Labs/pemly}"
GIT_REF="main"

DOMAIN=""
TLS_MODE="selfsigned"
ACME_EMAIL=""
ACME_PROVIDER=""
EXTERNAL_DB="false"
NON_INTERACTIVE="false"
DO_UPGRADE="false"
DO_UNINSTALL="false"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()         { log_error "$*"; exit 1; }

# =============================================================================
# Preflight
# =============================================================================
check_root() {
    [[ "${EUID}" -eq 0 ]] || die "This script must be run as root (use sudo)."
}

detect_os() {
    [[ -f /etc/os-release ]] || die "Cannot detect the operating system (/etc/os-release missing)."
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID}"
    log_info "Detected ${PRETTY_NAME:-${ID}}"
}

prompt_input() {
    local prompt="$1" default="$2" __var="$3" reply
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        printf -v "${__var}" '%s' "${default}"
        return
    fi
    read -r -p "${prompt} [${default}]: " reply < /dev/tty
    printf -v "${__var}" '%s' "${reply:-${default}}"
}

# =============================================================================
# Docker
# =============================================================================
install_docker() {
    if command -v docker &>/dev/null && docker compose version &>/dev/null; then
        log_info "Docker with the Compose v2 plugin is already installed"
        return
    fi

    log_info "Installing Docker..."
    case "${OS_ID}" in
        ubuntu|debian|raspbian|linuxmint|pop|rhel|centos|rocky|almalinux|fedora)
            # get.docker.com is Docker's own installer; it configures the apt/dnf
            # repository, the signing key and the compose plugin on all of these.
            curl -fsSL https://get.docker.com | sh
            ;;
        *)
            die "Unsupported distribution '${OS_ID}'. Install Docker manually, then re-run this script."
            ;;
    esac

    systemctl enable --now docker

    command -v docker &>/dev/null || die "Docker installation failed."
    docker compose version &>/dev/null \
        || die "The Docker Compose v2 plugin is missing after installation."
    log_success "Docker installed"
}

# =============================================================================
# Application files
# =============================================================================
fetch_application() {
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log_info "Updating existing checkout in ${INSTALL_DIR}..."
        git -C "${INSTALL_DIR}" fetch --depth 1 origin "${GIT_REF}"
        git -C "${INSTALL_DIR}" checkout -f FETCH_HEAD
    else
        command -v git &>/dev/null || die "git is required. Install it and re-run."
        [[ ! -e "${INSTALL_DIR}" ]] || die "${INSTALL_DIR} exists but is not a git checkout. Move it aside first."
        log_info "Cloning Pemly into ${INSTALL_DIR}..."
        git clone --depth 1 --branch "${GIT_REF}" "${REPO_URL}" "${INSTALL_DIR}"
    fi

    # .env lives under here and holds the encryption key.
    chmod 0700 "${INSTALL_DIR}"
}

# =============================================================================
# Actions
# =============================================================================
compose_dir() { echo "${INSTALL_DIR}/deploy/docker"; }

do_install() {
    check_root
    detect_os
    install_docker
    fetch_application

    local dir; dir="$(compose_dir)"

    if [[ ! -f "${dir}/.env" ]]; then
        [[ -n "${DOMAIN}" ]] || prompt_input "Domain name Pemly will be served on" "pemly.example.com" DOMAIN
        [[ -n "${DOMAIN}" ]] || die "A domain name is required."

        local args=(init --domain "${DOMAIN}" --tls "${TLS_MODE}")
        [[ -n "${ACME_EMAIL}" ]]         && args+=(--acme-email "${ACME_EMAIL}")
        [[ -n "${ACME_PROVIDER}" ]]      && args+=(--acme-provider "${ACME_PROVIDER}")
        [[ "${EXTERNAL_DB}" == "true" ]] && args+=(--external-db)

        "${dir}/bootstrap.sh" "${args[@]}"
    else
        log_info "Existing ${dir}/.env found; keeping current configuration"
        DOMAIN="$(grep -E '^PEMLY_DOMAIN=' "${dir}/.env" | cut -d= -f2- || true)"
    fi

    if [[ "${TLS_MODE}" == "acme-dns" ]] && [[ ! -s "${dir}/.env.dns" ]]; then
        log_warn "Add your DNS provider credentials to ${dir}/.env.dns, then run:"
        log_warn "  ${dir}/bootstrap.sh up"
        exit 0
    fi

    "${dir}/bootstrap.sh" up

    echo
    echo "=============================================="
    log_success "Pemly installation complete"
    echo "=============================================="
    echo
    log_info "URL:      https://${DOMAIN}"
    log_info "Logs:     ${dir}/bootstrap.sh logs"
    log_info "Upgrade:  ${dir}/bootstrap.sh upgrade"
    echo
    log_info "Next steps:"
    echo "  1. Find the generated admin password:"
    echo "       ${dir}/bootstrap.sh logs app | grep -A4 'first administrator'"
    echo "  2. Log in and set up your Certificate Authority"
    if [[ "${TLS_MODE}" != "acme-dns" ]]; then
        echo "  3. Replace the self-signed certificate, either with your own:"
        echo "       ${dir}/bootstrap.sh install-cert cert.pem key.pem"
        echo "     or one issued by Pemly itself, once the CA exists:"
        echo "       cd ${dir} && docker compose exec app python manage.py issue_web_cert"
    fi
    echo
}

do_upgrade() {
    check_root
    [[ -d "${INSTALL_DIR}/.git" ]] || die "Pemly is not installed at ${INSTALL_DIR}."
    fetch_application
    "$(compose_dir)/bootstrap.sh" upgrade
    log_success "Upgrade complete"
}

do_uninstall() {
    check_root
    local dir; dir="$(compose_dir)"

    if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        echo
        log_warn "This stops Pemly and deletes ${INSTALL_DIR}."
        log_warn "Database and certificate volumes are NOT removed; remove them with:"
        log_warn "  docker volume rm pemly_pemly_pgdata pemly_pemly_certs"
        read -r -p "Type 'yes' to continue: " reply < /dev/tty
        [[ "${reply}" == "yes" ]] || { log_info "Cancelled"; exit 0; }
    fi

    if [[ -f "${dir}/compose.yml" ]]; then
        (cd "${dir}" && docker compose down) || log_warn "Could not stop the stack; continuing"
    fi

    # The encryption key is unrecoverable and every stored private key depends on
    # it, so keep a copy rather than deleting it along with the rest of the tree.
    if [[ -f "${dir}/.env" ]]; then
        local keep="/root/pemly-env-backup-$(date +%Y%m%d%H%M%S)"
        cp "${dir}/.env" "${keep}"
        chmod 600 "${keep}"
        log_warn "Saved ${keep} (contains ENCRYPTION_KEY, needed to read the database volume)"
    fi

    rm -rf "${INSTALL_DIR}"
    log_success "Pemly removed"
}

show_help() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

# =============================================================================
# Args
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)          DOMAIN="$2"; shift 2 ;;
        --tls)             TLS_MODE="$2"; shift 2 ;;
        --acme-email)      ACME_EMAIL="$2"; shift 2 ;;
        --acme-provider)   ACME_PROVIDER="$2"; shift 2 ;;
        --external-db)     EXTERNAL_DB="true"; shift ;;
        --dir)             INSTALL_DIR="$2"; shift 2 ;;
        --ref)             GIT_REF="$2"; shift 2 ;;
        --upgrade)         DO_UPGRADE="true"; shift ;;
        --uninstall)       DO_UNINSTALL="true"; shift ;;
        --non-interactive) NON_INTERACTIVE="true"; shift ;;
        -h|--help)         show_help; exit 0 ;;
        *)                 die "Unknown option '$1' (try --help)" ;;
    esac
done

echo "=============================================="
echo "  Pemly Certificate Manager"
echo "=============================================="
echo

if [[ "${DO_UNINSTALL}" == "true" ]]; then
    do_uninstall
elif [[ "${DO_UPGRADE}" == "true" ]]; then
    do_upgrade
else
    do_install
fi
