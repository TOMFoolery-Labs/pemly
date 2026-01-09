#!/bin/bash
# =============================================================================
# Pemly Automated Installation Script
# =============================================================================
# This script automates the installation of Pemly on Linux systems with systemd.
# Supports: Debian/Ubuntu, RHEL/Rocky/AlmaLinux/Fedora
#
# Usage:
#   sudo ./install.sh [OPTIONS]
#
# Options:
#   --no-ssl          Skip Let's Encrypt SSL setup (HTTP only)
#   --skip-deps       Skip system dependency installation
#   --skip-db         Skip database setup (use existing database)
#   --skip-nginx      Skip nginx configuration
#   --non-interactive Run without prompts (requires env vars or defaults)
#   --force           Force fresh clone even if directory exists (preserves .env)
#   --uninstall       Remove Pemly installation
#   -h, --help        Show this help message
# =============================================================================

set -e

# =============================================================================
# Configuration
# =============================================================================
PEMLY_USER="pemly"
PEMLY_GROUP="pemly"
INSTALL_DIR="/opt/pemly"
VENV_DIR="${INSTALL_DIR}/venv"
STORAGE_DIR="${INSTALL_DIR}/storage/certificates"
CFSSL_VERSION="1.6.5"
REPO_URL="https://github.com/TOMFoolery-Labs/pemly.git"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

die() {
    log_error "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        OS_NAME="${PRETTY_NAME}"
    else
        die "Cannot detect OS. /etc/os-release not found."
    fi

    case "${OS_ID}" in
        ubuntu|debian)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt update"
            PKG_INSTALL="apt install -y"
            NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
            NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
            ;;
        rhel|rocky|almalinux|centos|fedora)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf check-update || true"
            PKG_INSTALL="dnf install -y"
            NGINX_SITES_AVAILABLE="/etc/nginx/conf.d"
            NGINX_SITES_ENABLED="/etc/nginx/conf.d"
            ;;
        *)
            die "Unsupported OS: ${OS_ID}. Supported: debian, ubuntu, rhel, rocky, almalinux, centos, fedora"
            ;;
    esac

    log_info "Detected OS: ${OS_NAME}"
}

check_interactive() {
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        return 1
    fi
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        log_error "No interactive terminal available."
        log_error "When running via 'curl | bash', use --non-interactive flag"
        log_error "or download and run the script directly."
        exit 1
    fi
    return 0
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-y}"

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        [[ "${default}" == "y" ]]
        return $?
    fi

    local yn
    if [[ "${default}" == "y" ]]; then
        echo -n "${prompt} [Y/n]: "
        read -r yn < /dev/tty || yn=""
        yn="${yn:-y}"
    else
        echo -n "${prompt} [y/N]: "
        read -r yn < /dev/tty || yn=""
        yn="${yn:-n}"
    fi

    [[ "${yn}" =~ ^[Yy] ]]
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        eval "${var_name}=\"${default}\""
        return
    fi

    local input
    echo -n "${prompt} [${default}]: "
    read -r input < /dev/tty || input=""
    eval "${var_name}=\"${input:-${default}}\""
}

prompt_secret() {
    local prompt="$1"
    local var_name="$2"

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        eval "${var_name}=\"\""
        return
    fi

    local input
    echo -n "${prompt}: "
    read -rs input < /dev/tty || input=""
    echo
    eval "${var_name}=\"${input}\""
}

generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(50))"
}

# =============================================================================
# Installation Functions
# =============================================================================

install_system_deps() {
    log_info "Installing system dependencies..."

    ${PKG_UPDATE}

    case "${PKG_MANAGER}" in
        apt)
            ${PKG_INSTALL} \
                python3 \
                python3-venv \
                python3-pip \
                python3-dev \
                build-essential \
                libpq-dev \
                postgresql \
                postgresql-contrib \
                nginx \
                git \
                curl \
                rsync \
                nodejs \
                npm
            ;;
        dnf)
            ${PKG_INSTALL} \
                python3 \
                python3-devel \
                python3-pip \
                gcc \
                libpq-devel \
                postgresql-server \
                postgresql-contrib \
                nginx \
                git \
                curl \
                rsync \
                nodejs \
                npm

            # Initialize PostgreSQL on RHEL-based systems
            if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
                log_info "Initializing PostgreSQL database..."
                postgresql-setup --initdb || true
            fi
            ;;
    esac

    # Start and enable PostgreSQL
    systemctl enable postgresql
    systemctl start postgresql

    log_success "System dependencies installed"
}

install_cfssl() {
    log_info "Installing CFSSL ${CFSSL_VERSION}..."

    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       die "Unsupported architecture: $(uname -m)" ;;
    esac

    local base_url="https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VERSION}"

    for binary in cfssl cfssljson; do
        if [[ ! -f "/usr/local/bin/${binary}" ]]; then
            log_info "Downloading ${binary}..."
            curl -sL -o "/usr/local/bin/${binary}" \
                "${base_url}/${binary}_${CFSSL_VERSION}_linux_${arch}"
            chmod +x "/usr/local/bin/${binary}"
        else
            log_info "${binary} already installed"
        fi
    done

    # Verify installation
    /usr/local/bin/cfssl version || die "CFSSL installation failed"

    log_success "CFSSL installed"
}

create_user() {
    log_info "Creating system user '${PEMLY_USER}'..."

    if id "${PEMLY_USER}" &>/dev/null; then
        log_info "User '${PEMLY_USER}' already exists"
    else
        useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${PEMLY_USER}"
        log_success "User '${PEMLY_USER}' created"
    fi
}

install_application() {
    log_info "Installing Pemly application..."

    # Create install directory
    mkdir -p "${INSTALL_DIR}"

    # Check if we're running from the repo itself
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_root
    repo_root="$(cd "${script_dir}/../.." && pwd)"

    if [[ -f "${repo_root}/manage.py" ]] && [[ -f "${repo_root}/requirements.txt" ]]; then
        log_info "Installing from local source: ${repo_root}"

        # Copy files (excluding .git, venv, node_modules, etc.)
        rsync -a --exclude='.git' \
                 --exclude='venv' \
                 --exclude='node_modules' \
                 --exclude='*.pyc' \
                 --exclude='__pycache__' \
                 --exclude='.env' \
                 --exclude='db.sqlite3' \
                 --exclude='staticfiles' \
                 "${repo_root}/" "${INSTALL_DIR}/"
    elif [[ -d "${INSTALL_DIR}/.git" ]] && [[ "${FORCE_INSTALL}" != "true" ]]; then
        log_info "Updating existing installation..."
        cd "${INSTALL_DIR}"
        git pull
    else
        log_info "Cloning from ${REPO_URL}..."
        # Preserve .env if it exists
        local saved_env=""
        if [[ -f "${INSTALL_DIR}/.env" ]]; then
            log_info "Preserving existing .env file..."
            saved_env=$(cat "${INSTALL_DIR}/.env")
        fi
        # Remove existing directory and clone fresh
        rm -rf "${INSTALL_DIR:?}"
        git clone "${REPO_URL}" "${INSTALL_DIR}"
        # Restore .env if it was saved
        if [[ -n "${saved_env}" ]]; then
            echo "${saved_env}" > "${INSTALL_DIR}/.env"
            log_info "Restored .env file"
        fi
    fi

    chown -R "${PEMLY_USER}:${PEMLY_GROUP}" "${INSTALL_DIR}"

    log_success "Application files installed"
}

setup_python_env() {
    log_info "Setting up Python virtual environment..."

    if [[ ! -d "${VENV_DIR}" ]]; then
        sudo -u "${PEMLY_USER}" python3 -m venv "${VENV_DIR}"
    fi

    sudo -u "${PEMLY_USER}" "${VENV_DIR}/bin/pip" install --upgrade pip
    sudo -u "${PEMLY_USER}" "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

    log_success "Python environment configured"
}

build_frontend() {
    log_info "Building frontend assets..."

    cd "${INSTALL_DIR}"

    # Install npm dependencies
    sudo -u "${PEMLY_USER}" npm install

    # Build production CSS
    sudo -u "${PEMLY_USER}" npm run tailwind:prod

    log_success "Frontend assets built"
}

configure_environment() {
    log_info "Configuring environment..."

    local env_file="${INSTALL_DIR}/.env"

    if [[ -f "${env_file}" ]] && [[ "${NON_INTERACTIVE}" != "true" ]]; then
        if ! prompt_yes_no "Environment file exists. Overwrite?"; then
            log_info "Keeping existing environment configuration"
            return
        fi
    fi

    # Gather configuration
    echo
    log_info "Please provide the following configuration values:"
    echo

    prompt_input "Domain name" "pemly.example.com" DOMAIN_NAME
    prompt_input "Database host" "localhost" DB_HOST
    prompt_input "Database port" "5432" DB_PORT
    prompt_input "Database name" "pemly" DB_NAME
    prompt_input "Database user" "pemly" DB_USER
    prompt_secret "Database password (leave empty to generate)" DB_PASSWORD

    if [[ -z "${DB_PASSWORD}" ]]; then
        DB_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
        log_info "Generated database password"
    fi

    # Generate secrets
    log_info "Generating secret keys..."
    local django_secret
    django_secret=$(generate_secret_key)

    # Need cryptography installed for Fernet key generation
    local encryption_key
    encryption_key=$("${VENV_DIR}/bin/python" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    # Write environment file
    cat > "${env_file}" <<EOF
# Pemly Environment Configuration
# Generated by install.sh on $(date)

# =============================================================================
# REQUIRED SETTINGS
# =============================================================================

DJANGO_SECRET_KEY=${django_secret}
ENCRYPTION_KEY=${encryption_key}
DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
DJANGO_ALLOWED_HOSTS=${DOMAIN_NAME},localhost,127.0.0.1
CSRF_TRUSTED_ORIGINS=https://${DOMAIN_NAME},http://${DOMAIN_NAME}

# =============================================================================
# CFSSL SETTINGS
# =============================================================================

CFSSL_AUTO_START=true
CFSSL_HOST=127.0.0.1
CFSSL_PORT=8888

# =============================================================================
# OPTIONAL SETTINGS
# =============================================================================

CERTIFICATE_STORAGE_PATH=${STORAGE_DIR}
DJANGO_LOG_LEVEL=INFO
EOF

    chown "${PEMLY_USER}:${PEMLY_GROUP}" "${env_file}"
    chmod 600 "${env_file}"

    # Export for database setup
    export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD DOMAIN_NAME

    log_success "Environment configured"
}

setup_database() {
    log_info "Setting up database..."

    # Only create local database if using localhost
    if [[ "${DB_HOST}" == "localhost" ]] || [[ "${DB_HOST}" == "127.0.0.1" ]]; then
        log_info "Setting up local PostgreSQL database..."

        # Check if database exists
        if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "${DB_NAME}"; then
            log_info "Database '${DB_NAME}' already exists"
        else
            # Create database user
            sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || \
                log_info "User '${DB_USER}' may already exist"

            # Create database
            sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

            # Grant privileges
            sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"

            log_success "Database '${DB_NAME}' created"
        fi
    else
        log_info "Using external database at ${DB_HOST}"
    fi

    # Run migrations
    log_info "Running database migrations..."
    cd "${INSTALL_DIR}"
    sudo -u "${PEMLY_USER}" DJANGO_SETTINGS_MODULE=pkife.settings.production "${VENV_DIR}/bin/python" manage.py migrate

    # Create storage directory
    mkdir -p "${STORAGE_DIR}"
    chown -R "${PEMLY_USER}:${PEMLY_GROUP}" "${INSTALL_DIR}/storage"

    # Collect static files
    log_info "Collecting static files..."
    sudo -u "${PEMLY_USER}" DJANGO_SETTINGS_MODULE=pkife.settings.production "${VENV_DIR}/bin/python" manage.py collectstatic --noinput

    log_success "Database setup complete"
}

create_superuser() {
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        log_warn "Skipping admin user creation in non-interactive mode"
        log_info "Create manually: sudo -u ${PEMLY_USER} ${VENV_DIR}/bin/python ${INSTALL_DIR}/manage.py createsuperuser"
        return
    fi

    echo
    if prompt_yes_no "Create admin user now?"; then
        cd "${INSTALL_DIR}"
        # Use PYTHONUNBUFFERED to ensure prompts display immediately
        sudo -u "${PEMLY_USER}" DJANGO_SETTINGS_MODULE=pkife.settings.production PYTHONUNBUFFERED=1 "${VENV_DIR}/bin/python" manage.py createsuperuser < /dev/tty
    else
        log_info "Skipping admin user creation"
        log_info "Create later: sudo -u ${PEMLY_USER} ${VENV_DIR}/bin/python ${INSTALL_DIR}/manage.py createsuperuser"
    fi
}

install_systemd_service() {
    log_info "Installing systemd service..."

    local service_file="/etc/systemd/system/pemly.service"
    local tmpfiles_conf="/etc/tmpfiles.d/pemly.conf"

    # Copy service file
    cp "${INSTALL_DIR}/deploy/systemd/pemly.service" "${service_file}"

    # Copy tmpfiles config
    cp "${INSTALL_DIR}/deploy/systemd/pemly.tmpfiles" "${tmpfiles_conf}"

    # Create runtime directory
    systemd-tmpfiles --create "${tmpfiles_conf}"

    # Reload systemd
    systemctl daemon-reload

    # Enable and start service
    systemctl enable pemly
    systemctl start pemly

    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet pemly; then
        log_success "Pemly service started successfully"
    else
        log_error "Pemly service failed to start. Check logs: journalctl -u pemly -e"
    fi
}

configure_nginx() {
    log_info "Configuring nginx (HTTP only for initial setup)..."

    local nginx_conf

    case "${PKG_MANAGER}" in
        apt)
            nginx_conf="${NGINX_SITES_AVAILABLE}/pemly"
            ;;
        dnf)
            nginx_conf="${NGINX_SITES_AVAILABLE}/pemly.conf"
            ;;
    esac

    # Generate initial HTTP-only nginx configuration
    # SSL will be configured by certbot if --no-ssl is not specified
    cat > "${nginx_conf}" <<EOF
# Pemly Nginx Configuration
# Generated by install.sh on $(date)

upstream pemly {
    server unix:/run/pemly/gunicorn.sock fail_timeout=0;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN_NAME};

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/pemly_access.log;
    error_log /var/log/nginx/pemly_error.log;

    # Static files - served directly by nginx
    location /static/ {
        alias /opt/pemly/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Proxy to gunicorn
    location / {
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        proxy_pass http://pemly;
    }

    # Deny access to hidden files
    location ~ /\\. {
        deny all;
    }
}
EOF

    # For Debian/Ubuntu, create symlink
    if [[ "${PKG_MANAGER}" == "apt" ]]; then
        ln -sf "${nginx_conf}" "${NGINX_SITES_ENABLED}/pemly"

        # Remove default site if it exists
        rm -f "${NGINX_SITES_ENABLED}/default"
    fi

    # Add nginx user to pemly group for socket access
    usermod -aG "${PEMLY_GROUP}" nginx 2>/dev/null || \
    usermod -aG "${PEMLY_GROUP}" www-data 2>/dev/null || true

    # Test nginx configuration
    if nginx -t; then
        systemctl enable nginx
        systemctl reload nginx || systemctl start nginx
        log_success "Nginx configured"
    else
        log_error "Nginx configuration test failed"
    fi
}

setup_ssl() {
    log_info "Setting up SSL with Let's Encrypt..."

    # Install certbot
    case "${PKG_MANAGER}" in
        apt)
            ${PKG_INSTALL} certbot python3-certbot-nginx
            ;;
        dnf)
            ${PKG_INSTALL} certbot python3-certbot-nginx
            ;;
    esac

    echo
    log_warn "SSL certificate setup requires:"
    log_warn "  1. Domain '${DOMAIN_NAME}' must point to this server's IP"
    log_warn "  2. Port 80 must be accessible from the internet"
    echo

    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        log_info "Running certbot in non-interactive mode..."
        if certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --register-unsafely-without-email; then
            log_success "SSL certificate obtained and configured"
            SSL_CONFIGURED=true
        else
            log_error "Certbot failed. SSL not configured."
            log_info "You can retry manually: sudo certbot --nginx -d ${DOMAIN_NAME}"
            SSL_CONFIGURED=false
        fi
    else
        if prompt_yes_no "Proceed with Let's Encrypt certificate?"; then
            if certbot --nginx -d "${DOMAIN_NAME}"; then
                log_success "SSL certificate obtained and configured"
                SSL_CONFIGURED=true
            else
                log_error "Certbot failed. SSL not configured."
                log_info "You can retry manually: sudo certbot --nginx -d ${DOMAIN_NAME}"
                SSL_CONFIGURED=false
            fi
        else
            log_info "Skipping SSL setup"
            log_info "Run manually later: sudo certbot --nginx -d ${DOMAIN_NAME}"
            SSL_CONFIGURED=false
        fi
    fi
}

# =============================================================================
# Uninstall Function
# =============================================================================

uninstall() {
    log_warn "This will remove the Pemly installation."
    log_warn "The database will NOT be removed."
    echo

    if ! prompt_yes_no "Are you sure you want to uninstall Pemly?" "n"; then
        log_info "Uninstall cancelled"
        exit 0
    fi

    log_info "Stopping services..."
    systemctl stop pemly 2>/dev/null || true
    systemctl disable pemly 2>/dev/null || true

    log_info "Removing systemd files..."
    rm -f /etc/systemd/system/pemly.service
    rm -f /etc/tmpfiles.d/pemly.conf
    systemctl daemon-reload

    log_info "Removing nginx configuration..."
    rm -f /etc/nginx/sites-available/pemly
    rm -f /etc/nginx/sites-enabled/pemly
    rm -f /etc/nginx/conf.d/pemly.conf
    systemctl reload nginx 2>/dev/null || true

    log_info "Removing application files..."
    rm -rf "${INSTALL_DIR}"

    log_info "Removing user..."
    userdel "${PEMLY_USER}" 2>/dev/null || true

    log_success "Pemly uninstalled"
    log_info "Database '${DB_NAME:-pemly}' was NOT removed. Remove manually if needed:"
    log_info "  sudo -u postgres psql -c 'DROP DATABASE pemly;'"
}

# =============================================================================
# Main
# =============================================================================

show_help() {
    head -24 "$0" | tail -19
    exit 0
}

parse_args() {
    SKIP_DEPS=false
    SKIP_DB=false
    SKIP_NGINX=false
    SKIP_SSL=false
    NON_INTERACTIVE=false
    DO_UNINSTALL=false
    FORCE_INSTALL=false
    SSL_CONFIGURED=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-ssl)         SKIP_SSL=true ;;
            --skip-deps)      SKIP_DEPS=true ;;
            --skip-db)        SKIP_DB=true ;;
            --skip-nginx)     SKIP_NGINX=true ;;
            --non-interactive) NON_INTERACTIVE=true ;;
            --force)          FORCE_INSTALL=true ;;
            --uninstall)      DO_UNINSTALL=true ;;
            -h|--help)        show_help ;;
            *)                die "Unknown option: $1" ;;
        esac
        shift
    done
}

main() {
    echo "=============================================="
    echo "  Pemly Certificate Manager - Installation"
    echo "=============================================="
    echo

    check_root
    detect_os

    # Check if interactive input is available (unless --non-interactive)
    if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        if ! exec 3< /dev/tty 2>/dev/null; then
            log_error "No interactive terminal available for prompts."
            log_error "Options:"
            log_error "  1. Download script first: curl -O <url>/install.sh && sudo bash install.sh"
            log_error "  2. Use non-interactive mode: curl <url>/install.sh | sudo bash -s -- --non-interactive"
            exit 1
        fi
        exec 3<&-
    fi

    if [[ "${DO_UNINSTALL}" == "true" ]]; then
        uninstall
        exit 0
    fi

    # Confirm installation
    if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        echo
        log_info "This script will install Pemly to ${INSTALL_DIR}"
        echo
        if ! prompt_yes_no "Continue with installation?"; then
            log_info "Installation cancelled"
            exit 0
        fi
    fi

    # Installation steps
    if [[ "${SKIP_DEPS}" != "true" ]]; then
        install_system_deps
    fi

    install_cfssl
    create_user
    install_application
    setup_python_env
    build_frontend
    configure_environment

    if [[ "${SKIP_DB}" != "true" ]]; then
        setup_database
        create_superuser
    fi

    install_systemd_service

    if [[ "${SKIP_NGINX}" != "true" ]]; then
        configure_nginx

        if [[ "${SKIP_SSL}" != "true" ]]; then
            setup_ssl
        fi
    fi

    echo
    echo "=============================================="
    log_success "Pemly installation complete!"
    echo "=============================================="
    echo
    log_info "Service status:  sudo systemctl status pemly"
    log_info "View logs:       sudo journalctl -u pemly -f"

    if [[ "${SSL_CONFIGURED}" == "true" ]]; then
        log_info "Application URL: https://${DOMAIN_NAME:-pemly.example.com}"
        echo
        log_info "Next steps:"
        echo "  1. Access Pemly at https://${DOMAIN_NAME:-pemly.example.com}"
        echo "  2. Log in and set up your Certificate Authority"
    else
        log_info "Application URL: http://${DOMAIN_NAME:-pemly.example.com}"
        echo
        log_info "Next steps:"
        echo "  1. Access Pemly at http://${DOMAIN_NAME:-pemly.example.com}"
        echo "  2. Log in and set up your Certificate Authority"
        if [[ "${SKIP_SSL}" != "true" ]]; then
            echo "  3. To enable HTTPS: sudo certbot --nginx -d ${DOMAIN_NAME:-pemly.example.com}"
        fi
    fi
    echo
}

parse_args "$@"
main
