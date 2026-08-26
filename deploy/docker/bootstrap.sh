#!/bin/bash
# =============================================================================
# Pemly bootstrap
# =============================================================================
# Generates the secrets Pemly refuses to start without, selects the TLS mode, and
# brings the stack up.
#
#   ./bootstrap.sh                                  # init (if needed) and start
#   ./bootstrap.sh init --domain pki.example.com    # write .env only
#   ./bootstrap.sh init --tls acme-dns --domain pki.example.com \
#                       --acme-email admin@example.com --acme-provider cloudflare \
#                       --dns-env CF_DNS_API_TOKEN=...    # repeatable
#   ./bootstrap.sh install-cert ./cert.pem ./key.pem   # use a certificate you have
#   ./bootstrap.sh issue-cert                          # let Pemly's own CA issue one
#   ./bootstrap.sh up | down | logs | upgrade
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

ENV_FILE="${SCRIPT_DIR}/.env"
DNS_ENV_FILE="${SCRIPT_DIR}/.env.dns"
# Must match the PEMLY_IMAGE default in compose.yml. If they ever drift the only
# cost is building an image we could have pulled, which is cached and harmless.
DEFAULT_IMAGE="ghcr.io/tomfoolery-labs/pemly:latest"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()         { log_error "$*"; exit 1; }

# -----------------------------------------------------------------------------
# Prerequisites
# -----------------------------------------------------------------------------
require_docker() {
    command -v docker &>/dev/null || die "docker is not installed. See https://docs.docker.com/engine/install/"
    docker compose version &>/dev/null \
        || die "the Docker Compose v2 plugin is required (docker compose version)."

    # !reset / !override in compose.external-db.yml need 2.24+.
    local version
    version="$(docker compose version --short 2>/dev/null || echo 0)"
    local major="${version%%.*}"
    local minor="${version#*.}"; minor="${minor%%.*}"
    if [[ "${major}" -lt 2 ]] || { [[ "${major}" -eq 2 ]] && [[ "${minor}" -lt 24 ]]; }; then
        log_warn "Docker Compose ${version} detected; 2.24+ is recommended (needed for --external-db)."
    fi
}

# -----------------------------------------------------------------------------
# Secret generation
# -----------------------------------------------------------------------------
generate_secret_key() {
    # Django's SECRET_KEY is an opaque string; length is what matters.
    openssl rand -base64 48 | tr -d '\n='
}

generate_fernet_key() {
    # Fernet requires exactly 32 raw bytes, url-safe base64 encoded. core/models.py
    # uses this to encrypt CA private keys at rest - losing it makes every stored
    # key unrecoverable.
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
}

generate_password() {
    openssl rand -base64 24 | tr -d '/+=\n' | head -c 24
}

# -----------------------------------------------------------------------------
# init
# -----------------------------------------------------------------------------
DOMAIN=""
TLS_MODE="selfsigned"
ACME_EMAIL=""
ACME_PROVIDER=""
EXTERNAL_DB="false"
FORCE="false"
DNS_ENV_PAIRS=()

cmd_init() {
    if [[ -f "${ENV_FILE}" ]] && [[ "${FORCE}" != "true" ]]; then
        log_info "${ENV_FILE} already exists; leaving it untouched (use --force to regenerate)."
        return 0
    fi

    # --force rewrites .env. Regenerating these three would be silently
    # destructive against data that already exists: a new ENCRYPTION_KEY makes
    # every stored private key unreadable, and a new POSTGRES_PASSWORD locks the
    # app out of an existing database volume. Carry them forward.
    local carried=()
    if [[ -f "${ENV_FILE}" ]]; then
        local backup="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
        cp "${ENV_FILE}" "${backup}"
        chmod 600 "${backup}"
        log_warn "Existing .env backed up to ${backup}"

        local existing
        for key in ENCRYPTION_KEY DJANGO_SECRET_KEY POSTGRES_PASSWORD; do
            existing="$(grep -E "^${key}=" "${ENV_FILE}" | tail -n1 | cut -d= -f2- || true)"
            if [[ -n "${existing}" ]]; then
                carried+=("${key}=${existing}")
            fi
        done
        [[ ${#carried[@]} -gt 0 ]] && log_info "Preserving existing ${#carried[@]} secret(s) from the previous .env"
    fi

    [[ -n "${DOMAIN}" ]] || die "--domain is required (e.g. --domain pki.example.com)"

    case "${TLS_MODE}" in
        selfsigned|file|pemly) ;;
        acme-dns)
            [[ -n "${ACME_EMAIL}" ]]    || die "--acme-email is required with --tls acme-dns"
            [[ -n "${ACME_PROVIDER}" ]] || die "--acme-provider is required with --tls acme-dns"
            ;;
        *) die "Unknown --tls mode '${TLS_MODE}' (selfsigned|file|pemly|acme-dns)" ;;
    esac

    # COMPOSE_FILE is read by docker compose itself, so overlays stay active for a
    # plain `docker compose up -d` without anyone needing to remember -f flags.
    local compose_files="compose.yml"
    [[ "${TLS_MODE}" == "acme-dns" ]] && compose_files="${compose_files}:compose.acme-dns.yml"
    [[ "${EXTERNAL_DB}" == "true" ]]  && compose_files="${compose_files}:compose.external-db.yml"

    log_info "Generating secrets..."
    umask 077
    cat > "${ENV_FILE}" <<EOF
# Pemly configuration - generated by bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# Keep this file. ENCRYPTION_KEY in particular cannot be regenerated: it decrypts
# every CA and certificate private key stored in the database.

COMPOSE_FILE=${compose_files}

# =============================================================================
# Required
# =============================================================================
PEMLY_DOMAIN=${DOMAIN}
DJANGO_SECRET_KEY=$(generate_secret_key)
ENCRYPTION_KEY=$(generate_fernet_key)

# =============================================================================
# Database (bundled Postgres)
# =============================================================================
POSTGRES_USER=pemly
POSTGRES_DB=pemly
POSTGRES_PASSWORD=$(generate_password)
# Set DATABASE_URL to use an external server instead (see compose.external-db.yml).
#DATABASE_URL=postgres://user:pass@host:5432/pemly

# =============================================================================
# TLS: ${TLS_MODE}
# =============================================================================
EOF

    if [[ "${TLS_MODE}" == "acme-dns" ]]; then
        cat >> "${ENV_FILE}" <<EOF
PEMLY_ACME_EMAIL=${ACME_EMAIL}
PEMLY_ACME_DNS_PROVIDER=${ACME_PROVIDER}
# Public resolvers are queried directly for the challenge TXT record; an internal
# resolver with a split-horizon view of the zone would never see it.
PEMLY_ACME_DNS_RESOLVERS=1.1.1.1:53,8.8.8.8:53
# Point at the staging directory while testing to avoid rate limits:
#PEMLY_ACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory

# Provider credentials go in .env.dns, which is mounted only into the proxy.
EOF
    else
        cat >> "${ENV_FILE}" <<EOF
# Mode '${TLS_MODE}': Traefik serves its built-in self-signed certificate until a
# real one is present at /certs/tls.crt. Supply one with either:
#     ./bootstrap.sh install-cert /path/cert.pem /path/key.pem
#     docker compose exec app python manage.py issue_web_cert
EOF
    fi

    cat >> "${ENV_FILE}" <<'EOF'

# =============================================================================
# Optional
# =============================================================================
#PEMLY_IMAGE=ghcr.io/tomfoolery-labs/pemly:latest
#PEMLY_HTTP_PORT=80
#PEMLY_HTTPS_PORT=443
#DJANGO_LOG_LEVEL=INFO
#PEMLY_TRAEFIK_LOG_LEVEL=INFO

# First-run administrator. Leave the password unset to have one generated and
# printed once in the container logs.
#PEMLY_ADMIN_USERNAME=admin
#PEMLY_ADMIN_EMAIL=admin@example.com
#PEMLY_ADMIN_PASSWORD=
EOF

    if [[ ${#carried[@]} -gt 0 ]]; then
        python3 - "${ENV_FILE}" "${carried[@]}" <<'PYEOF'
import sys

env_path, pairs = sys.argv[1], sys.argv[2:]
replacements = dict(pair.split('=', 1) for pair in pairs)

lines = []
for line in open(env_path).read().splitlines():
    key = line.split('=', 1)[0]
    if key in replacements:
        line = f'{key}={replacements[key]}'
    lines.append(line)
open(env_path, 'w').write('\n'.join(lines) + '\n')
PYEOF
        log_warn "ENCRYPTION_KEY, DJANGO_SECRET_KEY and POSTGRES_PASSWORD were kept."
        log_warn "To start genuinely fresh, also remove the data: docker compose down -v"
    fi

    chmod 600 "${ENV_FILE}"

    write_dns_env_file
    log_success "Wrote ${ENV_FILE}"
    if [[ "${TLS_MODE}" == "acme-dns" ]] && [[ ${#DNS_ENV_PAIRS[@]} -eq 0 ]]; then
        log_warn "Add your ${ACME_PROVIDER} credentials to ${DNS_ENV_FILE} before starting."
    fi
}

write_dns_env_file() {
    # Credentials passed via --dns-env win: they mean the caller is doing a
    # one-shot install and expects the stack to come up already enrolled.
    if [[ ${#DNS_ENV_PAIRS[@]} -gt 0 ]]; then
        umask 077
        {
            echo "# DNS provider credentials for ACME DNS-01."
            echo "# Mounted only into the traefik container."
            for pair in "${DNS_ENV_PAIRS[@]}"; do
                echo "${pair}"
            done
        } > "${DNS_ENV_FILE}"
        chmod 600 "${DNS_ENV_FILE}"
        log_info "Wrote ${#DNS_ENV_PAIRS[@]} DNS credential(s) to ${DNS_ENV_FILE}"
        return
    fi

    if [[ ! -f "${DNS_ENV_FILE}" ]]; then
        cat > "${DNS_ENV_FILE}" <<'EOF'
# DNS provider credentials for ACME DNS-01, mounted only into the traefik
# container so the proxy never sees the Django or database secrets.
#
# Use the variable names your provider expects; the full list is at
# https://go-acme.github.io/lego/dns/
#
# cloudflare:
#CF_DNS_API_TOKEN=
#
# route53:
#AWS_ACCESS_KEY_ID=
#AWS_SECRET_ACCESS_KEY=
#AWS_REGION=us-east-1
#
# rfc2136 (internal BIND / Windows DNS - usually the right choice with no public zone):
#RFC2136_NAMESERVER=ns1.internal.example.com:53
#RFC2136_TSIG_ALGORITHM=hmac-sha256.
#RFC2136_TSIG_KEY=pemly-acme
#RFC2136_TSIG_SECRET=
EOF
        chmod 600 "${DNS_ENV_FILE}"
    fi
}

# -----------------------------------------------------------------------------
# install-cert
# -----------------------------------------------------------------------------
cmd_install_cert() {
    local cert="${1:-}" key="${2:-}"
    [[ -f "${cert}" ]] || die "usage: bootstrap.sh install-cert <cert.pem> <key.pem>"
    [[ -f "${key}"  ]] || die "usage: bootstrap.sh install-cert <cert.pem> <key.pem>"

    openssl x509 -in "${cert}" -noout -subject >/dev/null 2>&1 \
        || die "${cert} does not parse as a PEM certificate"

    docker compose ps --status running --services 2>/dev/null | grep -qx app \
        || die "the app container must be running (docker compose up -d) to install a certificate"

    docker compose cp "${cert}" app:/certs/tls.crt
    docker compose cp "${key}"  app:/certs/tls.key
    # `docker compose cp` writes as root, which would leave the key world-readable
    # and stop `issue_web_cert` (running as pemly) from ever replacing these files.
    docker compose exec -u 0 -T app chown pemly:pemly /certs/tls.crt /certs/tls.key
    docker compose exec -u 0 -T app chmod 0644 /certs/tls.crt
    docker compose exec -u 0 -T app chmod 0600 /certs/tls.key

    reload_proxy
    log_success "Certificate installed."
    log_info "Verify with: openssl s_client -connect localhost:443 -servername \${PEMLY_DOMAIN} </dev/null"
}

# Traefik's file provider watches its configuration directory, but certificate files
# named in that configuration are only read when the configuration loads. A cert
# dropped in afterwards is therefore invisible until the proxy restarts.
reload_proxy() {
    log_info "Restarting the proxy to load the new certificate..."
    docker compose restart traefik
}

cmd_issue_cert() {
    docker compose ps --status running --services 2>/dev/null | grep -qx app \
        || die "the app container must be running (docker compose up -d) first"

    # Everything after `issue-cert` is passed through to the management command, so
    # --ca / --alt-name / --ip / --validity-days all work here.
    docker compose exec -T app python manage.py issue_web_cert "$@"
    reload_proxy
    log_success "Pemly issued and installed its own web certificate."
}

# -----------------------------------------------------------------------------
# lifecycle
# -----------------------------------------------------------------------------
cmd_up() {
    [[ -f "${ENV_FILE}" ]] || die "no .env found - run: ./bootstrap.sh init --domain <fqdn>"

    # compose cannot enforce this itself without also breaking `docker compose
    # build` on a checkout that has no .env yet.
    if ! grep -qE '^DATABASE_URL=.+' "${ENV_FILE}" \
       && ! grep -qE '^POSTGRES_PASSWORD=.+' "${ENV_FILE}"; then
        die "neither POSTGRES_PASSWORD nor DATABASE_URL is set in ${ENV_FILE}"
    fi
    grep -qE '^ENCRYPTION_KEY=.+' "${ENV_FILE}" \
        || die "ENCRYPTION_KEY is missing from ${ENV_FILE}; the app will refuse to start"

    ensure_image
    log_info "Starting Pemly..."
    docker compose up -d
    echo
    log_success "Pemly is starting."
    log_info "Watch the first-run admin password: docker compose logs -f app"
    # shellcheck disable=SC1090
    log_info "URL: https://$(grep -E '^PEMLY_DOMAIN=' "${ENV_FILE}" | cut -d= -f2-)"
}

# Build locally when the image cannot be pulled. Without this, `up` attempts a
# pull that fails with a bare "error from registry: denied", interleaves it with
# the progress display, and only then falls back to building - which reads as a
# fatal error even though the build is proceeding normally.
ensure_image() {
    local image
    image="$(grep -E '^PEMLY_IMAGE=' "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
    image="${image:-${DEFAULT_IMAGE}}"

    if docker image inspect "${image}" &>/dev/null; then
        return
    fi

    if docker pull --quiet "${image}" &>/dev/null; then
        log_info "Pulled ${image}"
        return
    fi

    log_info "No published image for ${image}; building it locally."
    log_info "First build takes several minutes - do not interrupt it."
    docker compose build
    log_success "Image built"
}

cmd_upgrade() {
    [[ -f "${ENV_FILE}" ]] || die "no .env found - nothing to upgrade"
    log_info "Pulling latest images..."
    docker compose pull
    docker compose up -d
    log_success "Upgrade complete (migrations ran in the app entrypoint)."
}

# -----------------------------------------------------------------------------
# args
# -----------------------------------------------------------------------------
COMMAND=""
# A bare `./bootstrap.sh --domain x` has no subcommand; only treat $1 as one when it
# is not a flag.
if [[ $# -gt 0 ]] && [[ "$1" != --* ]]; then
    COMMAND="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)        DOMAIN="$2"; shift 2 ;;
        --tls)           TLS_MODE="$2"; shift 2 ;;
        --acme-email)    ACME_EMAIL="$2"; shift 2 ;;
        --acme-provider) ACME_PROVIDER="$2"; shift 2 ;;
        --external-db)   EXTERNAL_DB="true"; shift ;;
        --dns-env)
            [[ "$2" == *=* ]] || die "--dns-env expects KEY=VALUE, got '$2'"
            DNS_ENV_PAIRS+=("$2"); shift 2 ;;
        --force)         FORCE="true"; shift ;;
        *)               break ;;
    esac
done

require_docker

case "${COMMAND}" in
    init)         cmd_init ;;
    install-cert) cmd_install_cert "$@" ;;
    issue-cert)   cmd_issue_cert "$@" ;;
    up)           cmd_up ;;
    upgrade)      cmd_upgrade ;;
    down)         docker compose down ;;
    logs)         docker compose logs -f "$@" ;;
    ""|start)     cmd_init; cmd_up ;;
    *)            die "Unknown command '${COMMAND}' (init|up|down|logs|upgrade|install-cert|issue-cert)" ;;
esac
