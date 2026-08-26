#!/bin/bash
# =============================================================================
# Migrate a systemd/bare-metal Pemly install to the container stack
# =============================================================================
# Run this on the existing Pemly host, as root:
#
#   sudo bash deploy/migrate-from-systemd.sh
#
# It dumps the existing database, stops the old services, installs the container
# stack carrying the ORIGINAL DJANGO_SECRET_KEY and ENCRYPTION_KEY across, then
# restores the dump.
#
# ENCRYPTION_KEY is the critical value: every CA and certificate private key in
# the database is Fernet-encrypted with it (core/models.py). Without the original
# key the dump restores but every private key is unreadable, so this script
# refuses to run if it cannot find one.
#
# Nothing is deleted. The old tree is moved aside, not removed.
# =============================================================================
set -euo pipefail

OLD_DIR="${OLD_DIR:-/opt/pemly}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/pemly}"
STAMP="$(date +%Y%m%d%H%M%S)"
DUMP_FILE="${BACKUP_ROOT}/pemly-${STAMP}.sql"
ARCHIVED_DIR="${OLD_DIR}.pre-docker.${STAMP}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()         { log_error "$*"; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Run this as root (sudo)."
[[ -f "${OLD_DIR}/.env" ]] || die "No ${OLD_DIR}/.env found - is this the Pemly host?"

# -----------------------------------------------------------------------------
# Read the values that must survive
# -----------------------------------------------------------------------------
read_env() {
    # Deliberately not `source`: the old .env may contain values with spaces or
    # characters that would be word-split or executed.
    grep -E "^$1=" "${OLD_DIR}/.env" | tail -n1 | cut -d= -f2- || true
}

OLD_SECRET_KEY="$(read_env DJANGO_SECRET_KEY)"
OLD_ENCRYPTION_KEY="$(read_env ENCRYPTION_KEY)"
OLD_DATABASE_URL="$(read_env DATABASE_URL)"
OLD_ALLOWED_HOSTS="$(read_env DJANGO_ALLOWED_HOSTS)"

[[ -n "${OLD_ENCRYPTION_KEY}" ]] || die \
    "ENCRYPTION_KEY is missing from ${OLD_DIR}/.env. Stopping: without it every stored
     private key would be permanently unreadable after the move. Restore the original
     .env first."
[[ -n "${OLD_SECRET_KEY}" ]]  || die "DJANGO_SECRET_KEY is missing from ${OLD_DIR}/.env."
[[ -n "${OLD_DATABASE_URL}" ]] || die "DATABASE_URL is missing from ${OLD_DIR}/.env."

DOMAIN="${DOMAIN:-$(echo "${OLD_ALLOWED_HOSTS}" | cut -d, -f1)}"
[[ -n "${DOMAIN}" ]] || die "Could not determine the domain; re-run with DOMAIN=<fqdn>."

log_info "Domain:         ${DOMAIN}"
log_info "Old install:    ${OLD_DIR}"
log_info "Database dump:  ${DUMP_FILE}"
echo
log_warn "This stops the existing pemly and nginx services."
read -r -p "Type 'yes' to continue: " reply < /dev/tty
[[ "${reply}" == "yes" ]] || { log_info "Cancelled"; exit 0; }

# -----------------------------------------------------------------------------
# Dump the database first, while everything still works
# -----------------------------------------------------------------------------
command -v pg_dump &>/dev/null || die "pg_dump not found. Install postgresql-client and re-run."
install -d -m 0700 "${BACKUP_ROOT}"

log_info "Dumping the database..."
# --no-owner / --no-acl so the dump restores cleanly as the container's pemly role.
pg_dump --no-owner --no-acl --clean --if-exists -d "${OLD_DATABASE_URL}" -f "${DUMP_FILE}"
chmod 600 "${DUMP_FILE}"
log_success "Dumped $(wc -l < "${DUMP_FILE}") lines to ${DUMP_FILE}"

# -----------------------------------------------------------------------------
# Stop the old stack
# -----------------------------------------------------------------------------
log_info "Stopping the old services..."
systemctl disable --now pemly 2>/dev/null || log_warn "pemly service was not running"
# nginx is left installed but stopped: the container stack binds :80 and :443.
systemctl disable --now nginx 2>/dev/null || log_warn "nginx was not running"

log_info "Archiving ${OLD_DIR} to ${ARCHIVED_DIR}..."
mv "${OLD_DIR}" "${ARCHIVED_DIR}"

# -----------------------------------------------------------------------------
# Install the container stack
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/install.sh" ]]; then
    INSTALLER="${SCRIPT_DIR}/install.sh"
else
    INSTALLER="$(mktemp)"
    curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/install.sh -o "${INSTALLER}"
fi

log_info "Installing the container stack..."
# --tls selfsigned keeps the site reachable immediately; issue or install a real
# certificate afterwards.
bash "${INSTALLER}" --domain "${DOMAIN}" --tls selfsigned --non-interactive

COMPOSE_DIR="/opt/pemly/deploy/docker"
[[ -f "${COMPOSE_DIR}/.env" ]] || die "Installation did not produce ${COMPOSE_DIR}/.env"

# -----------------------------------------------------------------------------
# Carry the original keys across
# -----------------------------------------------------------------------------
log_info "Restoring the original secret and encryption keys..."
(cd "${COMPOSE_DIR}" && docker compose down)

python3 - "$COMPOSE_DIR/.env" "$OLD_SECRET_KEY" "$OLD_ENCRYPTION_KEY" <<'PY'
import sys

env_path, secret_key, encryption_key = sys.argv[1], sys.argv[2], sys.argv[3]
replacements = {
    'DJANGO_SECRET_KEY': secret_key,
    'ENCRYPTION_KEY': encryption_key,
}
lines = []
for line in open(env_path).read().splitlines():
    key = line.split('=', 1)[0]
    if key in replacements:
        line = f'{key}={replacements.pop(key)}'
    lines.append(line)
for key, value in replacements.items():
    lines.append(f'{key}={value}')
open(env_path, 'w').write('\n'.join(lines) + '\n')
PY

grep -q "^ENCRYPTION_KEY=${OLD_ENCRYPTION_KEY}$" "${COMPOSE_DIR}/.env" \
    || die "Failed to write the original ENCRYPTION_KEY into ${COMPOSE_DIR}/.env"
log_success "Original keys carried over"

# -----------------------------------------------------------------------------
# Restore the dump
# -----------------------------------------------------------------------------
cd "${COMPOSE_DIR}"

log_info "Starting the database..."
docker compose up -d db
for attempt in $(seq 1 60); do
    if docker compose exec -T db pg_isready -U pemly -d pemly &>/dev/null; then break; fi
    [[ "${attempt}" -eq 60 ]] && die "Database did not become ready"
    sleep 1
done

log_info "Restoring the dump..."
docker compose exec -T db psql -v ON_ERROR_STOP=0 -U pemly -d pemly < "${DUMP_FILE}" >/dev/null

log_info "Starting the rest of the stack..."
docker compose up -d

# -----------------------------------------------------------------------------
# Verify the encrypted material actually decrypts
# -----------------------------------------------------------------------------
log_info "Verifying that stored private keys still decrypt..."
for attempt in $(seq 1 30); do
    if docker compose exec -T app python -c "print('ready')" &>/dev/null; then break; fi
    sleep 2
done

if docker compose exec -T app python - <<'PY'
import sys

import django
django.setup()

from core.models import CertificateAuthority

cas = list(CertificateAuthority.objects.exclude(private_key_pem_encrypted=''))
if not cas:
    print("No CAs with stored private keys; nothing to verify.")
    sys.exit(0)

for ca in cas:
    key = ca.get_private_key()
    if 'PRIVATE KEY' not in key:
        print(f"FAILED to decrypt the private key for CA '{ca.name}'")
        sys.exit(1)
    print(f"  ok  {ca.name}")
print(f"Decrypted {len(cas)} CA private key(s).")
PY
then
    log_success "Migration complete."
else
    log_error "Stored private keys did NOT decrypt."
    log_error "The old install is intact at ${ARCHIVED_DIR} and the dump at ${DUMP_FILE}."
    log_error "Check that ENCRYPTION_KEY in ${COMPOSE_DIR}/.env matches the original."
    exit 1
fi

echo
log_info "Old install archived at: ${ARCHIVED_DIR}"
log_info "Database dump kept at:   ${DUMP_FILE}"
log_info "Pemly is now at:         https://${DOMAIN}"
echo
log_info "The site is on a self-signed certificate. To use Pemly's own CA instead:"
log_info "  ${COMPOSE_DIR}/bootstrap.sh issue-cert"
log_info "Once you are satisfied, remove the old tree: rm -rf ${ARCHIVED_DIR}"
