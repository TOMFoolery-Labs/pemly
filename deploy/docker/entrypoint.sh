#!/bin/bash
# Entrypoint for the Pemly app container.
#
# Only the `app` service uses this; the `cfssl` service overrides the entrypoint so
# that it does not also try to run migrations.
set -euo pipefail

log() { echo "[pemly-entrypoint] $*"; }

# -----------------------------------------------------------------------------
# Wait for the database
# -----------------------------------------------------------------------------
# compose already gates on the db healthcheck, but an external DATABASE_URL has no
# such gate, and Postgres accepts connections slightly before it accepts queries.
if [[ "${DATABASE_URL:-}" == postgres* ]]; then
    log "Waiting for PostgreSQL..."
    for attempt in $(seq 1 60); do
        if python -c "
import os, sys
import psycopg
try:
    psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=3).close()
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            log "PostgreSQL is ready"
            break
        fi
        if [[ "${attempt}" -eq 60 ]]; then
            log "ERROR: PostgreSQL did not become ready within 60s"
            exit 1
        fi
        sleep 1
    done
fi

# -----------------------------------------------------------------------------
# Migrations
# -----------------------------------------------------------------------------
log "Running database migrations..."
python manage.py migrate --noinput

# -----------------------------------------------------------------------------
# First-run administrator
# -----------------------------------------------------------------------------
# Only ever runs on a genuinely empty install. Once any user exists this is a no-op,
# so it cannot reset a password or resurrect a deleted account on later restarts.
if [[ "${PEMLY_CREATE_ADMIN:-true}" == "true" ]]; then
    python <<'PYTHON'
import os
import secrets
import sys

import django

django.setup()

from django.contrib.auth.models import User  # noqa: E402

if User.objects.exists():
    sys.exit(0)

username = os.environ.get('PEMLY_ADMIN_USERNAME', 'admin')
email = os.environ.get('PEMLY_ADMIN_EMAIL', '')
password = os.environ.get('PEMLY_ADMIN_PASSWORD', '')
generated = not password

if generated:
    # url-safe(24) is ~32 chars of base64; well beyond what Django's validators want.
    password = secrets.token_urlsafe(24)

User.objects.create_superuser(username=username, email=email, password=password)

banner = '=' * 68
print(banner, flush=True)
print('  Pemly: created the first administrator account', flush=True)
print(f'  username: {username}', flush=True)
if generated:
    print(f'  password: {password}', flush=True)
    print('', flush=True)
    print('  This password is shown once and is not stored anywhere else.', flush=True)
    print('  Change it after your first login.', flush=True)
else:
    print('  password: (from PEMLY_ADMIN_PASSWORD)', flush=True)
print(banner, flush=True)
PYTHON
fi

log "Starting: $*"
exec "$@"
