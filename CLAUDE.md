# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PEMLY is a Django web application that provides a user-friendly frontend for CloudFlare's CFSSL PKI toolkit. It enables organizations to build and manage their own Certificate Authority with hierarchical CA support, RBAC, and certificate lifecycle management.

## Development Commands

### Local Development Setup
```bash
# Create and activate virtual environment
python -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
npm install

# Configure environment (copy .env.example to .env and set DJANGO_SECRET_KEY, ENCRYPTION_KEY)

# Initialize database
python manage.py migrate
python manage.py createsuperuser

# Build Tailwind CSS
npm run tailwind:build          # One-time build
npm run tailwind:watch          # Development with live reload
npm run tailwind:prod           # Production (minified)

# Run development server (CFSSL auto-starts via CFSSL_AUTO_START=true)
python manage.py runserver
```

### Docker Commands
```bash
make dev-build          # Start development mode with rebuild
make up-build           # Start production mode with rebuild
make down               # Stop containers
make logs               # Follow app logs
make shell              # Access container shell
make migrate            # Run database migrations
make createsuperuser    # Create Django superuser
```

### Management Commands
```bash
# Send certificate expiration warnings (run daily via cron)
python manage.py send_expiration_warnings
python manage.py send_expiration_warnings --dry-run   # Preview without sending
```

## Architecture

### Tech Stack
- **Backend:** Django 5.x with Django REST Framework
- **Frontend:** Django Templates with Tailwind CSS
- **Database:** SQLite (dev) / PostgreSQL (prod) via `dj-database-url`
- **PKI Backend:** CloudFlare CFSSL (HTTP API for key generation, CLI for signing)
- **Encryption:** Fernet (AES-128-CBC) for private keys at rest

### Core Apps

**`core/`** - Main PKI functionality
- `models.py` - CertificateAuthority, Certificate, PendingCertificateRequest, AuditLog, APIKey, AppSettings, CertificateProfile
- `services/cfssl.py` - CFSSLClient class that wraps CFSSL HTTP API and CLI
- `cfssl.py` - Higher-level certificate issuance helper functions
- `permissions.py` - RBAC permission mixins and helper functions
- `api_views.py` - REST API ViewSets for certificates, CAs, requests
- `api_urls.py` - DRF router configuration
- `views/` - Web interface views (ca.py, certificates.py, approvals.py, settings.py, etc.)

**`accounts/`** - User management
- `models.py` - UserProfile with Role enum (super_admin, administrator, certificate_manager, certificate_requester, auditor)
- Auto-creates UserProfile on User creation via post_save signal

### Settings Structure
- `pkife/settings/base.py` - Common settings
- `pkife/settings/development.py` - DEBUG=True, SQLite
- `pkife/settings/production.py` - DEBUG=False, PostgreSQL, WhiteNoise

### Key Design Patterns

**RBAC Permission System:**
- Permission mixins in `core/permissions.py` (e.g., `CanManageCertificatesMixin`, `SuperAdminRequiredMixin`)
- Template context via `add_permission_context` processor
- Max 2 Super Admins enforced at model level

**Certificate Workflow:**
1. Direct issuance: Managers use `CFSSLClient.generate_key()` + `CFSSLClient.sign()`
2. CSR approval: Requesters submit CSRs → Managers approve → `issue_certificate_from_csr()`

**Private Key Encryption:**
- All models with private keys have `set_private_key()` / `get_private_key()` methods
- Uses `ENCRYPTION_KEY` env var with Fernet encryption

### REST API
- Base URL: `/api/v1/`
- Documentation: `/api/docs/` (Swagger UI) and `/api/schema/` (OpenAPI)
- Authentication: `ApiKey pemly_<prefix>_<secret>` header or session
- ViewSets: CertificateViewSet, CertificateAuthorityViewSet, PendingCertificateRequestViewSet, APIKeyViewSet

### URL Structure
- `/` - Core web interface (`core/urls.py`)
- `/accounts/` - Authentication and user management
- `/api/v1/` - REST API endpoints
- `/admin/` - Django admin

## Testing

The project uses Django's test framework. Tests are located in standard Django test locations within each app.

## Environment Variables

Key variables (see `.env.example`):
- `DJANGO_SECRET_KEY` - Django secret key (required)
- `ENCRYPTION_KEY` - Fernet key for encrypting private keys (required)
- `CFSSL_API_URL` - CFSSL server URL (default: http://localhost:8888)
- `CFSSL_AUTO_START` - Auto-start CFSSL with Django (default: true)
- `DATABASE_URL` - Database connection string
