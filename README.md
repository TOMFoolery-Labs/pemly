# Pemly - Certificate Manager

A Django web application that serves as a user-friendly frontend for CloudFlare's CFSSL PKI toolkit. Build and manage your own Certificate Authority with a clean, modern interface.

## Features

- **Role-Based Access Control (RBAC)** - 5 user roles with granular permissions and approval workflows
- **Certificate Authority Management** - Create and manage root and intermediate CAs
- **Certificate Issuance** - Issue certificates with server-side key generation or sign existing CSRs
- **Certificate Approval Workflow** - Certificate Requesters submit CSRs for Manager approval
- **Certificate Types** - Support for Server TLS, Client Authentication, Code Signing, and Email (S/MIME)
- **Subject Alternative Names** - Add DNS names, IP addresses, and email addresses to certificates
- **Certificate Revocation** - Revoke certificates with CRL generation
- **Certificate Profiles** - Reusable templates for certificate issuance
- **Air-Gap Support** - Export/remove/restore CA private keys for offline storage
- **Backup & Restore** - Full database and certificate backup/restore functionality
- **Audit Logging** - Complete audit trail of all operations
- **Modern UI** - Clean, responsive interface built with Tailwind CSS
- **Security** - Private keys encrypted at rest using Fernet (AES-128-CBC)

## Tech Stack

- **Backend:** Django 5.x, Python 3.11+
- **Frontend:** Django Templates, Tailwind CSS
- **Database:** SQLite (development), PostgreSQL (production)
- **PKI Backend:** CloudFlare CFSSL

## Project Structure

```
pemly/
├── accounts/              # User management and authentication
│   ├── models.py          # UserProfile with RBAC roles
│   ├── forms.py           # User creation/edit forms
│   └── views.py           # Login, logout, user management views
├── core/                  # Main application
│   ├── models.py          # CA, Certificate, PendingCertificateRequest, AuditLog
│   ├── forms.py           # Certificate request forms
│   ├── cfssl.py           # CFSSL certificate issuance helper
│   ├── permissions.py     # RBAC permission mixins
│   ├── services/          # CFSSL API client
│   │   └── cfssl.py
│   ├── templatetags/      # Custom template tags
│   │   └── core_tags.py
│   └── views/             # Dashboard, CA, Certificates, Approvals, Audit views
│       ├── approvals.py   # Certificate approval workflow
│       ├── ca.py
│       ├── certificates.py
│       └── ...
├── deploy/                # Deployment configurations
│   └── docker/            # Docker deployment
│       ├── Dockerfile
│       ├── compose.yml
│       ├── compose.override.yml
│       └── entrypoint.sh
├── pkife/
│   └── settings/          # Split settings (base/dev/prod)
├── templates/             # Django templates
│   ├── accounts/          # User management UI
│   ├── approvals/         # Certificate request approval UI
│   ├── audit/
│   ├── ca/
│   ├── certificates/
│   ├── components/
│   └── dashboard/
├── static/
│   └── css/               # Tailwind CSS (input + compiled output)
└── storage/
    └── certificates/      # Filesystem certificate storage
```

## Server Installation

Deploy on a Linux server with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/systemd/install.sh | sudo bash
```

This downloads the latest release (pre-built, no npm/node required) and installs Pemly with systemd, nginx, PostgreSQL, and optional Let's Encrypt SSL. See [deploy/systemd/INSTALL.md](deploy/systemd/INSTALL.md) for options and manual installation.

## Local Development

### Prerequisites

- Python 3.11+
- Node.js (for Tailwind CSS compilation)
- CFSSL (`brew install cfssl` on macOS)

### 1. Clone and Set Up Python Environment

```bash
cd pkife
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Node Dependencies (for Tailwind)

```bash
npm install
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set the following:

```bash
# Generate a Django secret key
#Run: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
DJANGO_SECRET_KEY=your-secret-key-here

# Generate encryption key for private keys at rest
# Run: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=your-fernet-key-here

# CFSSL API URL (default)
CFSSL_API_URL=http://localhost:8888
```

### 4. Initialize Database

```bash
python manage.py migrate
python manage.py createsuperuser
```

### 5. Build Tailwind CSS

```bash
npm run tailwind:build
```

### 6. Run Django Development Server

```bash
python manage.py runserver
```

CFSSL starts automatically with Django (configured via `CFSSL_AUTO_START=true`).

Visit http://localhost:8000 and log in with your superuser credentials.

## Docker Deployment

### Prerequisites

- Docker and Docker Compose

### 1. Configure Environment

```bash
cp .env.example .env
```

Generate and set the required secrets in `.env`:

```bash
# Generate Django secret key
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Generate encryption key for private keys
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Edit `.env`:

```bash
DJANGO_SECRET_KEY=<generated-secret-key>
ENCRYPTION_KEY=<generated-fernet-key>
POSTGRES_PASSWORD=<strong-database-password>
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com
```

### 2. Start Development Server

```bash
make dev-build
```

This runs in development mode with:
- Live code reload (local files mounted into container)
- Django debug mode enabled
- PostgreSQL port exposed on localhost:5432

### 3. Start Production Server

```bash
make up-build
```

This runs in production mode with:
- Gunicorn WSGI server (2 workers, 4 threads)
- Optimized Docker image
- Debug mode disabled

**Using an external database:**

```bash
# Set DATABASE_URL in .env:
# DATABASE_URL=postgres://user:password@your-db-host:5432/pemly

# Start only the app container
docker compose -f deploy/docker/compose.yml up -d --build app
```

### 4. Post-Start Setup

```bash
# View logs
make logs

# Create superuser
make createsuperuser
```

### 5. Access the Application

Visit http://localhost:8000 and log in with your superuser credentials.

### Docker Commands

```bash
make up           # Start production (detached)
make up-build     # Start production with rebuild
make dev          # Start development
make dev-build    # Start development with rebuild
make down         # Stop containers
make down-v       # Stop and remove volumes (WARNING: deletes data)
make logs         # Follow app logs
make shell        # Access container shell
make migrate      # Run database migrations
make createsuperuser  # Create Django superuser
```

### Production Considerations

For production deployments:

1. **HTTPS**: Put a reverse proxy (nginx, Traefik, Caddy) in front with SSL termination
2. **Environment**: Set `DJANGO_ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` appropriately
3. **Secrets**: Consider using Docker secrets or a secrets manager instead of `.env`
4. **Backups**: Regularly backup the `postgres_data` and `app_storage` volumes
5. **ENCRYPTION_KEY**: Store securely - losing it means losing access to all private keys

### Architecture

```
┌─────────────────────────────────────────┐
│              Docker Host                │
│  ┌───────────────────────────────────┐  │
│  │           app container           │  │
│  │  ┌─────────┐    ┌──────────────┐  │  │
│  │  │ Gunicorn│    │    CFSSL     │  │  │
│  │  │ (Django)│────│  (auto-start)│  │  │
│  │  └─────────┘    └──────────────┘  │  │
│  │         │                         │  │
│  │         ▼                         │  │
│  │   ┌───────────┐                   │  │
│  │   │ WhiteNoise│ (static files)    │  │
│  │   └───────────┘                   │  │
│  └───────────────────────────────────┘  │
│              │                          │
│              ▼                          │
│  ┌───────────────────────────────────┐  │
│  │          db container             │  │
│  │         (PostgreSQL)              │  │
│  └───────────────────────────────────┘  │
│                                         │
│  Volumes:                               │
│  - postgres_data (database)             │
│  - app_storage (certificates)           │
└─────────────────────────────────────────┘
```

## Development

### Tailwind CSS

For development with live CSS reloading:

```bash
npm run tailwind:watch
```

For production build (minified):

```bash
npm run tailwind:prod
```

### Django Admin

Access Django admin at http://localhost:8000/admin/ for troubleshooting and low-level data inspection.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | Django secret key | Required |
| `DJANGO_DEBUG` | Debug mode | `True` (dev) |
| `DJANGO_ALLOWED_HOSTS` | Allowed hosts | `localhost,127.0.0.1` |
| `DATABASE_URL` | Database connection URL | `sqlite:///db.sqlite3` |
| `CFSSL_API_URL` | CFSSL API server URL | `http://localhost:8888` |
| `CFSSL_AUTH_KEY` | CFSSL authentication key | Empty |
| `ENCRYPTION_KEY` | Fernet key for encrypting private keys | Required |
| `CERTIFICATE_STORAGE_PATH` | Filesystem path for certificate export | `./storage/certificates` |

### Settings Files

- `pkife/settings/base.py` - Common settings
- `pkife/settings/development.py` - Development settings (DEBUG=True, SQLite)
- `pkife/settings/production.py` - Production settings (DEBUG=False, PostgreSQL)

## Usage

### Initial Setup

1. Log in with your superuser account
2. You'll be redirected to the CA Setup wizard
3. Fill in your organization details and key parameters
4. Click "Create Certificate Authority"

### Issuing Certificates

1. Navigate to Certificates > Issue Certificate
2. Choose generation method:
   - **Generate key pair on server** - Pemly generates the private key
   - **Sign existing CSR** - Paste a CSR from elsewhere
3. Fill in certificate details (common name, SANs, validity)
4. Click "Issue Certificate"
5. Download the certificate files

### Revoking Certificates

1. Navigate to the certificate detail page
2. Click "Revoke"
3. Select a revocation reason
4. Confirm revocation

## Role-Based Access Control (RBAC)

Pemly implements a comprehensive RBAC system with 5 distinct roles:

### User Roles

| Role | Permissions |
|------|-------------|
| **Super Admin** | Full system access including user management. Maximum of 2 per system. |
| **Administrator** | Full access to CAs, certificates, profiles, and settings. Cannot manage users. |
| **Certificate Manager** | Issue/revoke certificates, approve/reject requests, view audit logs. Cannot manage CAs or system settings. |
| **Certificate Requester** | Submit certificate requests (CSRs) for approval, view only own certificates. |
| **Auditor** | Read-only access to certificates, CAs, and audit logs. Cannot modify anything. |

### Certificate Approval Workflow

**For Certificate Requesters:**

1. Generate a private key and CSR locally:
   ```bash
   openssl genrsa -out private.key 2048
   openssl req -new -key private.key -out request.csr -subj "/CN=example.com/O=My Organization"
   ```
2. Navigate to Approvals > Request Certificate
3. Paste the CSR and fill in certificate details
4. Submit for approval
5. Wait for a Certificate Manager to review
6. Download the signed certificate once approved

**For Certificate Managers:**

1. View pending requests in the Approvals queue (badge shows count)
2. Click on a request to view details and validate the CSR
3. Approve to issue the certificate, or Reject with a reason
4. All approvals are audited with reviewer identity

### User Management

Super Admins can manage users via the Users menu:

- Create new users and assign roles
- Edit user details and change roles (with Super Admin limit enforcement)
- Delete users (cannot delete the last Super Admin)
- All user management actions are logged to the audit trail

### Separation of Duties

- Users cannot approve their own certificate requests
- Super Admin limit (2 maximum) enforced at system level
- Certificate Requesters only see their own certificates (database-level filtering)

## Security Notes

- Private keys are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256)
- The encryption key is stored in environment variables, not in the database
- All certificate operations are logged to the audit trail
- CFSSL API should only be accessible from localhost or a private network
- For production, enable HTTPS and configure secure session cookies

## API Architecture

Pemly communicates with CFSSL via its REST API:

| Operation | CFSSL Endpoint |
|-----------|----------------|
| Initialize CA | `POST /api/v1/cfssl/init_ca` |
| Generate Key + CSR | `POST /api/v1/cfssl/newkey` |
| Sign Certificate | `POST /api/v1/cfssl/sign` |
| Revoke Certificate | `POST /api/v1/cfssl/revoke` |

## Roadmap

See `PROJECT_PLAN.md` for the full implementation plan.

**Completed:**
- Certificate Authority hierarchy (Root + Intermediate CAs)
- Air-gap support (export/remove/restore private keys)
- Certificate profiles/templates
- Certificate revocation with CRL generation
- Backup and restore functionality
- Docker deployment
- Role-based access control (RBAC) with 5 user roles
- Certificate approval workflow for separation of duties

**Planned:**
- Email notifications for expiring certificates
- REST API for automation

## License

Licensed under the GNU Affero General Public License v3.0. See `LICENSE`.
