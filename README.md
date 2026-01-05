# Pemly - Certificate Manager

A Django web application that serves as a user-friendly frontend for CloudFlare's CFSSL PKI toolkit. Build and manage your own Certificate Authority with a clean, modern interface.

## Features

- **Certificate Authority Management** - Create and manage a root CA
- **Certificate Issuance** - Issue certificates with server-side key generation or sign existing CSRs
- **Certificate Types** - Support for Server TLS and Client Authentication certificates
- **Subject Alternative Names** - Add DNS names and IP addresses to certificates
- **Certificate Revocation** - Revoke certificates with standard revocation reasons
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
pkife/
├── accounts/              # Authentication (login/logout)
├── core/                  # Main application
│   ├── models.py          # CA, Certificate, AuditLog models
│   ├── services/          # CFSSL API client
│   │   └── cfssl.py
│   └── views/             # Dashboard, CA, Certificates, Audit views
├── pkife/
│   └── settings/          # Split settings (base/dev/prod)
├── templates/             # Django templates
│   ├── accounts/
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

## Prerequisites

- Python 3.11+
- Node.js (for Tailwind CSS compilation)
- CFSSL (`brew install cfssl` on macOS)

## Quick Start

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

### 6. Start CFSSL Server

In a separate terminal:

```bash
cfssl serve -address=localhost -port=8888
```

### 7. Run Django Development Server

```bash
python manage.py runserver
```

Visit http://localhost:8000 and log in with your superuser credentials.

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

See `PROJECT_PLAN.md` for the full implementation plan. Future phases include:

- **Phase 2:** Certificate revocation lists (CRL), expiration warnings, filesystem export
- **Phase 3:** Certificate profiles/templates, email notifications, REST API
- **Phase 4:** Role-based access control (RBAC), Docker deployment, backup/restore

## License

[Add your license here]
