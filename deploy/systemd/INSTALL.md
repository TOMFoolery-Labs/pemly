# Pemly Systemd Installation Guide

This guide covers deploying Pemly on a Linux server with systemd and nginx.

## Quick Install

Run the automated installer (downloads pre-built release, no npm/node required):

```bash
curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/systemd/install.sh | sudo bash
```

To skip SSL setup and use HTTP only:

```bash
curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/systemd/install.sh | sudo bash -s -- --no-ssl
```

The script downloads the latest release (with pre-built CSS), installs dependencies, configures PostgreSQL, nginx, and optional Let's Encrypt SSL. See `install.sh --help` for all options.

---

## Manual Installation

The following sections describe the manual installation process.

### Prerequisites

- Linux server (Debian/Ubuntu, RHEL/Rocky, etc.)
- Python 3.11+
- PostgreSQL (or other database accessible via DATABASE_URL)
- nginx
- CFSSL binary installed and in PATH
- Node.js/npm (only if installing from git; release tarballs include pre-built CSS)

#### Install CFSSL

```bash
# Download latest release from https://github.com/cloudflare/cfssl/releases
VERSION=1.6.5
curl -L -o /usr/local/bin/cfssl https://github.com/cloudflare/cfssl/releases/download/v${VERSION}/cfssl_${VERSION}_linux_amd64
curl -L -o /usr/local/bin/cfssljson https://github.com/cloudflare/cfssl/releases/download/v${VERSION}/cfssljson_${VERSION}_linux_amd64
chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson
```

### Installation Steps

#### 1. Create System User

```bash
sudo useradd --system --home /opt/pemly --shell /usr/sbin/nologin pemly
```

#### 2. Install Application

**Option A: Download release tarball (recommended, no npm required)**

```bash
# Create directory
sudo mkdir -p /opt/pemly
sudo chown pemly:pemly /opt/pemly

# Download and extract latest release
VERSION=$(curl -sL https://api.github.com/repos/TOMFoolery-Labs/pemly/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
curl -sL "https://github.com/TOMFoolery-Labs/pemly/releases/download/${VERSION}/pemly-${VERSION}.tar.gz" | \
  sudo -u pemly tar -xz -C /opt/pemly --strip-components=1

# Create virtual environment and install dependencies
sudo -u pemly python3 -m venv /opt/pemly/venv
sudo -u pemly /opt/pemly/venv/bin/pip install -r /opt/pemly/requirements.txt
```

**Option B: Clone from git (requires npm to build CSS)**

```bash
# Create directory
sudo mkdir -p /opt/pemly
sudo chown pemly:pemly /opt/pemly

# Clone repository
sudo -u pemly git clone https://github.com/TOMFoolery-Labs/pemly.git /opt/pemly

# Create virtual environment and install dependencies
sudo -u pemly python3 -m venv /opt/pemly/venv
sudo -u pemly /opt/pemly/venv/bin/pip install -r /opt/pemly/requirements.txt
```

#### 3. Build Frontend Assets (git installs only)

Skip this step if you installed from a release tarball (CSS is pre-built).

```bash
# Install Node.js (Debian/Ubuntu)
sudo apt install nodejs npm

# Install npm dependencies and build CSS
cd /opt/pemly
sudo -u pemly npm install
sudo -u pemly npm run tailwind:prod
```

#### 4. Configure Environment

```bash
# Copy and edit environment file
sudo cp /opt/pemly/deploy/systemd/pemly.env.example /opt/pemly/.env
sudo chown pemly:pemly /opt/pemly/.env
sudo chmod 600 /opt/pemly/.env

# Edit with your settings
sudo -e /opt/pemly/.env
```

Generate required secrets:

```bash
# Generate Django secret key
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Generate encryption key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

#### 5. Initialize Database

```bash
# Run migrations
sudo -u pemly /opt/pemly/venv/bin/python /opt/pemly/manage.py migrate

# Create superuser
sudo -u pemly /opt/pemly/venv/bin/python /opt/pemly/manage.py createsuperuser

# Collect static files
sudo -u pemly /opt/pemly/venv/bin/python /opt/pemly/manage.py collectstatic --noinput
```

#### 6. Create Storage Directories

```bash
sudo -u pemly mkdir -p /opt/pemly/storage/certificates
```

#### 7. Install Systemd Service

```bash
# Install service file
sudo cp /opt/pemly/deploy/systemd/pemly.service /etc/systemd/system/

# Install tmpfiles config (creates /run/pemly on boot)
sudo cp /opt/pemly/deploy/systemd/pemly.tmpfiles /etc/tmpfiles.d/pemly.conf

# Create runtime directory now
sudo systemd-tmpfiles --create /etc/tmpfiles.d/pemly.conf

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable pemly
sudo systemctl start pemly

# Check status
sudo systemctl status pemly
```

#### 8. Configure Nginx

```bash
# Copy and customize nginx config
sudo cp /opt/pemly/deploy/systemd/nginx.conf.example /etc/nginx/sites-available/pemly

# Edit server_name and SSL paths
sudo nano /etc/nginx/sites-available/pemly

# Enable site
sudo ln -s /etc/nginx/sites-available/pemly /etc/nginx/sites-enabled/

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

#### 9. SSL Certificate (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx  # Debian/Ubuntu
# or
sudo dnf install certbot python3-certbot-nginx  # RHEL/Rocky

# Get certificate (stop nginx first or use webroot)
sudo certbot certonly --nginx -d pemly.example.com

# Update nginx config with certificate paths, then reload
sudo systemctl reload nginx
```

### Management Commands

```bash
# View logs
sudo journalctl -u pemly -f

# Restart service
sudo systemctl restart pemly

# Check service status
sudo systemctl status pemly

# Run Django management commands
sudo -u pemly /opt/pemly/venv/bin/python /opt/pemly/manage.py <command>
```

### Upgrading

**Option A: Upgrade from release (recommended)**

```bash
# Download and extract new release
cd /opt/pemly
VERSION=$(curl -sL https://api.github.com/repos/TOMFoolery-Labs/pemly/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
curl -sL "https://github.com/TOMFoolery-Labs/pemly/releases/download/${VERSION}/pemly-${VERSION}.tar.gz" | \
  sudo -u pemly tar -xz -C /opt/pemly --strip-components=1

# Install any new dependencies
sudo -u pemly /opt/pemly/venv/bin/pip install -r requirements.txt

# Run migrations and collect static files
sudo -u pemly /opt/pemly/venv/bin/python manage.py migrate
sudo -u pemly /opt/pemly/venv/bin/python manage.py collectstatic --noinput

# Restart service
sudo systemctl restart pemly
```

**Option B: Upgrade from git**

```bash
# Pull updates
cd /opt/pemly
sudo -u pemly git pull

# Install any new dependencies
sudo -u pemly /opt/pemly/venv/bin/pip install -r requirements.txt
sudo -u pemly npm install

# Build frontend assets
sudo -u pemly npm run tailwind:prod

# Run migrations and collect static files
sudo -u pemly /opt/pemly/venv/bin/python manage.py migrate
sudo -u pemly /opt/pemly/venv/bin/python manage.py collectstatic --noinput

# Restart service
sudo systemctl restart pemly
```

### Troubleshooting

#### Service won't start

```bash
# Check logs
sudo journalctl -u pemly -e

# Test gunicorn manually
sudo -u pemly /opt/pemly/venv/bin/gunicorn --bind 127.0.0.1:8000 pkife.wsgi:application
```

#### 502 Bad Gateway

- Check if pemly service is running: `sudo systemctl status pemly`
- Check socket exists: `ls -la /run/pemly/gunicorn.sock`
- Check nginx can access socket (nginx user needs to be in pemly group or socket needs 777)

#### Static files not loading

- Verify collectstatic was run: `ls /opt/pemly/staticfiles/`
- Check nginx config paths match
- Check file permissions

#### Database connection errors

- Verify DATABASE_URL in /opt/pemly/.env
- Test connection: `sudo -u pemly /opt/pemly/venv/bin/python manage.py dbshell`
