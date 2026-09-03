# Deploying Pemly

Pemly ships as a Docker Compose stack. The host needs Docker and nothing else -
no Python, Node, nginx, certbot or PostgreSQL installation.

```
        :80/:443
           │
      ┌────▼─────┐
      │ traefik  │  TLS termination and the only ingress
      └────┬─────┘
           │  http, X-Forwarded-Proto: https
      ┌────▼─────┐
      │   app    │  gunicorn + Django; no published host port
      └──┬────┬──┘
         │    │
    ┌────▼─┐ ┌▼─────┐
    │cfssl │ │  db  │  internal network, no route to the internet
    └──────┘ └──────┘
```

Two design points worth knowing:

- **CFSSL is its own service.** It used to be spawned from inside a gunicorn
  worker, which meant three workers raced to start it and only the winner
  monitored it. The app image still contains the binary, because signing runs
  through the CFSSL CLI (`core/services/cfssl.py`); only key generation uses the
  HTTP API.
- **The app is always behind TLS termination.** `USE_X_FORWARDED_PROTO` is on in
  every mode, so `SECURE_SSL_REDIRECT` and secure cookies can stay enabled
  without the redirect-to-nowhere that an HTTP-only install used to produce.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/install.sh | sudo bash
```

Options: `--domain <fqdn>`, `--tls <mode>`, `--external-db`, `--dir <path>`,
`--ref <tag>`, `--upgrade`, `--uninstall`, `--non-interactive`.

Or, from a checkout:

```bash
cd deploy/docker
./bootstrap.sh init --domain pki.example.com
./bootstrap.sh up
```

### The generated .env

`bootstrap.sh init` writes `deploy/docker/.env` with a Django secret key, a
Fernet encryption key and a database password.

> **Back this file up.** `ENCRYPTION_KEY` decrypts every CA and certificate
> private key in the database. It cannot be regenerated or recovered. A database
> backup without it is worthless.

### First login

```bash
./bootstrap.sh logs app | grep -A4 'first administrator'
```

The password is printed once, on the first start of an empty install. Set
`PEMLY_ADMIN_USERNAME` / `PEMLY_ADMIN_PASSWORD` in `.env` beforehand to choose
your own. Once any user exists the bootstrap is a no-op, so restarts never reset
a password.

## Upgrades

```bash
curl -fsSL https://raw.githubusercontent.com/TOMFoolery-Labs/pemly/main/deploy/install.sh | sudo bash -s -- --upgrade
```

This updates the checkout in `/opt/pemly` and restarts the stack. `.env`, the
database and the certificate volume are untouched; migrations run in the app
entrypoint. Until a release is tagged there is no image on ghcr.io to pull, so
the upgrade rebuilds the image from the checkout - several minutes.

Updating a checkout by hand takes one non-obvious step. `install.sh` clones with
`--depth 1`, which implies `--single-branch`, and a fetch that names a branch
explicitly writes only `FETCH_HEAD`: there is no `origin/main` ref to check out,
and `git checkout -f origin/main` fails with `pathspec ... did not match`. The
tree then stays where it was and the rebuild faithfully rebuilds the old code.

```bash
sudo -i                        # /opt/pemly is root-owned and 0700
cd /opt/pemly
git fetch --depth 1 origin main
git checkout -f FETCH_HEAD     # not origin/main
cd deploy/docker
./bootstrap.sh upgrade
```

## TLS

### Self-signed (default)

Nothing to configure. Traefik serves its built-in certificate, so the login page
works over HTTPS on first boot. Browsers warn until you replace it.

### Your own certificate

```bash
./bootstrap.sh install-cert /path/cert.pem /path/key.pem
```

Copies the pair into the shared certs volume and restarts the proxy. Use the
full chain in `cert.pem` if an intermediate is involved.

### Issued by Pemly itself

Best answer for an air-gapped site: the appliance is already a CA.

```bash
./bootstrap.sh issue-cert                      # uses PEMLY_DOMAIN
./bootstrap.sh issue-cert --alt-name pki.internal --ip 10.0.0.5
```

Requires a CA to have been set up in the web UI first. The certificate is
recorded like any other issued certificate, so it shows up in the UI and can be
renewed or revoked normally. Clients that already trust the CA - via the trust
portal - trust the web UI with no extra step.

### ACME DNS-01

For a public domain on a host with no inbound port 80. DNS-01 proves control by
writing a TXT record, so it needs only outbound access to the ACME directory and
your DNS provider's API.

```bash
./bootstrap.sh init --tls acme-dns \
    --domain pki.example.com \
    --acme-email admin@example.com \
    --acme-provider cloudflare
```

Then put the provider's credentials in `deploy/docker/.env.dns`:

```bash
CF_DNS_API_TOKEN=...
```

That file is mounted only into the proxy, so Traefik never sees the Django secret
key or the database password.

Traefik bundles [lego](https://go-acme.github.io/lego/dns/), so roughly 150
providers work with the stock image - no custom build. On a network with no
public zone at all, `rfc2136` talks to internal BIND or Windows DNS directly:

```bash
RFC2136_NAMESERVER=ns1.internal.example.com:53
RFC2136_TSIG_ALGORITHM=hmac-sha256.
RFC2136_TSIG_KEY=pemly-acme
RFC2136_TSIG_SECRET=...
```

Test against staging first to avoid rate limits:

```bash
PEMLY_ACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory
```

### A note on reloading

Traefik's file provider watches its *configuration* directory, but the
certificate files that configuration points at are only read when the
configuration loads. A certificate dropped in afterwards is invisible until the
proxy restarts. `install-cert` and `issue-cert` do the restart for you; if you
place files by hand, run `docker compose restart traefik`.

## External database

```bash
./bootstrap.sh init --domain pki.example.com --external-db
```

Then set `DATABASE_URL` in `.env`. This removes the bundled `db` service and its
volume entirely. Needs Docker Compose 2.24+ for the `!reset` tag.

## Air-gapped installs

On a connected machine:

```bash
docker pull ghcr.io/tomfoolery-labs/pemly:latest
docker save ghcr.io/tomfoolery-labs/pemly:latest | gzip > pemly-image.tgz
docker pull traefik:v3.3   && docker save traefik:v3.3   | gzip > traefik.tgz
docker pull postgres:16-alpine && docker save postgres:16-alpine | gzip > postgres.tgz
```

On the target, load the images and use the deploy tarball from the release page:

```bash
gunzip -c pemly-image.tgz | docker load
gunzip -c traefik.tgz     | docker load
gunzip -c postgres.tgz    | docker load
tar -xzf pemly-deploy-v*.tar.gz && cd docker
./bootstrap.sh init --domain pki.internal
./bootstrap.sh up
```

Use the self-signed default, then `issue-cert` once the CA exists.

## Backups

The database volume is the only durable state - all key material lives in it,
encrypted.

```bash
cd deploy/docker
docker compose exec -T db pg_dump -U pemly --no-owner --no-acl pemly | gzip > pemly-$(date +%F).sql.gz
cp .env pemly-env-$(date +%F).bak     # ENCRYPTION_KEY lives here
```

Store the `.env` copy separately from the dump and treat it as a secret. Restore:

```bash
gunzip -c pemly-2026-01-01.sql.gz | docker compose exec -T db psql -U pemly -d pemly
```

## Migrating from a systemd installation

```bash
sudo bash deploy/migrate-from-systemd.sh
```

It dumps the existing database, stops `pemly` and `nginx`, archives
`/opt/pemly` rather than deleting it, installs the container stack carrying the
**original** `DJANGO_SECRET_KEY` and `ENCRYPTION_KEY` across, restores the dump,
and then verifies that every stored CA private key still decrypts. It refuses to
start if it cannot find an `ENCRYPTION_KEY` in the old `.env`.

The old tree and the dump are both left in place; remove them once you are
satisfied.

## Troubleshooting

**`docker compose config` complains about `POSTGRES_PASSWORD`** - `.env` is
missing or was not generated. Run `./bootstrap.sh init --domain <fqdn>`.

**Browser warns about the certificate** - expected on the self-signed default.
Install a real one, or distribute your CA through the trust portal.

**`healthz` reports `"cfssl": "unavailable"`** - the cfssl container is not
answering. `docker compose ps` and `docker compose logs cfssl`. The web UI keeps
working; certificate issuance does not.

**ACME fails with a DNS timeout** - the challenge record is not visible to the
public resolvers Traefik queries. Check `PEMLY_ACME_DNS_RESOLVERS`, and confirm
your provider credentials have write access to the zone.

**Checking what is actually served:**

```bash
curl -kI https://localhost/
echo | openssl s_client -connect localhost:443 -servername pki.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```
