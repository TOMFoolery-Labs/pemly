# Pemly Certificate Manager
#
# One image serves both the `app` and `cfssl` compose services. The CFSSL binary has
# to be present in the app image regardless of the separate server container:
# core/services/cfssl.py shells out to it for every signing operation and only uses
# the HTTP API for key generation.

ARG CFSSL_VERSION=1.6.5

# =============================================================================
# Stage 1: build static assets and Python wheels
# =============================================================================
FROM python:3.12-slim AS builder

ARG CFSSL_VERSION

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY tailwind.config.js ./
COPY static/ ./static/
COPY templates/ ./templates/
RUN npm run tailwind:prod

COPY . .

# collectstatic imports production settings, which refuse to start without these.
# The encryption key must be a structurally valid Fernet key so that anything which
# accidentally starts decrypting at build time fails loudly rather than silently
# producing garbage. It is thrown away with this stage and never reaches the runtime
# image; the real key is supplied at runtime from .env.
ENV DJANGO_SETTINGS_MODULE=pkife.settings.production
ENV DJANGO_SECRET_KEY=build-time-only-not-a-real-secret
ENV ENCRYPTION_KEY=Yjc4ZTZmMmEzZDRiNWM2ZDdlOGY5YTBiMWMyZDNlNGY=
RUN python manage.py collectstatic --noinput


# =============================================================================
# Stage 2: runtime
# =============================================================================
FROM python:3.12-slim

ARG CFSSL_VERSION
ARG TARGETARCH=amd64

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpq5 \
        curl \
    && curl -fsSL "https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VERSION}/cfssl_${CFSSL_VERSION}_linux_${TARGETARCH}" \
         -o /usr/local/bin/cfssl \
    && curl -fsSL "https://github.com/cloudflare/cfssl/releases/download/v${CFSSL_VERSION}/cfssljson_${CFSSL_VERSION}_linux_${TARGETARCH}" \
         -o /usr/local/bin/cfssljson \
    && chmod 0755 /usr/local/bin/cfssl /usr/local/bin/cfssljson \
    && cfssl version \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /root/.local/bin /usr/local/bin
COPY --from=builder /app /app

RUN useradd --create-home --shell /bin/bash pemly \
    # Shared with the traefik container. Owning it here means the named volume
    # inherits pemly ownership on first mount, so `manage.py issue_web_cert` can
    # write into it without a host-side chown.
    && mkdir -p /certs \
    && chown -R pemly:pemly /app /certs

COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER pemly

ENV DJANGO_SETTINGS_MODULE=pkife.settings.production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["entrypoint.sh"]
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "pkife.wsgi:application"]
