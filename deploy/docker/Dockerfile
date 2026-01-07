# Stage 1: Build static assets
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies and CFSSL (needed for dev mode)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    curl \
    ca-certificates \
    && curl -L https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssl_1.6.5_linux_amd64 -o /usr/local/bin/cfssl \
    && curl -L https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssljson_1.6.5_linux_amd64 -o /usr/local/bin/cfssljson \
    && chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson \
    && apt-get remove -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Install Node dependencies and build Tailwind CSS
COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY tailwind.config.js ./
COPY static/ ./static/
COPY templates/ ./templates/
RUN npm run tailwind:prod

# Copy application code
COPY . .

# Collect static files
ENV DJANGO_SETTINGS_MODULE=pkife.settings.production
ENV DJANGO_SECRET_KEY=build-time-secret-key
ENV ENCRYPTION_KEY=build-time-encryption-key
RUN python manage.py collectstatic --noinput


# Stage 2: Production runtime
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies and CFSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libpq5 \
    && curl -L https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssl_1.6.5_linux_amd64 -o /usr/local/bin/cfssl \
    && curl -L https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssljson_1.6.5_linux_amd64 -o /usr/local/bin/cfssljson \
    && chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson \
    && apt-get remove -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder to site-packages (accessible by all users)
COPY --from=builder /root/.local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /root/.local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app /app

# Copy collected static files
COPY --from=builder /app/staticfiles /app/staticfiles

# Create non-root user
RUN useradd --create-home --shell /bin/bash pemly \
    && mkdir -p /app/storage \
    && chown -R pemly:pemly /app

# Copy and set up entrypoint
COPY deploy/docker/entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh

USER pemly

# Environment
ENV DJANGO_SETTINGS_MODULE=pkife.settings.production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "pkife.wsgi:application"]
