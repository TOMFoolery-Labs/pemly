# Stage 1: Build static assets
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Install Node dependencies and build Tailwind CSS
COPY package.json package-lock.json* ./
RUN npm ci --only=production || npm install

COPY tailwind.config.js ./
COPY static/ ./static/
COPY templates/ ./templates/
COPY core/templates/ ./core/templates/
COPY accounts/templates/ ./accounts/templates/
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

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY --from=builder /app /app

# Copy collected static files
COPY --from=builder /app/staticfiles /app/staticfiles

# Create non-root user
RUN useradd --create-home --shell /bin/bash pemly \
    && mkdir -p /app/storage \
    && chown -R pemly:pemly /app

# Copy and set up entrypoint
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pemly

# Environment
ENV DJANGO_SETTINGS_MODULE=pkife.settings.production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "pkife.wsgi:application"]
