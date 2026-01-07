#!/bin/bash
set -e

# Wait for database to be ready (if using PostgreSQL)
if [[ "$DATABASE_URL" == postgres* ]]; then
    echo "Waiting for PostgreSQL..."
    while ! python -c "import psycopg; psycopg.connect('$DATABASE_URL')" 2>/dev/null; do
        sleep 1
    done
    echo "PostgreSQL is ready!"
fi

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --noinput

# Execute the main command
exec "$@"
