#!/bin/sh
set -e

echo "==> Waiting for database..."
python - <<'PY'
import os, time, sys
import psycopg
url = os.environ.get("DATABASE_URL", "")
if not url.startswith("postgres"):
    print("No Postgres URL detected; skipping wait.")
    sys.exit(0)
for i in range(30):
    try:
        psycopg.connect(url, connect_timeout=2).close()
        print("Database is up.")
        sys.exit(0)
    except Exception as e:
        print(f"  attempt {i+1}/30: {e}")
        time.sleep(2)
print("Database never came up.")
sys.exit(1)
PY

echo "==> Applying migrations..."
python manage.py migrate --noinput

if [ "$SEED_ON_START" = "1" ]; then
    echo "==> Seeding demo data..."
    python manage.py seed_data --reset || true
fi

if [ "$TRAIN_ON_START" = "1" ]; then
    echo "==> Training ML models..."
    python -m ml.train || true
fi

echo "==> Starting: $@"
exec "$@"s