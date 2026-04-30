#!/bin/sh
set -e

DB_PATH="${DATABASE:-/app/data/deskly_v2.db}"

# Initialize the database only on first run
if [ ! -f "$DB_PATH" ]; then
    echo "[entrypoint] Initializing database at $DB_PATH ..."
    python - <<'PYEOF'
import os, sqlite3
db_path = os.environ.get("DATABASE", "/app/data/deskly_v2.db")
conn = sqlite3.connect(db_path)
with open("schema.sql", encoding="utf-8") as f:
    conn.executescript(f.read())
conn.commit()
conn.close()
print("[entrypoint] Database initialized.")
PYEOF
else
    echo "[entrypoint] Database already exists, skipping init."
fi

echo "[entrypoint] Running security tests..."
python -m pytest tests/ -v
echo "[entrypoint] All tests passed. Starting server..."

exec python app.py
