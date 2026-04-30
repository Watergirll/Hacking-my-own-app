#!/bin/sh
set -e

DB_PATH="${DATABASE:-/app/data/deskly_v1.db}"

# Initialize the database only on first run (when the file doesn't exist yet)
if [ ! -f "$DB_PATH" ]; then
    echo "[entrypoint] Initializing database at $DB_PATH ..."
    python - <<'PYEOF'
import os, sqlite3
db_path = os.environ.get("DATABASE", "/app/data/deskly_v1.db")
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

echo "[entrypoint] Starting Flask (v1 - vulnerable)..."
exec python app.py
