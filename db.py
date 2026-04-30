import sqlite3
import uuid
from datetime import datetime, timezone

from flask import current_app, g


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row
        # Required per-connection in SQLite — not automatic from schema.sql
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


def close_db(error=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf-8'))


def gen_uuid() -> str:
    return str(uuid.uuid4())


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def log_audit(
    user_id,
    action,
    resource_type,
    resource_id=None,
    message=None,
    ip_address=None,
    user_agent=None,
):
    db = get_db()
    db.execute(
        '''INSERT INTO audit_logs
               (id, user_id, action, resource_type, resource_id,
                message, ip_address, user_agent, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            gen_uuid(),
            user_id,
            action,
            resource_type,
            resource_id,
            message,
            ip_address,
            user_agent,
            now_iso(),
        ),
    )
    db.commit()
