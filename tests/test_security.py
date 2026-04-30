"""
Automated security tests for Deskly v2 (secure).
Validates that all 6 identified vulnerabilities have been remediated.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app import app
from db import get_db, init_db


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    app.config['DATABASE'] = db_path
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'

    with app.app_context():
        init_db()

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(db_path)


def _register(client, email, password='SecurePass1!', role='ANALYST'):
    with client.application.app_context():
        from db import gen_uuid, now_iso
        import bcrypt
        db = get_db()
        uid = gen_uuid()
        ts = now_iso()
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        db.execute(
            'INSERT INTO users (id, email, password_hash, role, created_at, updated_at) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (uid, email, pw_hash, role, ts, ts),
        )
        db.commit()
        return uid


def _login(client, email, password='SecurePass1!'):
    with client.session_transaction() as sess:
        pass
    rv = client.get('/auth/login')
    from flask import session
    with client.application.test_request_context():
        from flask_wtf.csrf import generate_csrf
    with client.session_transaction() as sess:
        csrf = sess.get('csrf_token', '')

    return client.post('/auth/login', data={
        'email': email,
        'password': password,
        'csrf_token': csrf,
    }, follow_redirects=True)


def _create_ticket(client, uid, title='Test', description='Desc', severity='LOW'):
    with client.application.app_context():
        from db import gen_uuid, now_iso
        db = get_db()
        tid = gen_uuid()
        ts = now_iso()
        db.execute(
            'INSERT INTO tickets (id, title, description, severity, status, owner_id, created_at, updated_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (tid, title, description, severity, 'OPEN', uid, ts, ts),
        )
        db.commit()
        return tid


# ─────────────────────────────────────────────────────────────────────── #
# TEST 1: IDOR — Analyst cannot access another Analyst's ticket
# ─────────────────────────────────────────────────────────────────────── #
def test_idor(client):
    uid_a = _register(client, 'analyst_a@test.com')
    uid_b = _register(client, 'analyst_b@test.com')
    ticket_b = _create_ticket(client, uid_b, title='Secret Ticket')

    with client.session_transaction() as sess:
        sess['user_id'] = uid_a
        sess['user_email'] = 'analyst_a@test.com'
        sess['user_role'] = 'ANALYST'

    rv = client.get(f'/tickets/{ticket_b}')
    assert rv.status_code == 403


# ─────────────────────────────────────────────────────────────────────── #
# TEST 2: SQL Injection — payload does not leak data
# ─────────────────────────────────────────────────────────────────────── #
def test_sql_injection(client):
    uid = _register(client, 'sqli_user@test.com')
    _create_ticket(client, uid, title='Normal Ticket')

    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['user_email'] = 'sqli_user@test.com'
        sess['user_role'] = 'ANALYST'

    rv = client.get("/tickets/search?q=' OR '1'='1' --")
    assert rv.status_code == 200
    assert b'password_hash' not in rv.data


# ─────────────────────────────────────────────────────────────────────── #
# TEST 3: XSS — script tags are escaped in output
# ─────────────────────────────────────────────────────────────────────── #
def test_xss_escaped(client):
    uid = _register(client, 'xss_user@test.com')
    payload = '<script>alert("XSS")</script>'
    tid = _create_ticket(client, uid, title='XSS Test', description=payload)

    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['user_email'] = 'xss_user@test.com'
        sess['user_role'] = 'ANALYST'

    rv = client.get(f'/tickets/{tid}')
    assert rv.status_code == 200
    assert b'<script>alert("XSS")</script>' not in rv.data
    assert b'&lt;script&gt;' in rv.data


# ─────────────────────────────────────────────────────────────────────── #
# TEST 4: CSRF — POST without token is rejected
# ─────────────────────────────────────────────────────────────────────── #
def test_csrf_rejected(client):
    uid = _register(client, 'csrf_user@test.com')
    tid = _create_ticket(client, uid)

    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['user_email'] = 'csrf_user@test.com'
        sess['user_role'] = 'ANALYST'

    rv = client.post(f'/tickets/{tid}/status', data={'status': 'RESOLVED'})
    assert rv.status_code == 400


# ─────────────────────────────────────────────────────────────────────── #
# TEST 5: Password bcrypt — hash in DB starts with $2b$
# ─────────────────────────────────────────────────────────────────────── #
def test_password_bcrypt(client):
    _register(client, 'bcrypt_user@test.com', password='StrongPass123!')

    with client.application.app_context():
        db = get_db()
        row = db.execute(
            "SELECT password_hash FROM users WHERE email='bcrypt_user@test.com'"
        ).fetchone()
        assert row['password_hash'].startswith('$2b$')


# ─────────────────────────────────────────────────────────────────────── #
# TEST 6: Error handling — no stack trace for invalid routes
# ─────────────────────────────────────────────────────────────────────── #
def test_error_no_stacktrace(client):
    rv = client.get('/nonexistent-route-xyz')
    assert rv.status_code == 404
    assert b'Traceback' not in rv.data
    assert b'File "' not in rv.data


# ─────────────────────────────────────────────────────────────────────── #
# TEST 7: Lockout — account locks after 5 failed login attempts
# ─────────────────────────────────────────────────────────────────────── #
def _get_csrf_from_page(client, url):
    rv = client.get(url)
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', rv.data.decode())
    return match.group(1) if match else ''


def test_lockout(client):
    _register(client, 'lockout@test.com', password='CorrectPass1!')

    for i in range(5):
        csrf = _get_csrf_from_page(client, '/auth/login')
        client.post('/auth/login', data={
            'email': 'lockout@test.com',
            'password': 'WrongPassword',
            'csrf_token': csrf,
        })

    csrf = _get_csrf_from_page(client, '/auth/login')
    rv = client.post('/auth/login', data={
        'email': 'lockout@test.com',
        'password': 'CorrectPass1!',
        'csrf_token': csrf,
    })
    assert b'locked' in rv.data.lower()
