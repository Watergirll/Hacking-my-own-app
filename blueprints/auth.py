import bcrypt

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import gen_uuid, get_db, log_audit, now_iso

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

MAX_FAILED_LOGINS = 5


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())


# ================================================================== #
#  REGISTER                                                           #
# ================================================================== #
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role     = request.form.get('role', 'ANALYST')

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('auth/register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('auth/register.html')

        if role not in ('ANALYST', 'MANAGER'):
            role = 'ANALYST'

        db = get_db()

        existing = db.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')

        user_id = gen_uuid()
        ts = now_iso()

        db.execute(
            '''INSERT INTO users
                   (id, email, password_hash, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, email, _hash_password(password), role, ts, ts),
        )
        db.commit()

        log_audit(
            user_id, 'REGISTER', 'auth', user_id,
            f'New user registered: {email}',
            request.remote_addr,
            request.headers.get('User-Agent'),
        )

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


# ================================================================== #
#  LOGIN                                                              #
# ================================================================== #
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()

        if user and user['is_locked']:
            log_audit(
                user['id'], 'LOGIN_FAILED', 'auth', user['id'],
                f'Login attempt on locked account: {email}',
                request.remote_addr,
                request.headers.get('User-Agent'),
            )
            flash('Account is locked due to too many failed attempts. Contact an admin.', 'danger')
            return render_template('auth/login.html')

        if user and _check_password(password, user['password_hash']):
            session.clear()
            session['user_id']    = user['id']
            session['user_email'] = user['email']
            session['user_role']  = user['role']
            session.permanent = True

            ts = now_iso()
            db.execute(
                'UPDATE users SET last_login_at=?, failed_logins=0, updated_at=? WHERE id=?',
                (ts, ts, user['id']),
            )
            db.commit()

            log_audit(
                user['id'], 'LOGIN_SUCCESS', 'auth', user['id'],
                f'Login success: {email}',
                request.remote_addr,
                request.headers.get('User-Agent'),
            )
            return redirect(url_for('main.dashboard'))

        # Login failed
        if user:
            ts = now_iso()
            new_count = user['failed_logins'] + 1
            locked = 1 if new_count >= MAX_FAILED_LOGINS else 0
            db.execute(
                'UPDATE users SET failed_logins=?, is_locked=?, updated_at=? WHERE id=?',
                (new_count, locked, ts, user['id']),
            )
            db.commit()
            log_audit(
                user['id'], 'LOGIN_FAILED', 'auth', user['id'],
                f'Login failed ({new_count}/{MAX_FAILED_LOGINS}): {email}',
                request.remote_addr,
                request.headers.get('User-Agent'),
            )

        flash('Invalid email or password.', 'danger')

    return render_template('auth/login.html')


# ================================================================== #
#  LOGOUT                                                             #
# ================================================================== #
@auth_bp.route('/logout')
def logout():
    user_id = session.get('user_id')

    if user_id:
        log_audit(
            user_id, 'LOGOUT', 'auth', user_id,
            'User logged out',
            request.remote_addr,
            request.headers.get('User-Agent'),
        )

    session.clear()
    return redirect(url_for('auth.login'))
