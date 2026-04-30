import hashlib

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


# ------------------------------------------------------------------ #
# [VULN #6] MD5 fara salt — hash slab, reversibil prin rainbow tables #
# FIX (v2): bcrypt.hashpw(password.encode(), bcrypt.gensalt())        #
# ------------------------------------------------------------------ #
def _hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def _check_password(password: str, stored_hash: str) -> bool:
    return _hash_password(password) == stored_hash


# ================================================================== #
#  REGISTER                                                           #
# ================================================================== #
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role     = request.form.get('role', 'ANALYST')

        # ---------------------------------------------------------- #
        # [VULN #5] Validare minima — nu se verifica lungime / format #
        # Erorile DB (ex. email duplicat) se propaga ca 500 cu trace  #
        # FIX (v2): validare completa + handler global erori          #
        # ---------------------------------------------------------- #
        if not email or not password:
            flash('Email and password are required.', 'danger')
            return render_template('auth/register.html')

        if role not in ('ANALYST', 'MANAGER'):
            role = 'ANALYST'

        db = get_db()
        user_id = gen_uuid()
        ts = now_iso()

        # [VULN #6] parola hash-uita cu MD5 (fara salt)
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

        # ---------------------------------------------------------- #
        # [VULN #4B] Nu se verifica is_locked — brute force posibil   #
        # chiar daca failed_logins creste in DB.                      #
        # FIX (v2): if user['is_locked']: return 403                  #
        # ---------------------------------------------------------- #
        if user and _check_password(password, user['password_hash']):
            session.clear()
            session['user_id']    = user['id']
            session['user_email'] = user['email']
            session['user_role']  = user['role']
            # [VULN #4B] Sesiunea nu are expirare setata explicit

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

        # Login esuat
        if user:
            ts = now_iso()
            db.execute(
                'UPDATE users SET failed_logins=failed_logins+1, updated_at=? WHERE id=?',
                (ts, user['id']),
            )
            db.commit()
            log_audit(
                user['id'], 'LOGIN_FAILED', 'auth', user['id'],
                f'Login failed: {email}',
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

    # ---------------------------------------------------------- #
    # [VULN #4B] session.clear() sterge doar cookie-ul client.   #
    # Nu exista invalidare server-side → token-ul vechi refolosit #
    # FIX (v2): tabel sessions cu revoked_at setat la logout      #
    # ---------------------------------------------------------- #
    session.clear()
    return redirect(url_for('auth.login'))
