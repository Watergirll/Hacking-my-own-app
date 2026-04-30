from functools import wraps

from flask import Blueprint, redirect, render_template, session, url_for
from db import get_db

main_bp = Blueprint('main', __name__)


def login_required(f):
    """Decorator: redirects to login if user has no active session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def manager_required(f):
    """Decorator: returns 403 if user is not MANAGER."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        if session.get('user_role') != 'MANAGER':
            return render_template('errors/403.html'), 403
        return f(*args, **kwargs)
    return decorated


@main_bp.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return redirect(url_for('main.dashboard'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    db   = get_db()
    uid  = session['user_id']
    role = session['user_role']

    base = 'SELECT COUNT(*) FROM tickets' + ('' if role == 'MANAGER' else ' WHERE owner_id=?')
    args = [] if role == 'MANAGER' else [uid]

    total    = db.execute(base, args).fetchone()[0]
    open_c   = db.execute(base.replace('COUNT(*)', "COUNT(*) ") + (' AND ' if 'WHERE' in base else ' WHERE ') + "status='OPEN'",   args).fetchone()[0]
    resolved = db.execute(base.replace('COUNT(*)', "COUNT(*) ") + (' AND ' if 'WHERE' in base else ' WHERE ') + "status='RESOLVED'", args).fetchone()[0]
    high     = db.execute(base.replace('COUNT(*)', "COUNT(*) ") + (' AND ' if 'WHERE' in base else ' WHERE ') + "severity='HIGH'",   args).fetchone()[0]

    return render_template('dashboard.html',
                           total=total, open_c=open_c,
                           resolved=resolved, high=high)
