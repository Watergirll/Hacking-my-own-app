from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import gen_uuid, get_db, log_audit, now_iso
from blueprints.main import login_required, manager_required

tickets_bp = Blueprint('tickets', __name__, url_prefix='/tickets')

SEVERITIES = ('LOW', 'MED', 'HIGH')
STATUSES   = ('OPEN', 'IN_PROGRESS', 'RESOLVED')


# ================================================================== #
#  LIST TICKETS                                                       #
# ================================================================== #
@tickets_bp.route('/')
@login_required
def list_tickets():
    db     = get_db()
    role   = session['user_role']
    uid    = session['user_id']

    status_filter   = request.args.get('status',   '').strip()
    severity_filter = request.args.get('severity', '').strip()

    if role == 'MANAGER':
        query  = 'SELECT t.*, u.email AS owner_email FROM tickets t JOIN users u ON t.owner_id=u.id'
        params = []
    else:
        query  = 'SELECT t.*, u.email AS owner_email FROM tickets t JOIN users u ON t.owner_id=u.id WHERE t.owner_id=?'
        params = [uid]

    if status_filter in STATUSES:
        query  += (' AND' if 'WHERE' in query else ' WHERE') + ' t.status=?'
        params.append(status_filter)

    if severity_filter in SEVERITIES:
        query  += ' AND t.severity=?'
        params.append(severity_filter)

    query += ' ORDER BY t.created_at DESC'
    tickets = db.execute(query, params).fetchall()

    log_audit(uid, 'TICKET_VIEW', 'ticket', None, 'Listed tickets',
              request.remote_addr, request.headers.get('User-Agent'))

    return render_template('tickets/list.html',
                           tickets=tickets,
                           statuses=STATUSES,
                           severities=SEVERITIES,
                           current_status=status_filter,
                           current_severity=severity_filter)


# ================================================================== #
#  SEARCH                                                             #
# ================================================================== #
@tickets_bp.route('/search')
@login_required
def search():
    db   = get_db()
    uid  = session['user_id']
    role = session['user_role']
    q    = request.args.get('q', '')

    # ------------------------------------------------------------------ #
    # [VULN #2] SQL Injection — input-ul e concatenat direct in query.    #
    # Exemplu PoC: q = %' UNION SELECT id,email,password_hash,role,       #
    #                   password_hash,id,created_at,updated_at            #
    #                   FROM users--                                       #
    # FIX (v2): query parametrizat cu LIKE ?                              #
    # ------------------------------------------------------------------ #
    if role == 'MANAGER':
        raw_query = (
            "SELECT t.*, u.email AS owner_email "
            "FROM tickets t JOIN users u ON t.owner_id=u.id "
            "WHERE t.title LIKE '%" + q + "%' "
            "OR t.description LIKE '%" + q + "%' "
            "ORDER BY t.created_at DESC"
        )
    else:
        raw_query = (
            "SELECT t.*, u.email AS owner_email "
            "FROM tickets t JOIN users u ON t.owner_id=u.id "
            "WHERE t.owner_id='" + uid + "' "
            "AND (t.title LIKE '%" + q + "%' "
            "OR t.description LIKE '%" + q + "%') "
            "ORDER BY t.created_at DESC"
        )

    # [VULN #5] Eroarea DB propagata direct la client (debug=True)
    tickets = db.execute(raw_query).fetchall()

    log_audit(uid, 'SEARCH', 'ticket', None, f'Search: {q[:50]}',
              request.remote_addr, request.headers.get('User-Agent'))

    return render_template('tickets/list.html',
                           tickets=tickets,
                           statuses=STATUSES,
                           severities=SEVERITIES,
                           current_status='',
                           current_severity='',
                           search_query=q)


# ================================================================== #
#  CREATE TICKET                                                      #
# ================================================================== #
@tickets_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title       = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity    = request.form.get('severity', 'LOW')
        tags_raw    = request.form.get('tags', '')

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('tickets/create.html',
                                   severities=SEVERITIES, statuses=STATUSES)

        if severity not in SEVERITIES:
            severity = 'LOW'

        db        = get_db()
        ticket_id = gen_uuid()
        uid       = session['user_id']
        ts        = now_iso()

        db.execute(
            '''INSERT INTO tickets (id, title, description, severity, status, owner_id, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?)''',
            (ticket_id, title, description, severity, uid, ts, ts),
        )

        for tag in {t.strip() for t in tags_raw.split(',') if t.strip()}:
            db.execute('INSERT OR IGNORE INTO ticket_tags (ticket_id, tag) VALUES (?, ?)',
                       (ticket_id, tag[:50]))

        db.commit()

        log_audit(uid, 'TICKET_CREATE', 'ticket', ticket_id,
                  f'Created: {title[:50]}',
                  request.remote_addr, request.headers.get('User-Agent'))

        flash('Ticket created.', 'success')
        return redirect(url_for('tickets.view', ticket_id=ticket_id))

    return render_template('tickets/create.html',
                           severities=SEVERITIES, statuses=STATUSES)


# ================================================================== #
#  VIEW TICKET                                                        #
# ================================================================== #
@tickets_bp.route('/<ticket_id>')
@login_required
def view(ticket_id):
    db     = get_db()
    uid    = session['user_id']
    role   = session['user_role']

    ticket = db.execute(
        'SELECT t.*, u.email AS owner_email FROM tickets t JOIN users u ON t.owner_id=u.id WHERE t.id=?',
        (ticket_id,)
    ).fetchone()

    if not ticket:
        abort(404)

    # ------------------------------------------------------------------ #
    # [VULN #1] IDOR — nicio verificare ownership/rol.                    #
    # Un Analyst poate vedea tichetul altui user schimband ID-ul in URL.  #
    # FIX (v2):                                                           #
    #   if role != 'MANAGER' and ticket['owner_id'] != uid:              #
    #       log_audit(uid, 'UNAUTHORIZED_ACCESS', ...); abort(403)        #
    # ------------------------------------------------------------------ #

    tags = db.execute('SELECT tag FROM ticket_tags WHERE ticket_id=?', (ticket_id,)).fetchall()

    log_audit(uid, 'TICKET_VIEW', 'ticket', ticket_id,
              f'Viewed ticket {ticket_id[:8]}',
              request.remote_addr, request.headers.get('User-Agent'))

    return render_template('tickets/view.html', ticket=ticket, tags=tags, statuses=STATUSES)


# ================================================================== #
#  EDIT TICKET                                                        #
# ================================================================== #
@tickets_bp.route('/<ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(ticket_id):
    db     = get_db()
    uid    = session['user_id']
    role   = session['user_role']

    ticket = db.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
    if not ticket:
        abort(404)

    # ------------------------------------------------------------------ #
    # [VULN #1] IDOR — Analyst poate edita tichetul altui user.          #
    # FIX (v2): acelasi check ownership ca la view                        #
    # ------------------------------------------------------------------ #

    if request.method == 'POST':
        title       = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity    = request.form.get('severity', ticket['severity'])
        tags_raw    = request.form.get('tags', '')

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('tickets/edit.html', ticket=ticket,
                                   severities=SEVERITIES, statuses=STATUSES)

        if severity not in SEVERITIES:
            severity = ticket['severity']

        ts = now_iso()
        db.execute(
            'UPDATE tickets SET title=?, description=?, severity=?, updated_at=? WHERE id=?',
            (title, description, severity, ts, ticket_id),
        )

        db.execute('DELETE FROM ticket_tags WHERE ticket_id=?', (ticket_id,))
        for tag in {t.strip() for t in tags_raw.split(',') if t.strip()}:
            db.execute('INSERT OR IGNORE INTO ticket_tags (ticket_id, tag) VALUES (?, ?)',
                       (ticket_id, tag[:50]))

        db.commit()

        log_audit(uid, 'TICKET_UPDATE', 'ticket', ticket_id,
                  f'Updated: {title[:50]}',
                  request.remote_addr, request.headers.get('User-Agent'))

        flash('Ticket updated.', 'success')
        return redirect(url_for('tickets.view', ticket_id=ticket_id))

    tags_list = [r['tag'] for r in db.execute(
        'SELECT tag FROM ticket_tags WHERE ticket_id=?', (ticket_id,))]
    return render_template('tickets/edit.html', ticket=ticket,
                           tags_csv=', '.join(tags_list),
                           severities=SEVERITIES, statuses=STATUSES)


# ================================================================== #
#  CHANGE STATUS                                                      #
# ================================================================== #
@tickets_bp.route('/<ticket_id>/status', methods=['POST'])
@login_required
def change_status(ticket_id):
    db     = get_db()
    uid    = session['user_id']
    role   = session['user_role']

    ticket = db.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
    if not ticket:
        abort(404)

    # ------------------------------------------------------------------ #
    # [VULN #4A] CSRF — endpoint accepta POST fara token CSRF.            #
    # O pagina externa poate trimite acest request cand userul e logat.   #
    # FIX (v2): Flask-WTF CSRF token + SameSite=Lax cookie               #
    # ------------------------------------------------------------------ #

    if role != 'MANAGER' and ticket['owner_id'] != uid:
        log_audit(uid, 'UNAUTHORIZED_ACCESS', 'ticket', ticket_id,
                  'Unauthorized status change attempt',
                  request.remote_addr, request.headers.get('User-Agent'))
        abort(403)

    new_status = request.form.get('status', '')
    if new_status not in STATUSES:
        flash('Invalid status.', 'danger')
        return redirect(url_for('tickets.view', ticket_id=ticket_id))

    db.execute('UPDATE tickets SET status=?, updated_at=? WHERE id=?',
               (new_status, now_iso(), ticket_id))
    db.commit()

    log_audit(uid, 'TICKET_STATUS_CHANGE', 'ticket', ticket_id,
              f'Status → {new_status}',
              request.remote_addr, request.headers.get('User-Agent'))

    flash(f'Status changed to {new_status}.', 'success')
    return redirect(url_for('tickets.view', ticket_id=ticket_id))


# ================================================================== #
#  DELETE TICKET  (Manager only)                                      #
# ================================================================== #
@tickets_bp.route('/<ticket_id>/delete', methods=['POST'])
@manager_required
def delete(ticket_id):
    db = get_db()

    ticket = db.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
    if not ticket:
        abort(404)

    db.execute('DELETE FROM tickets WHERE id=?', (ticket_id,))
    db.commit()

    log_audit(session['user_id'], 'TICKET_DELETE', 'ticket', ticket_id,
              f'Deleted ticket {ticket_id[:8]}',
              request.remote_addr, request.headers.get('User-Agent'))

    flash('Ticket deleted.', 'success')
    return redirect(url_for('tickets.list_tickets'))
