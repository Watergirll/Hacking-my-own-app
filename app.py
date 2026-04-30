import os
import logging

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect

from blueprints.auth import auth_bp
from blueprints.main import main_bp
from blueprints.tickets import tickets_bp
from db import close_db, init_db

app = Flask(__name__)

# FIX #4B — SECRET_KEY generat aleatoriu (32 bytes), stocat in env
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32))

app.config['DATABASE'] = os.environ.get('DATABASE', 'deskly_v2.db')

# FIX #4B — Cookie flags securizate
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # True in productie cu HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minute

# FIX #4A — CSRF protection globala
csrf = CSRFProtect(app)

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(tickets_bp)

app.teardown_appcontext(close_db)

# FIX #5 — Error handler global: mesaje generice pentru client
@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f'Unhandled exception: {e}', exc_info=True)
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    with app.app_context():
        init_db()
    # FIX #5 — debug=False, fara stack trace vizibil clientului
    app.run(debug=False, host='0.0.0.0', port=5000)
