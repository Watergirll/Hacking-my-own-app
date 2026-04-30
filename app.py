import os

from flask import Flask

from blueprints.auth import auth_bp
from blueprints.main import main_bp
from blueprints.tickets import tickets_bp
from db import close_db, init_db

app = Flask(__name__)

# ------------------------------------------------------------------ #
# [VULN #4B] SECRET_KEY hardcodat si slab → cookie de sesiune poate   #
# fi falsificat prin brute-force offline.                             #
# FIX (v2): generare cu os.urandom(32) si stocat in .env             #
# ------------------------------------------------------------------ #
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'deskly-dev-secret')

# DATABASE path: override via env var so Docker volume path works
app.config['DATABASE'] = os.environ.get('DATABASE', 'deskly_v1.db')

# ------------------------------------------------------------------ #
# [VULN #4B] Cookie de sesiune fara HttpOnly, Secure, SameSite →     #
# accesibil din JavaScript (XSS), trimis pe HTTP, fara protectie CSRF #
# FIX (v2): HttpOnly=True, Secure=True, SameSite='Lax'               #
# ------------------------------------------------------------------ #
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(tickets_bp)

app.teardown_appcontext(close_db)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    # [VULN #5] debug=True → stack trace complet afisat utilizatorului #
    # FIX (v2): debug=False + handler global de erori                  #
    app.run(debug=True, host='0.0.0.0', port=5000)
