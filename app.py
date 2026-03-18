from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from logs.analyzer.detector import (get_log_overview, get_all_alerts, search_logs, load_logs, get_ip_analysis, 
                                      get_attack_timeline, get_attack_heatmap, get_top_attackers, get_country_from_ip,
                                      detect_brute_force_pattern, detect_credential_stuffing, detect_impossible_travel,
                                      detect_sql_injection, detect_xss)
import sqlite3
import os

app = Flask(__name__, template_folder="logs/analyzer/templates", static_folder="logs/analyzer/templates/static")
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            alert_message TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            ip_address TEXT,
            username TEXT,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()
        # Create default admin if not exists
        if not db.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone():
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', generate_password_hash('password')))
            db.commit()

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        return User(user['id'], user['username'], user['password_hash'])
    return None

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, generate_password_hash(password)))
            db.commit()
            flash('Account created successfully. Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
            return redirect(url_for('signup'))
    return render_template("signup.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['password_hash'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/overview")
@login_required
def overview():
    overview_data = get_log_overview("logs/sample.log")
    return render_template("overview.html", data=overview_data)

@app.route("/alerts")
@login_required
def alerts():
    alerts = get_all_alerts("logs/sample.log")
    return render_template("alerts.html", title="All Alerts", alerts=alerts)

@app.route("/search", methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        query = {
            'ip': request.form.get('ip', ''),
            'username': request.form.get('username', ''),
            'timestamp': request.form.get('timestamp', ''),
            'keyword': request.form.get('keyword', '')
        }
        filters = {
            'time_range': request.form.get('time_range', ''),
            'log_type': request.form.get('log_type', '')
        }
        results = search_logs("logs/sample.log", query, filters)
        return render_template("search_results.html", results=results, query=query, filters=filters)
    return render_template("search.html")

@app.route("/logs")
@login_required
def logs():
    all_logs = load_logs("logs/sample.log")
    return render_template("logs.html", logs=all_logs)

@app.route("/ip_analysis")
@login_required
def ip_analysis():
    analysis = get_ip_analysis("logs/sample.log")
    return render_template("ip_analysis.html", analysis=analysis)

@app.route("/bruteforce")
@login_required
def bruteforce():
    alerts = detect_brute_force_pattern("logs/sample.log")
    return render_template("alerts.html", title="Brute Force Attacks", alerts=alerts)

@app.route("/sql_injection")
@login_required
def sql_injection():
    alerts = detect_sql_injection("logs/sample.log")
    return render_template("alerts.html", title="SQL Injection Attempts", alerts=alerts)

@app.route("/xss")
@login_required
def xss():
    alerts = detect_xss("logs/sample.log")
    return render_template("alerts.html", title="XSS Attempts", alerts=alerts)

@app.route("/visualization")
@login_required
def visualization():
    timeline = get_attack_timeline("logs/sample.log")
    heatmap = get_attack_heatmap("logs/sample.log")
    top_attackers = get_top_attackers("logs/sample.log")
    return render_template("visualization.html", timeline=timeline, heatmap=heatmap, top_attackers=top_attackers)

@app.route("/incidents")
@login_required
def incidents():
    db = get_db()
    incidents_list = db.execute('SELECT * FROM incidents ORDER BY created_at DESC').fetchall()
    return render_template("incidents.html", incidents=incidents_list)

@app.route("/create_incident", methods=['GET', 'POST'])
@login_required
def create_incident():
    if request.method == 'POST':
        alert_type = request.form.get('alert_type')
        alert_message = request.form.get('alert_message')
        severity = request.form.get('severity')
        ip_address = request.form.get('ip_address')
        username = request.form.get('username')
        notes = request.form.get('notes')
        
        db = get_db()
        db.execute('''INSERT INTO incidents (alert_type, alert_message, severity, ip_address, username, notes)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   (alert_type, alert_message, severity, ip_address, username, notes))
        db.commit()
        flash('Incident created successfully')
        return redirect(url_for('incidents'))
    return render_template("create_incident.html")

@app.route("/incident/<int:incident_id>", methods=['GET', 'POST'])
@login_required
def view_incident(incident_id):
    db = get_db()
    incident = db.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,)).fetchone()
    
    if request.method == 'POST':
        status = request.form.get('status')
        notes = request.form.get('notes')
        db.execute('UPDATE incidents SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                   (status, notes, incident_id))
        db.commit()
        flash('Incident updated successfully')
        incident = db.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,)).fetchone()
    
    # Get related logs for drill-down
    if incident and incident['ip_address']:
        logs = load_logs("logs/sample.log")
        related_logs = [log for log in logs if log['ip'] == incident['ip_address']]
    else:
        related_logs = []
    
    return render_template("view_incident.html", incident=incident, related_logs=related_logs)

@app.route("/geo_map")
@login_required
def geo_map():
    alerts = get_all_alerts("logs/sample.log")
    ip_locations = {}
    for alert in alerts:
        if 'ip' in alert:
            ip = alert['ip']
            if ip not in ip_locations:
                ip_locations[ip] = {
                    'country': get_country_from_ip(ip),
                    'count': 0,
                    'severity': alert['severity']
                }
            ip_locations[ip]['count'] += 1
    
    return render_template("geo_map.html", ip_locations=ip_locations)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)