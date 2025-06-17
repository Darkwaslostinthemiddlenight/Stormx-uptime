from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import sqlite3
import requests
import time
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import atexit

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production!
bcrypt = Bcrypt(app)

# Database setup
DATABASE = 'uptime_monitor.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        # Users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        ''')
        # Monitors table
        db.execute('''
            CREATE TABLE IF NOT EXISTS monitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                interval INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Status checks table
        db.execute('''
            CREATE TABLE IF NOT EXISTS status_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                monitor_id INTEGER NOT NULL,
                status_code INTEGER,
                response_time REAL,
                is_up INTEGER,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (monitor_id) REFERENCES monitors (id)
            )
        ''')
        db.commit()

init_db()

# Background monitoring thread
monitoring_active = True
monitor_thread = None

def monitor_websites():
    while monitoring_active:
        try:
            db = get_db()
            current_time = datetime.now()
            
            # Get all active monitors that need to be checked
            monitors = db.execute('''
                SELECT m.id, m.url, m.interval, MAX(sc.checked_at) as last_checked
                FROM monitors m
                LEFT JOIN status_checks sc ON m.id = sc.monitor_id
                WHERE m.is_active = 1
                GROUP BY m.id
                HAVING last_checked IS NULL OR 
                       (julianday(?) - julianday(last_checked)) * 86400 >= m.interval
            ''', (current_time,)).fetchall()
            
            for monitor in monitors:
                try:
                    start_time = time.time()
                    response = requests.get(monitor['url'], timeout=10)
                    response_time = time.time() - start_time
                    is_up = 1 if response.status_code < 400 else 0
                    
                    db.execute('''
                        INSERT INTO status_checks (monitor_id, status_code, response_time, is_up)
                        VALUES (?, ?, ?, ?)
                    ''', (monitor['id'], response.status_code, response_time, is_up))
                    db.commit()
                except requests.RequestException as e:
                    db.execute('''
                        INSERT INTO status_checks (monitor_id, status_code, response_time, is_up)
                        VALUES (?, ?, ?, ?)
                    ''', (monitor['id'], None, None, 0))
                    db.commit()
            
        except Exception as e:
            print(f"Monitoring error: {e}")
        
        time.sleep(5)  # Check every 5 seconds if any monitors need checking

def start_monitoring():
    global monitoring_active, monitor_thread
    monitoring_active = True
    if monitor_thread is None:
        monitor_thread = threading.Thread(target=monitor_websites)
        monitor_thread.daemon = True
        monitor_thread.start()

def stop_monitoring():
    global monitoring_active
    monitoring_active = False

start_monitoring()

# Cleanup on exit
atexit.register(stop_monitoring)

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>StormX - Login</title>
            <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;700&display=swap" rel="stylesheet">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Montserrat', sans-serif;
                }
                body {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                }
                .container {
                    width: 100%;
                    max-width: 400px;
                    padding: 2rem;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    animation: fadeIn 0.5s ease-in-out;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                h1 {
                    text-align: center;
                    margin-bottom: 2rem;
                    font-weight: 600;
                }
                .form-group {
                    margin-bottom: 1.5rem;
                }
                label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 400;
                }
                input {
                    width: 100%;
                    padding: 0.8rem;
                    border: none;
                    border-radius: 5px;
                    background: rgba(255, 255, 255, 0.2);
                    color: white;
                    font-size: 1rem;
                }
                input::placeholder {
                    color: rgba(255, 255, 255, 0.7);
                }
                button {
                    width: 100%;
                    padding: 0.8rem;
                    border: none;
                    border-radius: 5px;
                    background: white;
                    color: #667eea;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                button:hover {
                    background: rgba(255, 255, 255, 0.8);
                    transform: translateY(-2px);
                }
                .links {
                    margin-top: 1.5rem;
                    text-align: center;
                }
                .links a {
                    color: white;
                    text-decoration: none;
                    font-weight: 300;
                    transition: all 0.3s ease;
                }
                .links a:hover {
                    text-decoration: underline;
                }
                .alert {
                    padding: 0.8rem;
                    margin-bottom: 1.5rem;
                    border-radius: 5px;
                    text-align: center;
                }
                .alert-success {
                    background: rgba(46, 204, 113, 0.2);
                    border: 1px solid rgba(46, 204, 113, 0.3);
                }
                .alert-danger {
                    background: rgba(231, 76, 60, 0.2);
                    border: 1px solid rgba(231, 76, 60, 0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>StormX Login</h1>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST" action="{{ url_for('login') }}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" placeholder="Enter your username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Enter your password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <div class="links">
                    <p>Don't have an account? <a href="{{ url_for('signup') }}">Sign up</a></p>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, hashed_password))
            db.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>StormX - Sign Up</title>
            <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;700&display=swap" rel="stylesheet">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Montserrat', sans-serif;
                }
                body {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                }
                .container {
                    width: 100%;
                    max-width: 400px;
                    padding: 2rem;
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    animation: fadeIn 0.5s ease-in-out;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                h1 {
                    text-align: center;
                    margin-bottom: 2rem;
                    font-weight: 600;
                }
                .form-group {
                    margin-bottom: 1.5rem;
                }
                label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 400;
                }
                input {
                    width: 100%;
                    padding: 0.8rem;
                    border: none;
                    border-radius: 5px;
                    background: rgba(255, 255, 255, 0.2);
                    color: white;
                    font-size: 1rem;
                }
                input::placeholder {
                    color: rgba(255, 255, 255, 0.7);
                }
                button {
                    width: 100%;
                    padding: 0.8rem;
                    border: none;
                    border-radius: 5px;
                    background: white;
                    color: #667eea;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                button:hover {
                    background: rgba(255, 255, 255, 0.8);
                    transform: translateY(-2px);
                }
                .links {
                    margin-top: 1.5rem;
                    text-align: center;
                }
                .links a {
                    color: white;
                    text-decoration: none;
                    font-weight: 300;
                    transition: all 0.3s ease;
                }
                .links a:hover {
                    text-decoration: underline;
                }
                .alert {
                    padding: 0.8rem;
                    margin-bottom: 1.5rem;
                    border-radius: 5px;
                    text-align: center;
                }
                .alert-success {
                    background: rgba(46, 204, 113, 0.2);
                    border: 1px solid rgba(46, 204, 113, 0.3);
                }
                .alert-danger {
                    background: rgba(231, 76, 60, 0.2);
                    border: 1px solid rgba(231, 76, 60, 0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>StormX Sign Up</h1>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST" action="{{ url_for('signup') }}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" placeholder="Choose a username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" placeholder="Enter your email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" placeholder="Create a password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirm your password" required>
                    </div>
                    <button type="submit">Sign Up</button>
                </form>
                <div class="links">
                    <p>Already have an account? <a href="{{ url_for('login') }}">Log in</a></p>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    monitors = db.execute('''
        SELECT m.*, 
               (SELECT COUNT(*) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.is_up = 1) as up_count,
               (SELECT COUNT(*) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.is_up = 0) as down_count,
               (SELECT AVG(sc.response_time) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.response_time IS NOT NULL) as avg_response_time,
               (SELECT sc.is_up FROM status_checks sc WHERE sc.monitor_id = m.id ORDER BY sc.checked_at DESC LIMIT 1) as last_status
        FROM monitors m
        WHERE m.user_id = ?
        ORDER BY m.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>StormX - Dashboard</title>
            <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;700&display=swap" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Montserrat', sans-serif;
                }
                body {
                    background-color: #f5f7fa;
                    color: #333;
                }
                .navbar {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 1rem 2rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                .logo {
                    font-size: 1.8rem;
                    font-weight: 700;
                    background: linear-gradient(to right, #fff, #ddd);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .nav-links {
                    display: flex;
                    gap: 1.5rem;
                }
                .nav-links a {
                    color: white;
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.3s ease;
                }
                .nav-links a:hover {
                    opacity: 0.8;
                    transform: translateY(-2px);
                }
                .container {
                    max-width: 1200px;
                    margin: 2rem auto;
                    padding: 0 2rem;
                }
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 2rem;
                }
                .header h1 {
                    font-size: 2rem;
                    color: #444;
                }
                .btn {
                    padding: 0.6rem 1.2rem;
                    border: none;
                    border-radius: 5px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    text-decoration: none;
                    display: inline-block;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }
                .btn-secondary {
                    background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                }
                .btn-danger {
                    background: linear-gradient(135deg, #dc3545 0%, #a71d2a 100%);
                }
                .btn-success {
                    background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);
                }
                .monitors-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 1.5rem;
                }
                .monitor-card {
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
                    padding: 1.5rem;
                    transition: all 0.3s ease;
                }
                .monitor-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                }
                .monitor-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1rem;
                }
                .monitor-name {
                    font-weight: 600;
                    font-size: 1.2rem;
                    color: #444;
                }
                .monitor-status {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    margin-right: 0.5rem;
                }
                .status-up {
                    background-color: #28a745;
                    box-shadow: 0 0 10px rgba(40, 167, 69, 0.5);
                    animation: pulse 2s infinite;
                }
                .status-down {
                    background-color: #dc3545;
                    box-shadow: 0 0 10px rgba(220, 53, 69, 0.5);
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0% { transform: scale(0.95); }
                    50% { transform: scale(1.05); }
                    100% { transform: scale(0.95); }
                }
                .monitor-url {
                    color: #6c757d;
                    font-size: 0.9rem;
                    margin-bottom: 1rem;
                    word-break: break-all;
                }
                .monitor-stats {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 1rem;
                }
                .stat-item {
                    text-align: center;
                }
                .stat-value {
                    font-weight: 700;
                    font-size: 1.2rem;
                }
                .stat-label {
                    font-size: 0.8rem;
                    color: #6c757d;
                }
                .monitor-actions {
                    display: flex;
                    gap: 0.5rem;
                }
                .monitor-actions .btn {
                    padding: 0.4rem 0.8rem;
                    font-size: 0.8rem;
                }
                .response-time {
                    height: 5px;
                    background: #e9ecef;
                    border-radius: 5px;
                    margin-top: 0.5rem;
                    overflow: hidden;
                }
                .response-time-bar {
                    height: 100%;
                    background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
                    border-radius: 5px;
                    transition: width 0.5s ease;
                }
                .modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.5);
                    z-index: 1000;
                    justify-content: center;
                    align-items: center;
                }
                .modal-content {
                    background: white;
                    padding: 2rem;
                    border-radius: 10px;
                    width: 100%;
                    max-width: 500px;
                    box-shadow: 0 5px 25px rgba(0, 0, 0, 0.2);
                    animation: fadeIn 0.3s ease-out;
                }
                .modal-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1.5rem;
                }
                .modal-title {
                    font-size: 1.5rem;
                    font-weight: 600;
                }
                .close-btn {
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: #6c757d;
                }
                .form-group {
                    margin-bottom: 1.5rem;
                }
                .form-group label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                }
                .form-group input {
                    width: 100%;
                    padding: 0.8rem;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    font-size: 1rem;
                }
                .modal-footer {
                    display: flex;
                    justify-content: flex-end;
                    gap: 0.5rem;
                    margin-top: 2rem;
                }
                .alert {
                    padding: 1rem;
                    margin-bottom: 1.5rem;
                    border-radius: 5px;
                }
                .alert-success {
                    background: rgba(40, 167, 69, 0.1);
                    border: 1px solid rgba(40, 167, 69, 0.2);
                    color: #28a745;
                }
                .alert-danger {
                    background: rgba(220, 53, 69, 0.1);
                    border: 1px solid rgba(220, 53, 69, 0.2);
                    color: #dc3545;
                }
            </style>
        </head>
        <body>
            <nav class="navbar">
                <div class="logo">StormX Up</div>
                <div class="nav-links">
                    <a href="{{ url_for('dashboard') }}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                    <a href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a>
                </div>
            </nav>
            
            <div class="container">
                <div class="header">
                    <h1>Website Monitors</h1>
                    <button class="btn" onclick="openAddModal()"><i class="fas fa-plus"></i> Add Monitor</button>
                </div>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                {% if monitors %}
                    <div class="monitors-grid">
                        {% for monitor in monitors %}
                            <div class="monitor-card">
                                <div class="monitor-header">
                                    <div class="monitor-name">
                                        <span class="monitor-status {% if monitor['last_status'] == 1 %}status-up{% else %}status-down{% endif %}"></span>
                                        {{ monitor['name'] }}
                                    </div>
                                    <div class="monitor-actions">
                                        <button class="btn btn-secondary" onclick="editMonitor({{ monitor['id'] }}, '{{ monitor['name'] }}', '{{ monitor['url'] }}', {{ monitor['interval'] }}, {{ monitor['is_active'] }})">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="btn btn-danger" onclick="deleteMonitor({{ monitor['id'] }})">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="monitor-url">{{ monitor['url'] }}</div>
                                
                                <div class="monitor-stats">
                                    <div class="stat-item">
                                        <div class="stat-value">{{ monitor['up_count'] or 0 }}</div>
                                        <div class="stat-label">UP</div>
                                    </div>
                                    <div class="stat-item">
                                        <div class="stat-value">{{ monitor['down_count'] or 0 }}</div>
                                        <div class="stat-label">DOWN</div>
                                    </div>
                                    <div class="stat-item">
                                        <div class="stat-value">
                                            {% if monitor['avg_response_time'] %}
                                                {{ "%.2f"|format(monitor['avg_response_time']) }}s
                                            {% else %}
                                                -
                                            {% endif %}
                                        </div>
                                        <div class="stat-label">Avg. Response</div>
                                    </div>
                                    <div class="stat-item">
                                        <div class="stat-value">{{ monitor['interval'] }}s</div>
                                        <div class="stat-label">Interval</div>
                                    </div>
                                </div>
                                
                                {% if monitor['avg_response_time'] %}
                                    <div class="response-time">
                                        <div class="response-time-bar" style="width: {{ [monitor['avg_response_time'] * 100, 100]|min }}%"></div>
                                    </div>
                                {% endif %}
                                
                                <div class="monitor-actions">
                                    {% if monitor['is_active'] %}
                                        <button class="btn btn-secondary" onclick="toggleMonitor({{ monitor['id'] }}, 0)">
                                            <i class="fas fa-pause"></i> Pause
                                        </button>
                                    {% else %}
                                        <button class="btn btn-success" onclick="toggleMonitor({{ monitor['id'] }}, 1)">
                                            <i class="fas fa-play"></i> Resume
                                        </button>
                                    {% endif %}
                                    <a href="{{ url_for('monitor_details', monitor_id=monitor['id']) }}" class="btn">
                                        <i class="fas fa-chart-line"></i> Details
                                    </a>
                                </div>
                            </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <div style="text-align: center; padding: 3rem; background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);">
                        <h3 style="margin-bottom: 1rem; color: #6c757d;">No monitors yet</h3>
                        <p style="margin-bottom: 1.5rem; color: #6c757d;">Add your first website to start monitoring</p>
                        <button class="btn" onclick="openAddModal()"><i class="fas fa-plus"></i> Add Monitor</button>
                    </div>
                {% endif %}
            </div>
            
            <!-- Add Monitor Modal -->
            <div id="addModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <div class="modal-title">Add New Monitor</div>
                        <span class="close-btn" onclick="closeAddModal()">&times;</span>
                    </div>
                    <form id="addMonitorForm" action="{{ url_for('add_monitor') }}" method="POST">
                        <div class="form-group">
                            <label for="name">Website Name</label>
                            <input type="text" id="name" name="name" placeholder="e.g. My Awesome Site" required>
                        </div>
                        <div class="form-group">
                            <label for="url">Website URL</label>
                            <input type="url" id="url" name="url" placeholder="e.g. https://example.com" required>
                        </div>
                        <div class="form-group">
                            <label for="interval">Check Interval (seconds)</label>
                            <input type="number" id="interval" name="interval" min="30" value="60" required>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" onclick="closeAddModal()">Cancel</button>
                            <button type="submit" class="btn">Add Monitor</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Edit Monitor Modal -->
            <div id="editModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <div class="modal-title">Edit Monitor</div>
                        <span class="close-btn" onclick="closeEditModal()">&times;</span>
                    </div>
                    <form id="editMonitorForm" action="{{ url_for('edit_monitor') }}" method="POST">
                        <input type="hidden" id="edit_id" name="id">
                        <div class="form-group">
                            <label for="edit_name">Website Name</label>
                            <input type="text" id="edit_name" name="name" required>
                        </div>
                        <div class="form-group">
                            <label for="edit_url">Website URL</label>
                            <input type="url" id="edit_url" name="url" required>
                        </div>
                        <div class="form-group">
                            <label for="edit_interval">Check Interval (seconds)</label>
                            <input type="number" id="edit_interval" name="interval" min="30" required>
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="edit_is_active" name="is_active" value="1"> Active
                            </label>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
                            <button type="submit" class="btn">Save Changes</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <script>
                // Modal functions
                function openAddModal() {
                    document.getElementById('addModal').style.display = 'flex';
                }
                
                function closeAddModal() {
                    document.getElementById('addModal').style.display = 'none';
                }
                
                function openEditModal() {
                    document.getElementById('editModal').style.display = 'flex';
                }
                
                function closeEditModal() {
                    document.getElementById('editModal').style.display = 'none';
                }
                
                // Edit monitor
                function editMonitor(id, name, url, interval, isActive) {
                    document.getElementById('edit_id').value = id;
                    document.getElementById('edit_name').value = name;
                    document.getElementById('edit_url').value = url;
                    document.getElementById('edit_interval').value = interval;
                    document.getElementById('edit_is_active').checked = isActive === 1;
                    openEditModal();
                }
                
                // Delete monitor
                function deleteMonitor(id) {
                    if (confirm('Are you sure you want to delete this monitor?')) {
                        fetch('{{ url_for("delete_monitor") }}', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ id: id }),
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                location.reload();
                            } else {
                                alert('Error deleting monitor');
                            }
                        });
                    }
                }
                
                // Toggle monitor active status
                function toggleMonitor(id, status) {
                    fetch('{{ url_for("toggle_monitor") }}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ 
                            id: id,
                            is_active: status 
                        }),
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            location.reload();
                        } else {
                            alert('Error updating monitor');
                        }
                    });
                }
            </script>
        </body>
        </html>
    ''', monitors=monitors)

@app.route('/monitor/<int:monitor_id>')
def monitor_details(monitor_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    monitor = db.execute('''
        SELECT m.*, 
               (SELECT COUNT(*) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.is_up = 1) as up_count,
               (SELECT COUNT(*) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.is_up = 0) as down_count,
               (SELECT AVG(sc.response_time) FROM status_checks sc WHERE sc.monitor_id = m.id AND sc.response_time IS NOT NULL) as avg_response_time,
               (SELECT sc.is_up FROM status_checks sc WHERE sc.monitor_id = m.id ORDER BY sc.checked_at DESC LIMIT 1) as last_status
        FROM monitors m
        WHERE m.id = ? AND m.user_id = ?
    ''', (monitor_id, session['user_id'])).fetchone()
    
    if not monitor:
        flash('Monitor not found', 'danger')
        return redirect(url_for('dashboard'))
    
    checks = db.execute('''
        SELECT * FROM status_checks
        WHERE monitor_id = ?
        ORDER BY checked_at DESC
        LIMIT 50
    ''', (monitor_id,)).fetchall()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>StormX - Monitor Details</title>
            <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;700&display=swap" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Montserrat', sans-serif;
                }
                body {
                    background-color: #f5f7fa;
                    color: #333;
                }
                .navbar {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 1rem 2rem;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                .logo {
                    font-size: 1.8rem;
                    font-weight: 700;
                    background: linear-gradient(to right, #fff, #ddd);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }
                .nav-links {
                    display: flex;
                    gap: 1.5rem;
                }
                .nav-links a {
                    color: white;
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.3s ease;
                }
                .nav-links a:hover {
                    opacity: 0.8;
                    transform: translateY(-2px);
                }
                .container {
                    max-width: 1200px;
                    margin: 2rem auto;
                    padding: 0 2rem;
                }
                .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 2rem;
                }
                .header h1 {
                    font-size: 2rem;
                    color: #444;
                }
                .btn {
                    padding: 0.6rem 1.2rem;
                    border: none;
                    border-radius: 5px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    text-decoration: none;
                    display: inline-block;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }
                .btn-secondary {
                    background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                }
                .monitor-info {
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
                    padding: 1.5rem;
                    margin-bottom: 2rem;
                }
                .monitor-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1rem;
                }
                .monitor-name {
                    font-weight: 600;
                    font-size: 1.2rem;
                    color: #444;
                }
                .monitor-status {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    margin-right: 0.5rem;
                }
                .status-up {
                    background-color: #28a745;
                    box-shadow: 0 0 10px rgba(40, 167, 69, 0.5);
                    animation: pulse 2s infinite;
                }
                .status-down {
                    background-color: #dc3545;
                    box-shadow: 0 0 10px rgba(220, 53, 69, 0.5);
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0% { transform: scale(0.95); }
                    50% { transform: scale(1.05); }
                    100% { transform: scale(0.95); }
                }
                .monitor-url {
                    color: #6c757d;
                    font-size: 0.9rem;
                    margin-bottom: 1rem;
                    word-break: break-all;
                }
                .monitor-stats {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 1rem;
                }
                .stat-item {
                    text-align: center;
                }
                .stat-value {
                    font-weight: 700;
                    font-size: 1.2rem;
                }
                .stat-label {
                    font-size: 0.8rem;
                    color: #6c757d;
                }
                .checks-table {
                    width: 100%;
                    border-collapse: collapse;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
                    overflow: hidden;
                }
                .checks-table th, .checks-table td {
                    padding: 1rem;
                    text-align: left;
                    border-bottom: 1px solid #eee;
                }
                .checks-table th {
                    background: #f8f9fa;
                    font-weight: 600;
                    color: #495057;
                }
                .checks-table tr:last-child td {
                    border-bottom: none;
                }
                .status-badge {
                    display: inline-block;
                    padding: 0.3rem 0.6rem;
                    border-radius: 20px;
                    font-size: 0.8rem;
                    font-weight: 600;
                }
                .status-up-badge {
                    background: rgba(40, 167, 69, 0.1);
                    color: #28a745;
                }
                .status-down-badge {
                    background: rgba(220, 53, 69, 0.1);
                    color: #dc3545;
                }
                .response-time-cell {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .response-time-bar {
                    height: 5px;
                    background: #e9ecef;
                    border-radius: 5px;
                    flex-grow: 1;
                    overflow: hidden;
                }
                .response-time-fill {
                    height: 100%;
                    background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <nav class="navbar">
                <div class="logo">StormX Up</div>
                <div class="nav-links">
                    <a href="{{ url_for('dashboard') }}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                    <a href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a>
                </div>
            </nav>
            
            <div class="container">
                <div class="header">
                    <h1>Monitor Details</h1>
                    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
                </div>
                
                <div class="monitor-info">
                    <div class="monitor-header">
                        <div class="monitor-name">
                            <span class="monitor-status {% if monitor['last_status'] == 1 %}status-up{% else %}status-down{% endif %}"></span>
                            {{ monitor['name'] }}
                        </div>
                    </div>
                    <div class="monitor-url">{{ monitor['url'] }}</div>
                    
                    <div class="monitor-stats">
                        <div class="stat-item">
                            <div class="stat-value">{{ monitor['up_count'] or 0 }}</div>
                            <div class="stat-label">UP</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">{{ monitor['down_count'] or 0 }}</div>
                            <div class="stat-label">DOWN</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">
                                {% if monitor['avg_response_time'] %}
                                    {{ "%.2f"|format(monitor['avg_response_time']) }}s
                                {% else %}
                                    -
                                {% endif %}
                            </div>
                            <div class="stat-label">Avg. Response</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">{{ monitor['interval'] }}s</div>
                            <div class="stat-label">Interval</div>
                        </div>
                    </div>
                </div>
                
                <h2 style="margin-bottom: 1rem;">Recent Checks</h2>
                <table class="checks-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Status</th>
                            <th>Response Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for check in checks %}
                            <tr>
                                <td>{{ check['checked_at'] }}</td>
                                <td>
                                    {% if check['is_up'] == 1 %}
                                        <span class="status-badge status-up-badge">UP ({{ check['status_code'] }})</span>
                                    {% else %}
                                        <span class="status-badge status-down-badge">DOWN</span>
                                    {% endif %}
                                </td>
                                <td class="response-time-cell">
                                    {% if check['response_time'] %}
                                        {{ "%.2f"|format(check['response_time']) }}s
                                        <div class="response-time-bar">
                                            <div class="response-time-fill" style="width: {{ [check['response_time'] * 100, 100]|min }}%"></div>
                                        </div>
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
    ''', monitor=monitor, checks=checks)

@app.route('/add_monitor', methods=['POST'])
def add_monitor():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    name = request.form['name']
    url = request.form['url']
    interval = int(request.form['interval'])
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    db = get_db()
    try:
        db.execute('INSERT INTO monitors (user_id, name, url, interval) VALUES (?, ?, ?, ?)',
                  (session['user_id'], name, url, interval))
        db.commit()
        flash('Monitor added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Error adding monitor', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/edit_monitor', methods=['POST'])
def edit_monitor():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    monitor_id = request.form['id']
    name = request.form['name']
    url = request.form['url']
    interval = int(request.form['interval'])
    is_active = 1 if 'is_active' in request.form else 0
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    db = get_db()
    # Verify the monitor belongs to the user
    monitor = db.execute('SELECT * FROM monitors WHERE id = ? AND user_id = ?', 
                         (monitor_id, session['user_id'])).fetchone()
    if not monitor:
        flash('Monitor not found', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        db.execute('''
            UPDATE monitors 
            SET name = ?, url = ?, interval = ?, is_active = ?
            WHERE id = ?
        ''', (name, url, interval, is_active, monitor_id))
        db.commit()
        flash('Monitor updated successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Error updating monitor', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_monitor', methods=['POST'])
def delete_monitor():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    data = request.get_json()
    monitor_id = data['id']
    
    db = get_db()
    # Verify the monitor belongs to the user
    monitor = db.execute('SELECT * FROM monitors WHERE id = ? AND user_id = ?', 
                         (monitor_id, session['user_id'])).fetchone()
    if not monitor:
        return jsonify({'success': False, 'error': 'Monitor not found'})
    
    try:
        db.execute('DELETE FROM status_checks WHERE monitor_id = ?', (monitor_id,))
        db.execute('DELETE FROM monitors WHERE id = ?', (monitor_id,))
        db.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/toggle_monitor', methods=['POST'])
def toggle_monitor():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'})
    
    data = request.get_json()
    monitor_id = data['id']
    is_active = data['is_active']
    
    db = get_db()
    # Verify the monitor belongs to the user
    monitor = db.execute('SELECT * FROM monitors WHERE id = ? AND user_id = ?', 
                         (monitor_id, session['user_id'])).fetchone()
    if not monitor:
        return jsonify({'success': False, 'error': 'Monitor not found'})
    
    try:
        db.execute('UPDATE monitors SET is_active = ? WHERE id = ?', (is_active, monitor_id))
        db.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host = '0.0.0.0',debug=True,port=5000)
