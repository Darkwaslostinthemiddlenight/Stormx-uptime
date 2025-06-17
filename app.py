import asyncio
from aiohttp import web, ClientSession
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional
import json
import hashlib
import secrets
import sqlite3
from pathlib import Path

# Database setup
DB_PATH = 'uptime_monitor.db'

def init_db():
    Path(DB_PATH).touch()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()

init_db()

@dataclass
class MonitoredSite:
    name: str
    url: str
    interval: int
    user_id: int
    paused: bool = False

@dataclass
class User:
    id: int
    username: str
    email: str

class UptimeMonitor:
    def __init__(self):
        self.monitored_sites: Dict[int, List[MonitoredSite]] = {}  # user_id -> sites
        self.status_data: Dict[int, Dict[str, Dict]] = {}  # user_id -> url -> data
        self.users: Dict[str, User] = {}  # username -> User
        self.sessions: Dict[str, int] = {}  # session_id -> user_id
        
        self.app = web.Application()
        self.app.add_routes([
            web.get('/', self.handle_index),
            web.get('/login', self.handle_login_page),
            web.post('/login', self.handle_login),
            web.get('/signup', self.handle_signup_page),
            web.post('/signup', self.handle_signup),
            web.post('/logout', self.handle_logout),
            
            # Authenticated routes
            web.get('/dashboard', self.handle_dashboard),
            web.post('/add_site', self.handle_add_site),
            web.get('/status', self.handle_status),
            web.get('/status_updates', self.handle_status_updates),
            web.get('/site_details/{url}', self.handle_site_details),
            web.post('/pause_site', self.handle_pause_site),
            web.post('/delete_site', self.handle_delete_site),
            web.post('/check_now', self.handle_check_now)
        ])
        
        # Load users from DB
        self.load_users()
        self.monitor_task = None
    
    def load_users(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email FROM users')
        for user_id, username, email in cursor.fetchall():
            self.users[username] = User(id=user_id, username=username, email=email)
            self.monitored_sites[user_id] = []
            self.status_data[user_id] = {}
        
        # Load monitored sites
        cursor.execute('SELECT name, url, interval, user_id, paused FROM monitored_sites')
        for name, url, interval, user_id, paused in cursor.fetchall():
            self.monitored_sites[user_id].append(
                MonitoredSite(name=name, url=url, interval=interval, user_id=user_id, paused=paused)
            )
        conn.close()
    
    def hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    
    def create_session(self, user_id: int) -> str:
        session_id = secrets.token_hex(32)
        expires_at = datetime.now().timestamp() + 3600 * 24 * 7  # 1 week
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)',
            (session_id, user_id, expires_at)
        )
        conn.commit()
        conn.close()
        
        self.sessions[session_id] = user_id
        return session_id
    
    def validate_session(self, request) -> Optional[int]:
        session_id = request.cookies.get('session_id')
        if not session_id:
            return None
        
        if session_id in self.sessions:
            return self.sessions[session_id]
        
        # Check DB for valid session
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT user_id FROM sessions WHERE session_id = ? AND expires_at > ?',
            (session_id, datetime.now().timestamp())
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_id = result[0]
            self.sessions[session_id] = user_id
            return user_id
        return None
    
    async def monitor_sites(self):
        while True:
            tasks = []
            for user_id, sites in self.monitored_sites.items():
                for site in sites:
                    if not site.paused:
                        tasks.append(self.check_site(site))
            
            await asyncio.gather(*tasks)
            
            # Find shortest interval among all users' sites
            intervals = []
            for sites in self.monitored_sites.values():
                intervals.extend(site.interval for site in sites if not site.paused)
            
            if intervals:
                await asyncio.sleep(min(intervals))
            else:
                await asyncio.sleep(10)
    
    async def check_site(self, site: MonitoredSite):
        try:
            start_time = time.time()
            async with ClientSession() as session:
                async with session.get(site.url, timeout=10) as response:
                    response_time = round((time.time() - start_time) * 1000, 2)
                    status = 'up' if response.status == 200 else 'down'
        except Exception as e:
            response_time = 0
            status = 'down'
            print(f"Error checking {site.url}: {str(e)}")
        
        self.update_site_status(site, status, response_time)
        return status
    
    def update_site_status(self, site: MonitoredSite, status: str, response_time: float):
        user_id = site.user_id
        if user_id not in self.status_data:
            self.status_data[user_id] = {}
        
        if site.url not in self.status_data[user_id]:
            self.status_data[user_id][site.url] = {
                'name': site.name,
                'history': [],
                'uptime_percent': 0,
                'last_checked': None,
                'response_time': 0,
                'total_checks': 0,
                'up_count': 0,
                'down_count': 0,
                'avg_response_time': 0,
                'last_status': status,
                'paused': site.paused
            }
        
        record = self.status_data[user_id][site.url]
        record['history'].append({
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'status': status,
            'response_time': response_time
        })
        
        if len(record['history']) > 100:
            record['history'].pop(0)
        
        record['total_checks'] += 1
        if status == 'up':
            record['up_count'] += 1
        else:
            record['down_count'] += 1
        
        record['uptime_percent'] = round((record['up_count'] / record['total_checks']) * 100, 2)
        record['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record['response_time'] = response_time
        record['last_status'] = status
        record['paused'] = site.paused
        
        successful_responses = [r['response_time'] for r in record['history'] if r['status'] == 'up']
        record['avg_response_time'] = round(sum(successful_responses) / len(successful_responses), 2) if successful_responses else 0
    
    # Authentication handlers
    async def handle_login_page(self, request):
        html = """
        <!DOCTYPE html>
        <html lang="en" data-theme="light">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login | Storm X Up</title>
            <style>
                :root {
                    --primary: #4361ee;
                    --secondary: #3a0ca3;
                    --success: #4cc9f0;
                    --danger: #f72585;
                    --warning: #f8961e;
                    --info: #4895ef;
                    --light: #f8f9fa;
                    --dark: #212529;
                    --gray: #6c757d;
                    --bg: #ffffff;
                    --text: #212529;
                    --card-bg: #ffffff;
                    --border: #dee2e6;
                }
                
                [data-theme="dark"] {
                    --primary: #3a86ff;
                    --secondary: #8338ec;
                    --success: #06d6a0;
                    --danger: #ef476f;
                    --warning: #ffd166;
                    --info: #118ab2;
                    --light: #343a40;
                    --dark: #f8f9fa;
                    --gray: #adb5bd;
                    --bg: #121212;
                    --text: #f8f9fa;
                    --card-bg: #1e1e1e;
                    --border: #343a40;
                }
                
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    transition: background-color 0.3s, color 0.3s, border-color 0.3s;
                }
                
                body {
                    background-color: var(--bg);
                    color: var(--text);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                
                .auth-container {
                    width: 100%;
                    max-width: 400px;
                    padding: 2rem;
                    animation: fadeIn 0.5s ease-out;
                }
                
                .auth-card {
                    background-color: var(--card-bg);
                    border-radius: 12px;
                    padding: 2rem;
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                    transform: translateY(0);
                    transition: transform 0.3s, box-shadow 0.3s;
                }
                
                .auth-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 15px 30px rgba(0, 0, 0, 0.15);
                }
                
                .auth-header {
                    text-align: center;
                    margin-bottom: 2rem;
                }
                
                .auth-title {
                    font-size: 1.75rem;
                    font-weight: 700;
                    margin-bottom: 0.5rem;
                    color: var(--primary);
                }
                
                .auth-subtitle {
                    color: var(--gray);
                    font-size: 0.9rem;
                }
                
                .form-group {
                    margin-bottom: 1.5rem;
                    position: relative;
                }
                
                .form-group label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                    color: var(--text);
                }
                
                .form-control {
                    width: 100%;
                    padding: 0.75rem 1rem;
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    font-size: 1rem;
                    background-color: var(--card-bg);
                    color: var(--text);
                    transition: border-color 0.3s, box-shadow 0.3s;
                }
                
                .form-control:focus {
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.2);
                }
                
                .btn {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    padding: 0.75rem 1.5rem;
                    border-radius: 8px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.3s;
                    border: none;
                    width: 100%;
                }
                
                .btn-primary {
                    background-color: var(--primary);
                    color: white;
                }
                
                .btn-primary:hover {
                    background-color: var(--secondary);
                    transform: translateY(-2px);
                }
                
                .btn-google {
                    background-color: #4285F4;
                    color: white;
                    margin-bottom: 1rem;
                }
                
                .btn-google:hover {
                    background-color: #357ABD;
                }
                
                .auth-footer {
                    text-align: center;
                    margin-top: 1.5rem;
                    color: var(--gray);
                    font-size: 0.9rem;
                }
                
                .auth-footer a {
                    color: var(--primary);
                    text-decoration: none;
                    font-weight: 500;
                }
                
                .auth-footer a:hover {
                    text-decoration: underline;
                }
                
                .divider {
                    display: flex;
                    align-items: center;
                    margin: 1.5rem 0;
                    color: var(--gray);
                    font-size: 0.8rem;
                }
                
                .divider::before, .divider::after {
                    content: "";
                    flex: 1;
                    border-bottom: 1px solid var(--border);
                }
                
                .divider::before {
                    margin-right: 0.5rem;
                }
                
                .divider::after {
                    margin-left: 0.5rem;
                }
                
                .theme-toggle {
                    position: fixed;
                    bottom: 30px;
                    left: 30px;
                    width: 50px;
                    height: 50px;
                    border-radius: 50%;
                    background-color: var(--primary);
                    color: white;
                    border: none;
                    font-size: 1.2rem;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
                    z-index: 90;
                }
                
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                
                .spinner {
                    border: 3px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top: 3px solid white;
                    width: 20px;
                    height: 20px;
                    animation: spin 1s linear infinite;
                    margin-right: 8px;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .error-message {
                    color: var(--danger);
                    font-size: 0.9rem;
                    margin-top: 0.5rem;
                    animation: shake 0.5s;
                }
                
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    20%, 60% { transform: translateX(-5px); }
                    40%, 80% { transform: translateX(5px); }
                }
                
                .success-message {
                    color: var(--success);
                    font-size: 0.9rem;
                    margin-top: 0.5rem;
                    animation: fadeIn 0.5s;
                }
            </style>
        </head>
        <body>
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <h1 class="auth-title">Welcome Back</h1>
                        <p class="auth-subtitle">Sign in to monitor your sites</p>
                    </div>
                    
                    <form id="loginForm">
                        <div class="form-group">
                            <label for="username">Username or Email</label>
                            <input type="text" id="username" class="form-control" placeholder="Enter your username or email" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" class="form-control" placeholder="Enter your password" required>
                        </div>
                        
                        <div id="loginError" class="error-message" style="display: none;"></div>
                        
                        <button type="submit" class="btn btn-primary" id="loginBtn">
                            <span id="loginBtnText">Sign In</span>
                        </button>
                    </form>
                    
                    <div class="divider">OR</div>
                    
                    <button class="btn btn-google">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="margin-right: 8px;">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Sign in with Google
                    </button>
                    
                    <div class="auth-footer">
                        Don't have an account? <a href="/signup">Sign up</a>
                    </div>
                </div>
            </div>
            
            <button class="theme-toggle" id="themeToggle">🌓</button>
            
            <script>
                // Theme management
                const themeToggle = document.getElementById('themeToggle');
                themeToggle.addEventListener('click', () => {
                    const html = document.documentElement;
                    const currentTheme = html.getAttribute('data-theme');
                    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
                    html.setAttribute('data-theme', newTheme);
                    localStorage.setItem('theme', newTheme);
                });
                
                // Set initial theme
                const savedTheme = localStorage.getItem('theme') || 'light';
                document.documentElement.setAttribute('data-theme', savedTheme);
                
                // Login form handling
                const loginForm = document.getElementById('loginForm');
                const loginBtn = document.getElementById('loginBtn');
                const loginBtnText = document.getElementById('loginBtnText');
                const loginError = document.getElementById('loginError');
                
                loginForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    
                    loginBtn.disabled = true;
                    loginBtnText.innerHTML = '<div class="spinner"></div> Signing In...';
                    loginError.style.display = 'none';
                    
                    try {
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                username: username,
                                password: password
                            }),
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            window.location.href = '/dashboard';
                        } else {
                            loginError.textContent = data.error || 'Login failed. Please try again.';
                            loginError.style.display = 'block';
                            loginBtn.disabled = false;
                            loginBtnText.textContent = 'Sign In';
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        loginError.textContent = 'Network error. Please try again.';
                        loginError.style.display = 'block';
                        loginBtn.disabled = false;
                        loginBtnText.textContent = 'Sign In';
                    }
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def handle_signup_page(self, request):
        html = """
        <!DOCTYPE html>
        <html lang="en" data-theme="light">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sign Up | Storm X Up</title>
            <style>
                :root {
                    --primary: #4361ee;
                    --secondary: #3a0ca3;
                    --success: #4cc9f0;
                    --danger: #f72585;
                    --warning: #f8961e;
                    --info: #4895ef;
                    --light: #f8f9fa;
                    --dark: #212529;
                    --gray: #6c757d;
                    --bg: #ffffff;
                    --text: #212529;
                    --card-bg: #ffffff;
                    --border: #dee2e6;
                }
                
                [data-theme="dark"] {
                    --primary: #3a86ff;
                    --secondary: #8338ec;
                    --success: #06d6a0;
                    --danger: #ef476f;
                    --warning: #ffd166;
                    --info: #118ab2;
                    --light: #343a40;
                    --dark: #f8f9fa;
                    --gray: #adb5bd;
                    --bg: #121212;
                    --text: #f8f9fa;
                    --card-bg: #1e1e1e;
                    --border: #343a40;
                }
                
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    transition: background-color 0.3s, color 0.3s, border-color 0.3s;
                }
                
                body {
                    background-color: var(--bg);
                    color: var(--text);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                
                .auth-container {
                    width: 100%;
                    max-width: 400px;
                    padding: 2rem;
                    animation: fadeIn 0.5s ease-out;
                }
                
                .auth-card {
                    background-color: var(--card-bg);
                    border-radius: 12px;
                    padding: 2rem;
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                    transform: translateY(0);
                    transition: transform 0.3s, box-shadow 0.3s;
                }
                
                .auth-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 15px 30px rgba(0, 0, 0, 0.15);
                }
                
                .auth-header {
                    text-align: center;
                    margin-bottom: 2rem;
                }
                
                .auth-title {
                    font-size: 1.75rem;
                    font-weight: 700;
                    margin-bottom: 0.5rem;
                    color: var(--primary);
                }
                
                .auth-subtitle {
                    color: var(--gray);
                    font-size: 0.9rem;
                }
                
                .form-group {
                    margin-bottom: 1.5rem;
                    position: relative;
                }
                
                .form-group label {
                    display: block;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                    color: var(--text);
                }
                
                .form-control {
                    width: 100%;
                    padding: 0.75rem 1rem;
                    border: 1px solid var(--border);
                    border-radius: 8px;
                    font-size: 1rem;
                    background-color: var(--card-bg);
                    color: var(--text);
                    transition: border-color 0.3s, box-shadow 0.3s;
                }
                
                .form-control:focus {
                    outline: none;
                    border-color: var(--primary);
                    box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.2);
                }
                
                .btn {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    padding: 0.75rem 1.5rem;
                    border-radius: 8px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.3s;
                    border: none;
                    width: 100%;
                }
                
                .btn-primary {
                    background-color: var(--primary);
                    color: white;
                }
                
                .btn-primary:hover {
                    background-color: var(--secondary);
                    transform: translateY(-2px);
                }
                
                .btn-google {
                    background-color: #4285F4;
                    color: white;
                    margin-bottom: 1rem;
                }
                
                .btn-google:hover {
                    background-color: #357ABD;
                }
                
                .auth-footer {
                    text-align: center;
                    margin-top: 1.5rem;
                    color: var(--gray);
                    font-size: 0.9rem;
                }
                
                .auth-footer a {
                    color: var(--primary);
                    text-decoration: none;
                    font-weight: 500;
                }
                
                .auth-footer a:hover {
                    text-decoration: underline;
                }
                
                .divider {
                    display: flex;
                    align-items: center;
                    margin: 1.5rem 0;
                    color: var(--gray);
                    font-size: 0.8rem;
                }
                
                .divider::before, .divider::after {
                    content: "";
                    flex: 1;
                    border-bottom: 1px solid var(--border);
                }
                
                .divider::before {
                    margin-right: 0.5rem;
                }
                
                .divider::after {
                    margin-left: 0.5rem;
                }
                
                .theme-toggle {
                    position: fixed;
                    bottom: 30px;
                    left: 30px;
                    width: 50px;
                    height: 50px;
                    border-radius: 50%;
                    background-color: var(--primary);
                    color: white;
                    border: none;
                    font-size: 1.2rem;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
                    z-index: 90;
                }
                
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                
                .spinner {
                    border: 3px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top: 3px solid white;
                    width: 20px;
                    height: 20px;
                    animation: spin 1s linear infinite;
                    margin-right: 8px;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .error-message {
                    color: var(--danger);
                    font-size: 0.9rem;
                    margin-top: 0.5rem;
                    animation: shake 0.5s;
                }
                
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    20%, 60% { transform: translateX(-5px); }
                    40%, 80% { transform: translateX(5px); }
                }
                
                .success-message {
                    color: var(--success);
                    font-size: 0.9rem;
                    margin-top: 0.5rem;
                    animation: fadeIn 0.5s;
                }
                
                .password-strength {
                    margin-top: 0.5rem;
                    height: 4px;
                    background-color: var(--border);
                    border-radius: 2px;
                    overflow: hidden;
                }
                
                .strength-meter {
                    height: 100%;
                    width: 0%;
                    transition: width 0.3s, background-color 0.3s;
                }
                
                .strength-weak {
                    background-color: var(--danger);
                    width: 33%;
                }
                
                .strength-medium {
                    background-color: var(--warning);
                    width: 66%;
                }
                
                .strength-strong {
                    background-color: var(--success);
                    width: 100%;
                }
            </style>
        </head>
        <body>
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <h1 class="auth-title">Create Account</h1>
                        <p class="auth-subtitle">Get started with your monitoring dashboard</p>
                    </div>
                    
                    <form id="signupForm">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" class="form-control" placeholder="Choose a username" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="email">Email</label>
                            <input type="email" id="email" class="form-control" placeholder="Enter your email" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" class="form-control" placeholder="Create a password" required>
                            <div class="password-strength">
                                <div class="strength-meter" id="strengthMeter"></div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="confirmPassword">Confirm Password</label>
                            <input type="password" id="confirmPassword" class="form-control" placeholder="Confirm your password" required>
                        </div>
                        
                        <div id="signupError" class="error-message" style="display: none;"></div>
                        <div id="signupSuccess" class="success-message" style="display: none;"></div>
                        
                        <button type="submit" class="btn btn-primary" id="signupBtn">
                            <span id="signupBtnText">Sign Up</span>
                        </button>
                    </form>
                    
                    <div class="divider">OR</div>
                    
                    <button class="btn btn-google">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="margin-right: 8px;">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Sign up with Google
                    </button>
                    
                    <div class="auth-footer">
                        Already have an account? <a href="/login">Sign in</a>
                    </div>
                </div>
            </div>
            
            <button class="theme-toggle" id="themeToggle">🌓</button>
            
            <script>
                // Theme management
                const themeToggle = document.getElementById('themeToggle');
                themeToggle.addEventListener('click', () => {
                    const html = document.documentElement;
                    const currentTheme = html.getAttribute('data-theme');
                    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
                    html.setAttribute('data-theme', newTheme);
                    localStorage.setItem('theme', newTheme);
                });
                
                // Set initial theme
                const savedTheme = localStorage.getItem('theme') || 'light';
                document.documentElement.setAttribute('data-theme', savedTheme);
                
                // Password strength meter
                const passwordInput = document.getElementById('password');
                const strengthMeter = document.getElementById('strengthMeter');
                
                passwordInput.addEventListener('input', () => {
                    const password = passwordInput.value;
                    let strength = 0;
                    
                    // Length check
                    if (password.length >= 8) strength += 1;
                    if (password.length >= 12) strength += 1;
                    
                    // Complexity checks
                    if (/[A-Z]/.test(password)) strength += 1;
                    if (/[0-9]/.test(password)) strength += 1;
                    if (/[^A-Za-z0-9]/.test(password)) strength += 1;
                    
                    // Update meter
                    strengthMeter.className = 'strength-meter';
                    if (password.length === 0) {
                        strengthMeter.style.width = '0%';
                    } else if (strength <= 2) {
                        strengthMeter.classList.add('strength-weak');
                    } else if (strength <= 4) {
                        strengthMeter.classList.add('strength-medium');
                    } else {
                        strengthMeter.classList.add('strength-strong');
                    }
                });
                
                // Signup form handling
                const signupForm = document.getElementById('signupForm');
                const signupBtn = document.getElementById('signupBtn');
                const signupBtnText = document.getElementById('signupBtnText');
                const signupError = document.getElementById('signupError');
                const signupSuccess = document.getElementById('signupSuccess');
                
                signupForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const username = document.getElementById('username').value;
                    const email = document.getElementById('email').value;
                    const password = document.getElementById('password').value;
                    const confirmPassword = document.getElementById('confirmPassword').value;
                    
                    // Basic validation
                    if (password !== confirmPassword) {
                        signupError.textContent = 'Passwords do not match';
                        signupError.style.display = 'block';
                        return;
                    }
                    
                    if (password.length < 8) {
                        signupError.textContent = 'Password must be at least 8 characters';
                        signupError.style.display = 'block';
                        return;
                    }
                    
                    signupBtn.disabled = true;
                    signupBtnText.innerHTML = '<div class="spinner"></div> Creating Account...';
                    signupError.style.display = 'none';
                    signupSuccess.style.display = 'none';
                    
                    try {
                        const response = await fetch('/signup', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                username: username,
                                email: email,
                                password: password
                            }),
                        });
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            signupSuccess.textContent = 'Account created successfully! Redirecting...';
                            signupSuccess.style.display = 'block';
                            signupForm.reset();
                            
                            setTimeout(() => {
                                window.location.href = '/login';
                            }, 1500);
                        } else {
                            signupError.textContent = data.error || 'Signup failed. Please try again.';
                            signupError.style.display = 'block';
                            signupBtn.disabled = false;
                            signupBtnText.textContent = 'Sign Up';
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        signupError.textContent = 'Network error. Please try again.';
                        signupError.style.display = 'block';
                        signupBtn.disabled = false;
                        signupBtnText.textContent = 'Sign Up';
                    }
                });
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    async def handle_login(self, request):
        data = await request.json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return web.json_response({'success': False, 'error': 'Username and password are required'})
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if username or email exists
        cursor.execute(
            'SELECT id, username, password_hash, salt FROM users WHERE username = ? OR email = ?',
            (username, username)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return web.json_response({'success': False, 'error': 'Invalid username or password'})
        
        user_id, db_username, db_hash, salt = user
        input_hash = self.hash_password(password, salt)
        
        if input_hash == db_hash:
            session_id = self.create_session(user_id)
            response = web.json_response({'success': True})
            response.set_cookie('session_id', session_id, httponly=True, secure=True, samesite='Strict')
            return response
        
        return web.json_response({'success': False, 'error': 'Invalid username or password'})
    
    async def handle_signup(self, request):
        data = await request.json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return web.json_response({'success': False, 'error': 'All fields are required'})
        
        if len(password) < 8:
            return web.json_response({'success': False, 'error': 'Password must be at least 8 characters'})
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT 1 FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return web.json_response({'success': False, 'error': 'Username or email already exists'})
        
        # Create user
        salt = secrets.token_hex(16)
        password_hash = self.hash_password(password, salt)
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, salt)
            )
            user_id = cursor.lastrowid
            
            # Create monitored_sites table if not exists
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                interval INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                paused BOOLEAN DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            ''')
            
            conn.commit()
            
            # Add to in-memory data
            self.users[username] = User(id=user_id, username=username, email=email)
            self.monitored_sites[user_id] = []
            self.status_data[user_id] = {}
            
            return web.json_response({'success': True})
        except Exception as e:
            conn.rollback()
            return web.json_response({'success': False, 'error': str(e)})
        finally:
            conn.close()
    
    async def handle_logout(self, request):
        session_id = request.cookies.get('session_id')
        if session_id:
            # Remove from DB
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            conn.commit()
            conn.close()
            
            # Remove from memory
            if session_id in self.sessions:
                del self.sessions[session_id]
        
        response = web.json_response({'success': True})
        response.del_cookie('session_id')
        return response
    
    async def handle_index(self, request):
        user_id = self.validate_session(request)
        if user_id:
            return web.HTTPFound('/dashboard')
        return web.HTTPFound('/login')
    
    async def handle_dashboard(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.HTTPFound('/login')
        
        # Same HTML as before but now user-specific
        html = """
        <!DOCTYPE html>
        <html lang="en" data-theme="light">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Storm X Up</title>
            <style>
                /* All previous CSS remains the same */
            </style>
        </head>
        <body>
            <header>
                <h1>Storm X Up</h1>
                <div style="position: absolute; right: 20px; top: 20px;">
                    <button class="btn btn-secondary" id="logoutBtn" style="padding: 8px 16px;">Logout</button>
                </div>
            </header>
            
            <!-- Rest of the dashboard HTML remains the same -->
            
            <script>
                // Add logout functionality
                document.getElementById('logoutBtn').addEventListener('click', async () => {
                    try {
                        const response = await fetch('/logout', {
                            method: 'POST',
                            credentials: 'same-origin'
                        });
                        
                        if (response.ok) {
                            window.location.href = '/login';
                        }
                    } catch (error) {
                        console.error('Logout error:', error);
                    }
                });
                
                // All previous JavaScript remains the same
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')
    
    # All other handlers need to be updated to check user_id and use user-specific data
    async def handle_add_site(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        data = await request.json()
        # Check if site already exists for this user
        if any(site.url == data['url'] for site in self.monitored_sites.get(user_id, [])):
            return web.json_response({'success': False, 'error': 'Site already exists'})
        
        # Add to DB
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO monitored_sites (name, url, interval, user_id) VALUES (?, ?, ?, ?)',
                (data['name'], data['url'], int(data['interval']), user_id)
            )
            conn.commit()
            
            # Add to in-memory data
            site = MonitoredSite(
                name=data['name'],
                url=data['url'],
                interval=int(data['interval']),
                user_id=user_id
            )
            if user_id not in self.monitored_sites:
                self.monitored_sites[user_id] = []
            self.monitored_sites[user_id].append(site)
            
            return web.json_response({'success': True})
        except Exception as e:
            conn.rollback()
            return web.json_response({'success': False, 'error': str(e)})
        finally:
            conn.close()
    
    async def handle_status(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        return web.json_response({
            'sites': [{'name': s.name, 'url': s.url, 'interval': s.interval, 'paused': s.paused} 
                     for s in self.monitored_sites.get(user_id, [])],
            'status_data': self.status_data.get(user_id, {})
        })
    
    async def handle_status_updates(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.HTTPUnauthorized()
        
        response = web.StreamResponse(
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            }
        )
        await response.prepare(request)
        
        try:
            while True:
                data = {
                    'sites': [{'name': s.name, 'url': s.url, 'interval': s.interval, 'paused': s.paused} 
                             for s in self.monitored_sites.get(user_id, [])],
                    'status_data': self.status_data.get(user_id, {})
                }
                message = f"data: {json.dumps(data)}\n\n"
                await response.write(message.encode('utf-8'))
                await asyncio.sleep(5)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        
        return response
    
    async def handle_site_details(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        url = request.match_info['url']
        details = self.status_data.get(user_id, {}).get(url, {})
        return web.json_response({
            'name': details.get('name', url),
            'url': url,
            'last_status': details.get('last_status', 'unknown'),
            'uptime_percent': details.get('uptime_percent', 0),
            'avg_response_time': details.get('avg_response_time', 0),
            'total_checks': details.get('total_checks', 0),
            'up_count': details.get('up_count', 0),
            'down_count': details.get('down_count', 0),
            'last_checked': details.get('last_checked', 'Never'),
            'history': details.get('history', []),
            'paused': next((site.paused for site in self.monitored_sites.get(user_id, []) 
                          if site.url == url), False)
        })
    
    async def handle_pause_site(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        # Update in DB
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE monitored_sites SET paused = NOT paused WHERE url = ? AND user_id = ?',
                (url, user_id)
            )
            if cursor.rowcount == 0:
                return web.json_response({'success': False, 'error': 'Site not found'})
            conn.commit()
            
            # Update in-memory data
            for site in self.monitored_sites.get(user_id, []):
                if site.url == url:
                    site.paused = not site.paused
                    if url in self.status_data.get(user_id, {}):
                        self.status_data[user_id][url]['paused'] = site.paused
                    return web.json_response({'success': True, 'paused': site.paused})
            
            return web.json_response({'success': False, 'error': 'Site not found'})
        except Exception as e:
            conn.rollback()
            return web.json_response({'success': False, 'error': str(e)})
        finally:
            conn.close()
    
    async def handle_delete_site(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        # Delete from DB
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'DELETE FROM monitored_sites WHERE url = ? AND user_id = ?',
                (url, user_id)
            )
            conn.commit()
            
            # Delete from in-memory data
            self.monitored_sites[user_id] = [site for site in self.monitored_sites.get(user_id, []) 
                                           if site.url != url]
            if url in self.status_data.get(user_id, {}):
                del self.status_data[user_id][url]
            
            return web.json_response({'success': True})
        except Exception as e:
            conn.rollback()
            return web.json_response({'success': False, 'error': str(e)})
        finally:
            conn.close()
    
    async def handle_check_now(self, request):
        user_id = self.validate_session(request)
        if not user_id:
            return web.json_response({'success': False, 'error': 'Unauthorized'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        site = next((site for site in self.monitored_sites.get(user_id, []) 
                   if site.url == url), None)
        if site:
            status = await self.check_site(site)
            return web.json_response({'success': True, 'status': status})
        
        return web.json_response({'success': False, 'error': 'Site not found'})
    
    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 5000)
        self.monitor_task = asyncio.create_task(self.monitor_sites())
        await site.start()
        print("Server started at http://0.0.0.0:5000")

if __name__ == '__main__':
    try:
        monitor = UptimeMonitor()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(monitor.start())
        loop.run_forever()
    except KeyboardInterrupt:
        print("Server stopped")
