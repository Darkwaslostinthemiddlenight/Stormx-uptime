import asyncio
from aiohttp import web, ClientSession
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional
import json
import hashlib
import secrets
import os
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage

# Configuration
COOKIE_SECRET = secrets.token_bytes(32)  # For production, use a fixed secret
DB_FILE = "users.db"

@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    monitors: List[dict]
    status_data: Dict[str, Dict]

@dataclass
class MonitoredSite:
    name: str
    url: str
    interval: int
    paused: bool = False

class UptimeMonitor:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.load_users()
        
        middlewares = [
            session_middleware(EncryptedCookieStorage(COOKIE_SECRET))
        ]
        
        self.app = web.Application(middlewares=middlewares)
        self.setup_routes()
        self.monitor_task = None

    def setup_routes(self):
        self.app.add_routes([
            web.get('/', self.handle_index),
            web.get('/login', self.handle_login_page),
            web.post('/login', self.handle_login),
            web.get('/signup', self.handle_signup_page),
            web.post('/signup', self.handle_signup),
            web.get('/logout', self.handle_logout),
            web.post('/add_site', self.handle_add_site),
            web.get('/status', self.handle_status),
            web.get('/status_updates', self.handle_status_updates),
            web.get('/site_details/{url}', self.handle_site_details),
            web.post('/pause_site', self.handle_pause_site),
            web.post('/delete_site', self.handle_delete_site),
            web.post('/check_now', self.handle_check_now),
            web.static('/static', 'static')
        ])

    def load_users(self):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, 'r') as f:
                data = json.load(f)
                self.users = {
                    username: User(
                        username=user['username'],
                        password_hash=user['password_hash'],
                        salt=user['salt'],
                        monitors=[MonitoredSite(**m) for m in user.get('monitors', [])],
                        status_data=user.get('status_data', {})
                    )
                    for username, user in data.items()
                }

    def save_users(self):
        data = {
            username: {
                'username': user.username,
                'password_hash': user.password_hash,
                'salt': user.salt,
                'monitors': [{
                    'name': m.name,
                    'url': m.url,
                    'interval': m.interval,
                    'paused': m.paused
                } for m in user.monitors],
                'status_data': user.status_data
            }
            for username, user in self.users.items()
        }
        with open(DB_FILE, 'w') as f:
            json.dump(data, f)

    def hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()

    async def get_current_user(self, request) -> Optional[User]:
        session = await get_session(request)
        username = session.get('username')
        return self.users.get(username) if username else None

    async def monitor_sites(self):
        while True:
            tasks = []
            for user in self.users.values():
                for site in user.monitors:
                    if not site.paused:
                        tasks.append(self.check_site(user, site))
            
            await asyncio.gather(*tasks)
            await asyncio.sleep(10)  # Check every 10 seconds

    async def check_site(self, user: User, site: MonitoredSite):
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
        
        self.update_site_status(user, site, status, response_time)
        return status

    def update_site_status(self, user: User, site: MonitoredSite, status: str, response_time: float):
        if site.url not in user.status_data:
            user.status_data[site.url] = {
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
        
        record = user.status_data[site.url]
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
        
        # Save after each update
        self.save_users()

    async def handle_index(self, request):
        user = await self.get_current_user(request)
        if not user:
            raise web.HTTPFound('/login')
        
        with open('templates/dashboard.html', 'r') as f:
            html = f.read()
        return web.Response(text=html, content_type='text/html')

    async def handle_login_page(self, request):
        with open('templates/login.html', 'r') as f:
            html = f.read()
        return web.Response(text=html, content_type='text/html')

    async def handle_login(self, request):
        data = await request.post()
        username = data.get('username')
        password = data.get('password')
        
        user = self.users.get(username)
        if not user or user.password_hash != self.hash_password(password, user.salt):
            return web.Response(text="Invalid username or password", status=401)
        
        session = await get_session(request)
        session['username'] = username
        
        raise web.HTTPFound('/')

    async def handle_signup_page(self, request):
        with open('templates/signup.html', 'r') as f:
            html = f.read()
        return web.Response(text=html, content_type='text/html')

    async def handle_signup(self, request):
        data = await request.post()
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if password != confirm_password:
            return web.Response(text="Passwords don't match", status=400)
        
        if username in self.users:
            return web.Response(text="Username already exists", status=400)
        
        salt = secrets.token_hex(16)
        password_hash = self.hash_password(password, salt)
        
        self.users[username] = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            monitors=[],
            status_data={}
        )
        self.save_users()
        
        session = await get_session(request)
        session['username'] = username
        
        raise web.HTTPFound('/')

    async def handle_logout(self, request):
        session = await get_session(request)
        session.pop('username', None)
        raise web.HTTPFound('/login')

    async def handle_add_site(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        data = await request.json()
        if any(site.url == data['url'] for site in user.monitors):
            return web.json_response({'success': False, 'error': 'Site already exists'})
        
        user.monitors.append(MonitoredSite(
            name=data['name'],
            url=data['url'],
            interval=int(data['interval'])
        ))
        self.save_users()
        
        # Perform initial check
        status = await self.check_site(user, user.monitors[-1])
        return web.json_response({'success': True, 'status': status})

    async def handle_status(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        return web.json_response({
            'sites': [{
                'name': s.name,
                'url': s.url,
                'interval': s.interval,
                'paused': s.paused
            } for s in user.monitors],
            'status_data': user.status_data
        })

    async def handle_status_updates(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.Response(status=401)
        
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
                    'sites': [{
                        'name': s.name,
                        'url': s.url,
                        'interval': s.interval,
                        'paused': s.paused
                    } for s in user.monitors],
                    'status_data': user.status_data
                }
                message = f"data: {json.dumps(data)}\n\n"
                await response.write(message.encode('utf-8'))
                await asyncio.sleep(5)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        
        return response

    async def handle_site_details(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        url = request.match_info['url']
        details = user.status_data.get(url, {})
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
            'paused': next((s.paused for s in user.monitors if s.url == url), False)
        })

    async def handle_pause_site(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        for site in user.monitors:
            if site.url == url:
                site.paused = not site.paused
                if url in user.status_data:
                    user.status_data[url]['paused'] = site.paused
                self.save_users()
                return web.json_response({'success': True, 'paused': site.paused})
        
        return web.json_response({'success': False, 'error': 'Site not found'})

    async def handle_delete_site(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        user.monitors = [s for s in user.monitors if s.url != url]
        if url in user.status_data:
            del user.status_data[url]
        self.save_users()
        
        return web.json_response({'success': True})

    async def handle_check_now(self, request):
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        
        data = await request.json()
        url = data['url']
        
        site = next((s for s in user.monitors if s.url == url), None)
        if site:
            status = await self.check_site(user, site)
            return web.json_response({'success': True, 'status': status})
        
        return web.json_response({'success': False, 'error': 'Site not found'})

    async def start(self):
        # Create necessary directories
        os.makedirs('templates', exist_ok=True)
        os.makedirs('static/css', exist_ok=True)
        os.makedirs('static/js', exist_ok=True)
        
        # Create template files if they don't exist
        self.create_templates()
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 5000)
        self.monitor_task = asyncio.create_task(self.monitor_sites())
        await site.start()
        print("Server started at http://0.0.0.0:5000")

    def create_templates(self):
        # Create login.html
        if not os.path.exists('templates/login.html'):
            with open('templates/login.html', 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Storm X Up</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/auth.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <h1>Welcome Back</h1>
                <p>Login to monitor your sites</p>
            </div>
            
            <form class="auth-form" method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                    <div class="underline"></div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                    <div class="underline"></div>
                </div>
                
                <button type="submit" class="auth-btn">Login</button>
            </form>
            
            <div class="auth-footer">
                <p>Don't have an account? <a href="/signup">Sign up</a></p>
            </div>
        </div>
        
        <div class="auth-decoration">
            <div class="circle circle-1"></div>
            <div class="circle circle-2"></div>
            <div class="circle circle-3"></div>
            <div class="logo">Storm X Up</div>
        </div>
    </div>
    
    <script src="/static/js/auth.js"></script>
</body>
</html>""")

        # Create signup.html
        if not os.path.exists('templates/signup.html'):
            with open('templates/signup.html', 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up | Storm X Up</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/auth.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <h1>Create Account</h1>
                <p>Start monitoring your sites</p>
            </div>
            
            <form class="auth-form" method="POST" action="/signup">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                    <div class="underline"></div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                    <div class="underline"></div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                    <div class="underline"></div>
                </div>
                
                <button type="submit" class="auth-btn">Sign Up</button>
            </form>
            
            <div class="auth-footer">
                <p>Already have an account? <a href="/login">Login</a></p>
            </div>
        </div>
        
        <div class="auth-decoration">
            <div class="circle circle-1"></div>
            <div class="circle circle-2"></div>
            <div class="circle circle-3"></div>
            <div class="logo">Storm X Up</div>
        </div>
    </div>
    
    <script src="/static/js/auth.js"></script>
</body>
</html>""")

        # Create dashboard.html
        if not os.path.exists('templates/dashboard.html'):
            with open('templates/dashboard.html', 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard | Storm X Up</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/dashboard.css">
</head>
<body>
    <div class="navbar">
        <div class="navbar-brand">Storm X Up</div>
        <div class="navbar-actions">
            <span id="username-display"></span>
            <button id="logout-btn">Logout</button>
            <button id="theme-toggle">🌓</button>
        </div>
    </div>
    
    <div class="container">
        <div class="menu-bar">
            <button class="menu-btn active" data-view="status">Status</button>
            <button class="menu-btn" data-view="add">Add Monitor</button>
        </div>
        
        <div class="status-container" id="statusView">
            <h2>Monitor Status</h2>
            <div class="status-grid" id="statusGrid">
                <p class="no-monitors">No monitors added yet. Click the + button to add one.</p>
            </div>
        </div>
        
        <div class="add-container" id="addView" style="display: none;">
            <div class="form-container fade-in">
                <h2>Add New Monitor</h2>
                <form id="addMonitorForm">
                    <div class="form-group">
                        <label for="monitorName">Monitor Name</label>
                        <input type="text" id="monitorName" placeholder="e.g. My API" required>
                    </div>
                    <div class="form-group">
                        <label for="monitorUrl">Website URL</label>
                        <input type="url" id="monitorUrl" placeholder="https://example.com" required>
                    </div>
                    <div class="form-group">
                        <label for="monitorInterval">Check Interval</label>
                        <select id="monitorInterval">
                            <option value="30">30 seconds</option>
                            <option value="60" selected>1 minute</option>
                            <option value="300">5 minutes</option>
                            <option value="600">10 minutes</option>
                            <option value="1800">30 minutes</option>
                            <option value="3600">1 hour</option>
                        </select>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" id="cancelAdd">Cancel</button>
                        <button type="submit" class="btn btn-primary" id="submitAdd">Add Monitor</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <button class="add-btn" id="floatingAddBtn">+</button>
    
    <div class="modal" id="addModal">
        <div class="modal-content">
            <h2>Add New Monitor</h2>
            <form id="modalAddForm">
                <div class="form-group">
                    <label for="modalMonitorName">Monitor Name</label>
                    <input type="text" id="modalMonitorName" placeholder="e.g. My API" required>
                </div>
                <div class="form-group">
                    <label for="modalMonitorUrl">Website URL</label>
                    <input type="url" id="modalMonitorUrl" placeholder="https://example.com" required>
                </div>
                <div class="form-group">
                    <label for="modalMonitorInterval">Check Interval</label>
                    <select id="modalMonitorInterval">
                        <option value="30">30 seconds</option>
                        <option value="60" selected>1 minute</option>
                        <option value="300">5 minutes</option>
                        <option value="600">10 minutes</option>
                        <option value="1800">30 minutes</option>
                        <option value="3600">1 hour</option>
                    </select>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" id="modalCancel">Cancel</button>
                    <button type="submit" class="btn btn-primary" id="modalSubmit">Add Monitor</button>
                </div>
            </form>
        </div>
    </div>
    
    <div class="details-modal" id="detailsModal">
        <div class="details-content">
            <div class="details-header">
                <h2 id="detailsTitle">Monitor Details</h2>
                <button class="close-btn" id="closeDetails">&times;</button>
            </div>
            <div id="detailsContent">
                <!-- Details content will be added here dynamically -->
            </div>
        </div>
    </div>
    
    <script src="/static/js/dashboard.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</body>
</html>""")

        # Create CSS files
        if not os.path.exists('static/css/auth.css'):
            with open('static/css/auth.css', 'w') as f:
                f.write("""/* Auth Page Styles */
:root {
    --primary: #4361ee;
    --primary-dark: #3a0ca3;
    --secondary: #4cc9f0;
    --danger: #f72585;
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
    --primary-dark: #8338ec;
    --secondary: #06d6a0;
    --danger: #ef476f;
    --light: #343a40;
    --dark: #f8f9fa;
    --gray: #adb5bd;
    --bg: #121212;
    --text: #f8f9fa;
    --card-bg: #1e1e1e;
    --border: #343a40;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Poppins', sans-serif;
    transition: all 0.3s ease;
}

body {
    background-color: var(--bg);
    color: var(--text);
    height: 100vh;
    overflow: hidden;
}

.auth-container {
    display: flex;
    height: 100vh;
}

.auth-card {
    width: 400px;
    padding: 40px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    background-color: var(--card-bg);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    z-index: 2;
}

.auth-header {
    margin-bottom: 30px;
    text-align: center;
}

.auth-header h1 {
    font-size: 2rem;
    color: var(--primary);
    margin-bottom: 10px;
}

.auth-header p {
    color: var(--gray);
}

.auth-form {
    display: flex;
    flex-direction: column;
}

.form-group {
    margin-bottom: 25px;
    position: relative;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    color: var(--text);
    font-weight: 500;
}

.form-group input {
    width: 100%;
    padding: 12px 0;
    border: none;
    border-bottom: 1px solid var(--border);
    background-color: transparent;
    color: var(--text);
    font-size: 16px;
    outline: none;
}

.form-group .underline {
    position: absolute;
    bottom: 0;
    left: 0;
    width: 0;
    height: 2px;
    background-color: var(--primary);
    transition: width 0.3s ease;
}

.form-group input:focus ~ .underline {
    width: 100%;
}

.auth-btn {
    background-color: var(--primary);
    color: white;
    border: none;
    padding: 12px;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    margin-top: 20px;
    transition: background-color 0.3s, transform 0.2s;
}

.auth-btn:hover {
    background-color: var(--primary-dark);
    transform: translateY(-2px);
}

.auth-footer {
    margin-top: 20px;
    text-align: center;
    color: var(--gray);
}

.auth-footer a {
    color: var(--primary);
    text-decoration: none;
    font-weight: 500;
}

.auth-decoration {
    flex: 1;
    position: relative;
    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
    overflow: hidden;
}

.circle {
    position: absolute;
    border-radius: 50%;
    background-color: rgba(255, 255, 255, 0.1);
}

.circle-1 {
    width: 300px;
    height: 300px;
    top: -100px;
    right: -100px;
    animation: float 8s infinite ease-in-out;
}

.circle-2 {
    width: 200px;
    height: 200px;
    bottom: 50px;
    right: 100px;
    animation: float 6s infinite ease-in-out reverse;
}

.circle-3 {
    width: 150px;
    height: 150px;
    bottom: 200px;
    right: 300px;
    animation: float 5s infinite ease-in-out;
}

.logo {
    position: absolute;
    bottom: 50px;
    left: 50px;
    color: white;
    font-size: 2rem;
    font-weight: 700;
}

@keyframes float {
    0%, 100% {
        transform: translateY(0);
    }
    50% {
        transform: translateY(-20px);
    }
}

/* Animations */
.auth-card {
    animation: slideIn 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) both;
}

@keyframes slideIn {
    from {
        transform: translateX(-50px);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

/* Responsive */
@media (max-width: 768px) {
    .auth-container {
        flex-direction: column;
    }
    
    .auth-card {
        width: 100%;
        height: auto;
        padding: 30px 20px;
    }
    
    .auth-decoration {
        display: none;
    }
}""")

        if not os.path.exists('static/css/dashboard.css'):
            with open('static/css/dashboard.css', 'w') as f:
                f.write("""/* Dashboard Styles */
.navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 15px 30px;
    background-color: var(--primary);
    color: white;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.navbar-brand {
    font-size: 1.5rem;
    font-weight: 700;
}

.navbar-actions {
    display: flex;
    align-items: center;
    gap: 15px;
}

#username-display {
    font-weight: 500;
}

#logout-btn, #theme-toggle {
    background-color: rgba(255, 255, 255, 0.1);
    color: white;
    border: none;
    padding: 8px 15px;
    border-radius: 4px;
    cursor: pointer;
    transition: background-color 0.3s;
}

#logout-btn:hover, #theme-toggle:hover {
    background-color: rgba(255, 255, 255, 0.2);
}

.container {
    padding: 30px;
    max-width: 1200px;
    margin: 0 auto;
}

/* Rest of the dashboard styles from previous version */
/* ... (include all the previous dashboard CSS here) ... */""")

        # Create JS files
        if not os.path.exists('static/js/auth.js'):
            with open('static/js/auth.js', 'w') as f:
                f.write("""// Auth Page JavaScript
document.addEventListener('DOMContentLoaded', () => {
    // Form animations
    const formGroups = document.querySelectorAll('.form-group');
    formGroups.forEach((group, index) => {
        group.style.animationDelay = `${index * 0.1}s`;
        group.classList.add('animate__animated', 'animate__fadeInUp');
    });
    
    // Theme detection
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (prefersDark) {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', async (e) => {
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> ' + originalText;
            
            // Simulate loading
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        });
    });
    
    // Floating animation for circles
    const circles = document.querySelectorAll('.circle');
    circles.forEach((circle, index) => {
        circle.style.animationDelay = `${index * 0.5}s`;
    });
});""")

        if not os.path.exists('static/js/dashboard.js'):
            with open('static/js/dashboard.js', 'w') as f:
                f.write("""// Dashboard JavaScript
// (Include all the previous dashboard JavaScript here)
// ...""")

if __name__ == '__main__':
    try:
        monitor = UptimeMonitor()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(monitor.start())
        loop.run_forever()
    except KeyboardInterrupt:
        print("Server stopped")
