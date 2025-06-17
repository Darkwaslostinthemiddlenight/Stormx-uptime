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
    monitors: List['MonitoredSite']
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

    def setup_routes(self):
        self.app.add_routes([
            web.get('/', self.handle_index),
            web.get('/login', self.handle_login_page),
            web.post('/login', self.handle_login),
            web.get('/signup', self.handle_signup_page),
            web.post('/signup', self.handle_signup),
            web.get('/logout', self.handle_logout),
            web.post('/add_site', self.handle_add_site),  # Make sure this matches the method name
            web.get('/status', self.handle_status),
            web.get('/status_updates', self.handle_status_updates),
            web.get('/site_details/{url}', self.handle_site_details),
            web.post('/pause_site', self.handle_pause_site),
            web.post('/delete_site', self.handle_delete_site),
            web.post('/check_now', self.handle_check_now),
            web.static('/static', 'static')
    ])

class UptimeMonitor:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.load_users()  # This will now work if you add the method below
        # ... rest of your __init__ code

    def load_users(self):
        try:
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
        except Exception as e:
            print(f"Error loading users: {e}")
            self.users = {}

    def save_users(self):
        try:
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
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")

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
        
        self.save_users()

    async def handle_index(self, request):
        user = await self.get_current_user(request)
        if not user:
            raise web.HTTPFound('/login')
        
        html = """
        <!DOCTYPE html>
        <html lang="en" data-theme="light">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Storm X Up</title>
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
                }
                
                .navbar {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 15px 30px;
                    background: linear-gradient(135deg, var(--primary), var(--secondary));
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
                
                .navbar-btn {
                    background-color: rgba(255, 255, 255, 0.1);
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }
                
                .navbar-btn:hover {
                    background-color: rgba(255, 255, 255, 0.2);
                }
                
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                
                .menu-bar {
                    display: flex;
                    justify-content: center;
                    gap: 20px;
                    margin: 20px 0;
                    flex-wrap: wrap;
                }
                
                .menu-btn {
                    padding: 10px 20px;
                    border-radius: 50px;
                    background-color: var(--primary);
                    color: white;
                    border: none;
                    cursor: pointer;
                    font-weight: 500;
                    transition: transform 0.2s, box-shadow 0.2s;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                }
                
                .menu-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
                }
                
                .menu-btn.active {
                    background-color: var(--secondary);
                }
                
                .add-btn {
                    width: 50px;
                    height: 50px;
                    border-radius: 50%;
                    background-color: var(--primary);
                    color: white;
                    border: none;
                    font-size: 1.5rem;
                    cursor: pointer;
                    position: fixed;
                    bottom: 30px;
                    right: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
                    transition: transform 0.3s, background-color 0.3s;
                    z-index: 90;
                }
                
                .add-btn:hover {
                    transform: scale(1.1) rotate(90deg);
                    background-color: var(--secondary);
                }
                
                .modal {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 1000;
                    opacity: 0;
                    pointer-events: none;
                    transition: opacity 0.3s;
                }
                
                .modal.active {
                    opacity: 1;
                    pointer-events: all;
                }
                
                .modal-content {
                    background-color: var(--card-bg);
                    padding: 30px;
                    border-radius: 10px;
                    width: 90%;
                    max-width: 500px;
                    transform: translateY(-50px);
                    transition: transform 0.3s;
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
                }
                
                .modal.active .modal-content {
                    transform: translateY(0);
                }
                
                .form-group {
                    margin-bottom: 20px;
                }
                
                label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 500;
                    color: var(--text);
                }
                
                input, select {
                    width: 100%;
                    padding: 12px 15px;
                    border: 1px solid var(--border);
                    border-radius: 6px;
                    font-size: 16px;
                    background-color: var(--card-bg);
                    color: var(--text);
                }
                
                .form-actions {
                    display: flex;
                    justify-content: flex-end;
                    gap: 10px;
                    margin-top: 20px;
                }
                
                .btn {
                    padding: 10px 20px;
                    border-radius: 6px;
                    border: none;
                    cursor: pointer;
                    font-weight: 500;
                    transition: background-color 0.3s;
                }
                
                .btn-primary {
                    background-color: var(--primary);
                    color: white;
                }
                
                .btn-secondary {
                    background-color: var(--gray);
                    color: white;
                }
                
                .btn-danger {
                    background-color: var(--danger);
                    color: white;
                }
                
                .btn-warning {
                    background-color: var(--warning);
                    color: white;
                }
                
                .status-container {
                    margin-top: 30px;
                }
                
                .status-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 20px;
                }
                
                .status-card {
                    background-color: var(--card-bg);
                    border-radius: 10px;
                    padding: 20px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
                    transition: transform 0.3s, box-shadow 0.3s;
                    border-left: 4px solid var(--primary);
                    cursor: pointer;
                }
                
                .status-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
                }
                
                .status-card.up {
                    border-left-color: var(--success);
                }
                
                .status-card.down {
                    border-left-color: var(--danger);
                }
                
                .status-card.warning {
                    border-left-color: var(--warning);
                }
                
                .status-card.paused {
                    border-left-color: var(--gray);
                    opacity: 0.7;
                }
                
                .card-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }
                
                .site-name {
                    font-weight: 600;
                    font-size: 18px;
                    color: var(--text);
                }
                
                .status-badge {
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-size: 14px;
                    font-weight: 500;
                }
                
                .status-badge.up {
                    background-color: rgba(76, 201, 240, 0.1);
                    color: var(--success);
                }
                
                .status-badge.down {
                    background-color: rgba(247, 37, 133, 0.1);
                    color: var(--danger);
                }
                
                .status-badge.warning {
                    background-color: rgba(248, 150, 30, 0.1);
                    color: var(--warning);
                }
                
                .status-badge.paused {
                    background-color: rgba(108, 117, 125, 0.1);
                    color: var(--gray);
                }
                
                .card-stats {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 15px;
                    margin-top: 15px;
                }
                
                .stat-item {
                    display: flex;
                    flex-direction: column;
                }
                
                .stat-label {
                    font-size: 12px;
                    color: var(--gray);
                    margin-bottom: 5px;
                }
                
                .stat-value {
                    font-weight: 600;
                    font-size: 16px;
                    color: var(--text);
                }
                
                .card-actions {
                    display: flex;
                    gap: 10px;
                    margin-top: 15px;
                }
                
                .action-btn {
                    padding: 6px 12px;
                    border-radius: 4px;
                    border: none;
                    cursor: pointer;
                    font-size: 12px;
                    font-weight: 500;
                    transition: opacity 0.3s;
                }
                
                .action-btn:hover {
                    opacity: 0.8;
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
                
                .details-modal {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 1000;
                    opacity: 0;
                    pointer-events: none;
                    transition: opacity 0.3s;
                }
                
                .details-modal.active {
                    opacity: 1;
                    pointer-events: all;
                }
                
                .details-content {
                    background-color: var(--card-bg);
                    padding: 30px;
                    border-radius: 10px;
                    width: 90%;
                    max-width: 800px;
                    max-height: 80vh;
                    overflow-y: auto;
                    transform: translateY(-50px);
                    transition: transform 0.3s;
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
                }
                
                .details-modal.active .details-content {
                    transform: translateY(0);
                }
                
                .details-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                }
                
                .close-btn {
                    background: none;
                    border: none;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--gray);
                }
                
                .chart-container {
                    height: 200px;
                    margin: 20px 0;
                    position: relative;
                }
                
                .history-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }
                
                .history-table th, .history-table td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid var(--border);
                }
                
                .history-table th {
                    font-weight: 500;
                    color: var(--gray);
                }
                
                .status-cell {
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    text-align: center;
                }
                
                .status-cell.up {
                    background-color: rgba(76, 201, 240, 0.1);
                    color: var(--success);
                }
                
                .status-cell.down {
                    background-color: rgba(247, 37, 133, 0.1);
                    color: var(--danger);
                }
                
                .status-cell.paused {
                    background-color: rgba(108, 117, 125, 0.1);
                    color: var(--gray);
                }
                
                @media (max-width: 768px) {
                    .status-grid {
                        grid-template-columns: 1fr;
                    }
                    
                    .card-stats {
                        grid-template-columns: 1fr;
                    }
                    
                    h1 {
                        font-size: 2rem;
                    }
                }
                
                /* Animations */
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                
                .fade-in {
                    animation: fadeIn 0.5s ease-out forwards;
                }
                
                .delay-1 { animation-delay: 0.1s; }
                .delay-2 { animation-delay: 0.2s; }
                .delay-3 { animation-delay: 0.3s; }
                
                .spinner {
                    border: 3px solid rgba(0, 0, 0, 0.1);
                    border-radius: 50%;
                    border-top: 3px solid var(--primary);
                    width: 20px;
                    height: 20px;
                    animation: spin 1s linear infinite;
                    display: inline-block;
                    vertical-align: middle;
                    margin-right: 8px;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .loading-text {
                    display: inline-flex;
                    align-items: center;
                }
                
                /* Login/Signup Page Styles */
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
                
                .auth-form-group {
                    margin-bottom: 25px;
                    position: relative;
                }
                
                .auth-form-group label {
                    display: block;
                    margin-bottom: 8px;
                    color: var(--text);
                    font-weight: 500;
                }
                
                .auth-form-group input {
                    width: 100%;
                    padding: 12px 0;
                    border: none;
                    border-bottom: 1px solid var(--border);
                    background-color: transparent;
                    color: var(--text);
                    font-size: 16px;
                    outline: none;
                }
                
                .auth-form-group .underline {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    width: 0;
                    height: 2px;
                    background-color: var(--primary);
                    transition: width 0.3s ease;
                }
                
                .auth-form-group input:focus ~ .underline {
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
                    background-color: var(--secondary);
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
                    background: linear-gradient(135deg, var(--primary), var(--secondary));
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
                
                .auth-logo {
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
                
                /* Auth Animations */
                .auth-form-group {
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
                }
            </style>
        </head>
        <body>
            <div class="navbar">
                <div class="navbar-brand">Storm X Up</div>
                <div class="navbar-actions">
                    <span id="username-display"></span>
                    <button class="navbar-btn" id="logout-btn">Logout</button>
                    <button class="navbar-btn" id="theme-toggle">🌓</button>
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
            
            <script>
                // Current user
                let currentUser = null;
                
                // DOM Elements
                const statusView = document.getElementById('statusView');
                const addView = document.getElementById('addView');
                const statusGrid = document.getElementById('statusGrid');
                const addModal = document.getElementById('addModal');
                const floatingAddBtn = document.getElementById('floatingAddBtn');
                const themeToggle = document.getElementById('themeToggle');
                const detailsModal = document.getElementById('detailsModal');
                const menuBtns = document.querySelectorAll('.menu-btn');
                const addMonitorForm = document.getElementById('addMonitorForm');
                const modalAddForm = document.getElementById('modalAddForm');
                const logoutBtn = document.getElementById('logout-btn');
                const usernameDisplay = document.getElementById('username-display');
                
                // Set username if available
                async function checkAuth() {
                    try {
                        const response = await fetch('/status');
                        if (response.ok) {
                            const data = await response.json();
                            if (data.username) {
                                currentUser = data.username;
                                usernameDisplay.textContent = currentUser;
                            } else {
                                window.location.href = '/login';
                            }
                        } else {
                            window.location.href = '/login';
                        }
                    } catch (error) {
                        console.error('Auth check failed:', error);
                        window.location.href = '/login';
                    }
                }
                
                // Theme management
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
                
                // Menu navigation
                menuBtns.forEach(btn => {
                    btn.addEventListener('click', () => {
                        const view = btn.dataset.view;
                        menuBtns.forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        
                        if (view === 'status') {
                            statusView.style.display = 'block';
                            addView.style.display = 'none';
                        } else if (view === 'add') {
                            statusView.style.display = 'none';
                            addView.style.display = 'block';
                        }
                    });
                });
                
                // Floating add button
                floatingAddBtn.addEventListener('click', () => {
                    addModal.classList.add('active');
                });
                
                // Modal handling
                document.getElementById('modalCancel').addEventListener('click', () => {
                    addModal.classList.remove('active');
                });
                
                document.getElementById('cancelAdd').addEventListener('click', () => {
                    document.querySelector('.menu-btn[data-view="status"]').click();
                });
                
                // Logout
                logoutBtn.addEventListener('click', async () => {
                    try {
                        await fetch('/logout', { method: 'GET' });
                        window.location.href = '/login';
                    } catch (error) {
                        console.error('Logout failed:', error);
                    }
                });
                
                // Add monitor form (modal)
                modalAddForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const name = document.getElementById('modalMonitorName').value;
                    const url = document.getElementById('modalMonitorUrl').value;
                    const interval = document.getElementById('modalMonitorInterval').value;
                    
                    const submitBtn = document.getElementById('modalSubmit');
                    const originalText = submitBtn.textContent;
                    submitBtn.innerHTML = '<span class="spinner"></span> Adding...';
                    submitBtn.disabled = true;
                    
                    try {
                        // First add the site
                        const addResponse = await fetch('/add_site', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                name: name,
                                url: url,
                                interval: interval
                            }),
                        });
                        
                        if (addResponse.ok) {
                            // Immediately check the site
                            const checkResponse = await fetch('/check_now', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({ url: url }),
                            });
                            
                            if (checkResponse.ok) {
                                addModal.classList.remove('active');
                                modalAddForm.reset();
                                fetchStatus();
                            } else {
                                alert('Monitor added but initial check failed');
                            }
                        } else {
                            alert('Error adding monitor');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        alert('Error adding monitor');
                    } finally {
                        submitBtn.textContent = originalText;
                        submitBtn.disabled = false;
                    }
                });
                
                // Add monitor form (page)
                addMonitorForm.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const name = document.getElementById('monitorName').value;
                    const url = document.getElementById('monitorUrl').value;
                    const interval = document.getElementById('monitorInterval').value;
                    
                    const submitBtn = document.getElementById('submitAdd');
                    const originalText = submitBtn.textContent;
                    submitBtn.innerHTML = '<span class="spinner"></span> Adding...';
                    submitBtn.disabled = true;
                    
                    try {
                        // First add the site
                        const addResponse = await fetch('/add_site', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                name: name,
                                url: url,
                                interval: interval
                            }),
                        });
                        
                        if (addResponse.ok) {
                            // Immediately check the site
                            const checkResponse = await fetch('/check_now', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({ url: url }),
                            });
                            
                            if (checkResponse.ok) {
                                addMonitorForm.reset();
                                document.querySelector('.menu-btn[data-view="status"]').click();
                                fetchStatus();
                            } else {
                                alert('Monitor added but initial check failed');
                            }
                        } else {
                            alert('Error adding monitor');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        alert('Error adding monitor');
                    } finally {
                        submitBtn.textContent = originalText;
                        submitBtn.disabled = false;
                    }
                });
                
                // Close details modal
                document.getElementById('closeDetails').addEventListener('click', () => {
                    detailsModal.classList.remove('active');
                });
                
                // Pause/resume site
                async function togglePauseSite(url) {
                    try {
                        const response = await fetch('/pause_site', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ url: url }),
                        });
                        
                        if (response.ok) {
                            fetchStatus();
                        } else {
                            alert('Error toggling pause status');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        alert('Error toggling pause status');
                    }
                }
                
                // Delete site
                async function deleteSite(url) {
                    if (!confirm('Are you sure you want to delete this monitor?')) return;
                    
                    try {
                        const response = await fetch('/delete_site', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ url: url }),
                        });
                        
                        if (response.ok) {
                            fetchStatus();
                        } else {
                            alert('Error deleting monitor');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        alert('Error deleting monitor');
                    }
                }
                
                // Check site now
                async function checkSiteNow(url) {
                    try {
                        const response = await fetch('/check_now', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ url: url }),
                        });
                        
                        if (response.ok) {
                            fetchStatus();
                        } else {
                            alert('Error checking site');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        alert('Error checking site');
                    }
                }
                
                // Fetch and display status
                async function fetchStatus() {
                    try {
                        const response = await fetch('/status');
                        const data = await response.json();
                        updateStatusGrid(data);
                    } catch (error) {
                        console.error('Error fetching status:', error);
                    }
                }
                
                // Update status grid
                function updateStatusGrid(data) {
                    if (!data.sites || data.sites.length === 0) {
                        statusGrid.innerHTML = '<p class="no-monitors">No monitors added yet. Click the + button to add one.</p>';
                        return;
                    }
                    
                    let html = '';
                    let delay = 0;
                    
                    for (const site of data.sites) {
                        const statusInfo = data.status_data[site.url] || {
                            uptime_percent: 0,
                            last_checked: 'Never',
                            response_time: 0,
                            last_status: 'unknown',
                            avg_response_time: 0,
                            total_checks: 0,
                            up_count: 0,
                            down_count: 0,
                            paused: site.paused
                        };
                        
                        // Determine status class
                        let statusClass = statusInfo.last_status;
                        if (statusInfo.paused) {
                            statusClass = 'paused';
                        } else if (statusInfo.last_status === 'up' && statusInfo.avg_response_time > 1000) {
                            statusClass = 'warning';
                        }
                        
                        html += `
                            <div class="status-card ${statusClass} fade-in delay-${delay % 3}" data-url="${site.url}">
                                <div class="card-header">
                                    <div class="site-name">${site.name}</div>
                                    <div class="status-badge ${statusClass}">
                                        ${statusInfo.paused ? 'PAUSED' : statusClass.toUpperCase()}
                                    </div>
                                </div>
                                <div class="card-details">${site.url}</div>
                                
                                <div class="card-stats">
                                    <div class="stat-item">
                                        <span class="stat-label">Uptime</span>
                                        <span class="stat-value">${statusInfo.uptime_percent}%</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-label">Avg Response</span>
                                        <span class="stat-value">${statusInfo.avg_response_time} ms</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-label">Last Response</span>
                                        <span class="stat-value">${statusInfo.response_time} ms</span>
                                    </div>
                                    <div class="stat-item">
                                        <span class="stat-label">Last Checked</span>
                                        <span class="stat-value">${statusInfo.last_checked || 'Never'}</span>
                                    </div>
                                </div>
                                
                                <div class="card-actions">
                                    <button class="action-btn btn-primary" onclick="checkSiteNow('${site.url}')">Check Now</button>
                                    <button class="action-btn ${statusInfo.paused ? 'btn-success' : 'btn-warning'}" 
                                            onclick="togglePauseSite('${site.url}')">
                                        ${statusInfo.paused ? 'Resume' : 'Pause'}
                                    </button>
                                    <button class="action-btn btn-danger" onclick="deleteSite('${site.url}')">Delete</button>
                                </div>
                            </div>
                        `;
                        delay++;
                    }
                    
                    statusGrid.innerHTML = html;
                    
                    // Add click event to status cards
                    document.querySelectorAll('.status-card').forEach(card => {
                        card.addEventListener('click', (e) => {
                            // Don't open details if clicking on a button
                            if (e.target.tagName === 'BUTTON') return;
                            
                            const url = card.dataset.url;
                            showSiteDetails(url);
                        });
                    });
                }
                
                // Show site details
                async function showSiteDetails(url) {
                    try {
                        const response = await fetch(`/site_details/${encodeURIComponent(url)}`);
                        const data = await response.json();
                        
                        const detailsTitle = document.getElementById('detailsTitle');
                        const detailsContent = document.getElementById('detailsContent');
                        
                        detailsTitle.textContent = data.name;
                        
                        let html = `
                            <div class="card-stats">
                                <div class="stat-item">
                                    <span class="stat-label">Current Status</span>
                                    <span class="stat-value">
                                        <span class="status-badge ${data.paused ? 'paused' : data.last_status}">
                                            ${data.paused ? 'PAUSED' : data.last_status.toUpperCase()}
                                        </span>
                                    </span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Uptime Percentage</span>
                                    <span class="stat-value">${data.uptime_percent}%</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Average Response Time</span>
                                    <span class="stat-value">${data.avg_response_time} ms</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Total Checks</span>
                                    <span class="stat-value">${data.total_checks}</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Successful Checks</span>
                                    <span class="stat-value">${data.up_count}</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Failed Checks</span>
                                    <span class="stat-value">${data.down_count}</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Last Checked</span>
                                    <span class="stat-value">${data.last_checked}</span>
                                </div>
                                <div class="stat-item">
                                    <span class="stat-label">Check URL</span>
                                    <span class="stat-value">${url}</span>
                                </div>
                            </div>
                            
                            <div class="card-actions" style="margin: 20px 0;">
                                <button class="btn btn-primary" onclick="checkSiteNow('${url}')">Check Now</button>
                                <button class="btn ${data.paused ? 'btn-success' : 'btn-warning'}" 
                                        onclick="togglePauseSite('${url}'); setTimeout(() => location.reload(), 500);">
                                    ${data.paused ? 'Resume Monitoring' : 'Pause Monitoring'}
                                </button>
                                <button class="btn btn-danger" onclick="deleteSite('${url}'); setTimeout(() => location.reload(), 500);">Delete Monitor</button>
                            </div>
                            
                            <h3>Response Time History</h3>
                            <div class="chart-container">
                                <canvas id="responseChart"></canvas>
                            </div>
                            
                            <h3>Recent Checks</h3>
                            <table class="history-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Status</th>
                                        <th>Response Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.history.map(item => `
                                        <tr>
                                            <td>${item.time}</td>
                                            <td class="status-cell ${item.status}">${item.status.toUpperCase()}</td>
                                            <td>${item.response_time} ms</td>
                                        </tr>
                                    `).reverse().join('')}
                                </tbody>
                            </table>
                        `;
                        
                        detailsContent.innerHTML = html;
                        
                        // Initialize chart
                        initializeChart(data.history);
                        
                        detailsModal.classList.add('active');
                    } catch (error) {
                        console.error('Error fetching details:', error);
                    }
                }
                
                // Initialize response time chart
                function initializeChart(history) {
                    const ctx = document.getElementById('responseChart')?.getContext('2d');
                    if (!ctx) return;
                    
                    const labels = history.map(item => item.time).reverse();
                    const data = history.map(item => item.response_time).reverse();
                    const statuses = history.map(item => item.status).reverse();
                    
                    const backgroundColors = statuses.map(status => 
                        status === 'up' ? 'rgba(76, 201, 240, 0.5)' : 'rgba(247, 37, 133, 0.5)'
                    );
                    
                    const borderColors = statuses.map(status => 
                        status === 'up' ? 'rgba(76, 201, 240, 1)' : 'rgba(247, 37, 133, 1)'
                    );
                    
                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Response Time (ms)',
                                data: data,
                                backgroundColor: backgroundColors,
                                borderColor: borderColors,
                                borderWidth: 1,
                                pointRadius: 3,
                                pointHoverRadius: 5,
                                tension: 0.1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                }
                
                // Set up EventSource for real-time updates
                function setupEventSource() {
                    const eventSource = new EventSource('/status_updates');
                    
                    eventSource.onmessage = (event) => {
                        const data = JSON.parse(event.data);
                        updateStatusGrid(data);
                    };
                    
                    eventSource.onerror = () => {
                        console.log('EventSource error. Reconnecting...');
                        setTimeout(setupEventSource, 5000);
                    };
                }
                
                // Initialize
                checkAuth().then(() => {
                    fetchStatus();
                    setupEventSource();
                });
                
                // Make functions available globally
                window.togglePauseSite = togglePauseSite;
                window.deleteSite = deleteSite;
                window.checkSiteNow = checkSiteNow;
                window.showSiteDetails = showSiteDetails;
                
                // Load Chart.js
                const script = document.createElement('script');
                script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
                script.onload = () => console.log('Chart.js loaded');
                document.head.appendChild(script);
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')

    async def handle_login_page(self, request):
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login | Storm X Up</title>
            <style>
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
                
                .auth-form-group {
                    margin-bottom: 25px;
                    position: relative;
                }
                
                .auth-form-group label {
                    display: block;
                    margin-bottom: 8px;
                    color: var(--text);
                    font-weight: 500;
                }
                
                .auth-form-group input {
                    width: 100%;
                    padding: 12px 0;
                    border: none;
                    border-bottom: 1px solid var(--border);
                    background-color: transparent;
                    color: var(--text);
                    font-size: 16px;
                    outline: none;
                }
                
                .auth-form-group .underline {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    width: 0;
                    height: 2px;
                    background-color: var(--primary);
                    transition: width 0.3s ease;
                }
                
                .auth-form-group input:focus ~ .underline {
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
                
                .auth-logo {
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
                .auth-form-group {
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
                }
            </style>
        </head>
        <body>
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <h1>Welcome Back</h1>
                        <p>Login to monitor your sites</p>
                    </div>
                    
                    <form class="auth-form" method="POST" action="/login">
                        <div class="auth-form-group" style="animation-delay: 0.1s">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required>
                            <div class="underline"></div>
                        </div>
                        
                        <div class="auth-form-group" style="animation-delay: 0.2s">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                            <div class="underline"></div>
                        </div>
                        
                        <button type="submit" class="auth-btn" style="animation-delay: 0.3s">Login</button>
                    </form>
                    
                    <div class="auth-footer" style="animation-delay: 0.4s">
                        <p>Don't have an account? <a href="/signup">Sign up</a></p>
                    </div>
                </div>
                
                <div class="auth-decoration">
                    <div class="circle circle-1"></div>
                    <div class="circle circle-2"></div>
                    <div class="circle circle-3"></div>
                    <div class="auth-logo">Storm X Up</div>
                </div>
            </div>
            
            <script>
                // Form animations
                document.addEventListener('DOMContentLoaded', () => {
                    // Theme detection
                    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    if (prefersDark) {
                        document.documentElement.setAttribute('data-theme', 'dark');
                    }
                    
                    // Form validation
                    const form = document.querySelector('form');
                    form.addEventListener('submit', async (e) => {
                        const submitBtn = form.querySelector('button[type="submit"]');
                        const originalText = submitBtn.textContent;
                        
                        submitBtn.disabled = true;
                        submitBtn.innerHTML = '<span class="spinner"></span> ' + originalText;
                    });
                });
                
                // Spinner style
                const style = document.createElement('style');
                style.textContent = `
                    .spinner {
                        border: 2px solid rgba(255, 255, 255, 0.3);
                        border-radius: 50%;
                        border-top: 2px solid white;
                        width: 15px;
                        height: 15px;
                        display: inline-block;
                        animation: spin 1s linear infinite;
                        vertical-align: middle;
                        margin-right: 8px;
                    }
                    
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                `;
                document.head.appendChild(style);
            </script>
        </body>
        </html>
        """
        return web.Response(text=html, content_type='text/html')

    async def handle_signup_page(self, request):
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sign Up | Storm X Up</title>
            <style>
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
                
                .auth-form-group {
                    margin-bottom: 25px;
                    position: relative;
                }
                
                .auth-form-group label {
                    display: block;
                    margin-bottom: 8px;
                    color: var(--text);
                    font-weight: 500;
                }
                
                .auth-form-group input {
                    width: 100%;
                    padding: 12px 0;
                    border: none;
                    border-bottom: 1px solid var(--border);
                    background-color: transparent;
                    color: var(--text);
                    font-size: 16px;
                    outline: none;
                }
                
                .auth-form-group .underline {
                    position: absolute;
                    bottom: 0;
                    left: 0;
                    width: 0;
                    height: 2px;
                    background-color: var(--primary);
                    transition: width 0.3s ease;
                }
                
                .auth-form-group input:focus ~ .underline {
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
                
                .auth-logo {
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
                .auth-form-group {
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
                }
            </style>
        </head>
        <body>
            <div class="auth-container">
                <div class="auth-card">
                    <div class="auth-header">
                        <h1>Create Account</h1>
                        <p>Start monitoring your sites</p>
                    </div>
                    
                    <form class="auth-form" method="POST" action="/signup">
                        <div class="auth-form-group" style="animation-delay: 0.1s">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" required>
                            <div class="underline"></div>
                        </div>
                        
                        <div class="auth-form-group" style="animation-delay: 0.2s">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" required>
                            <div class="underline"></div>
                        </div>
                        
                        <div class="auth-form-group" style="animation-delay: 0.3s">
                            <label for="confirm_password">Confirm Password</label>
                            <input type="password" id="confirm_password" name="confirm_password" required>
                            <div class="underline"></div>
                        </div>
                        
                        <button type="submit" class="auth-btn" style="animation-delay: 0.4s">Sign Up</button>
                    </form>
                    
                    <div class="auth-footer" style="animation-delay: 0.5s">
                        <p>Already have an account? <a href="/login">Login</a></p>
                    </div>
                </div>
                
                <div class="auth-decoration">
                    <div class="circle circle-1"></div>
                    <div class="circle circle-2"></div>
                    <div class="circle circle-3"></div>
                    <div class="auth-logo">Storm X Up</div>
                </div>
            </div>
            
            <script>
                // Form animations
                document.addEventListener('DOMContentLoaded', () => {
                    // Theme detection
                    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    if (prefersDark) {
                        document.documentElement.setAttribute('data-theme', 'dark');
                    }
                    
                    // Form validation
                    const form = document.querySelector('form');
                    form.addEventListener('submit', async (e) => {
                        const password = document.getElementById('password').value;
                        const confirmPassword = document.getElementById('confirm_password').value;
                        
                        if (password !== confirmPassword) {
                            e.preventDefault();
                            alert('Passwords do not match');
                            return;
                        }
                        
                        const submitBtn = form.querySelector('button[type="submit"]');
                        const originalText = submitBtn.textContent;
                        
                        submitBtn.disabled = true;
                        submitBtn.innerHTML = '<span class="spinner"></span> ' + originalText;
                    });
                });
                
                // Spinner style
                const style = document.createElement('style');
                style.textContent = `
                    .spinner {
                        border: 2px solid rgba(255, 255, 255, 0.3);
                        border-radius: 50%;
                        border-top: 2px solid white;
                        width: 15px;
                        height: 15px;
                        display: inline-block;
                        animation: spin 1s linear infinite;
                        vertical-align: middle;
                        margin-right: 8px;
                    }
                    
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                `;
                document.head.appendChild(style);
            </script>
        </body>
        </html>
        """
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
