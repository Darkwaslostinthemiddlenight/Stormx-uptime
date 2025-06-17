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

# --- CONFIGURATION ---
COOKIE_SECRET = secrets.token_bytes(32)  # In production use a fixed secret.
DB_FILE = "users.db"

# --- DATA MODELS ---
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

# --- UPTIME MONITOR CLASS ---
class UptimeMonitor:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.load_users()
        middlewares = [session_middleware(EncryptedCookieStorage(COOKIE_SECRET))]
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
            # You can add more routes (e.g., check_now, pause_site) as needed.
        ])

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
                    'monitors': [vars(m) for m in user.monitors],
                    'status_data': user.status_data
                }
                for username, user in self.users.items()
            }
            with open(DB_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")

    def hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()

    async def get_current_user(self, request) -> Optional[User]:
        session = await get_session(request)
        username = session.get('username')
        return self.users.get(username) if username else None

    async def monitor_sites(self):
        # In a real app you'd check each site's interval and update accordingly.
        while True:
            tasks = []
            for user in self.users.values():
                for site in user.monitors:
                    if not site.paused:
                        tasks.append(self.check_site(user, site))
            if tasks:
                await asyncio.gather(*tasks)
            await asyncio.sleep(10)

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
        successes = [r['response_time'] for r in record['history'] if r['status'] == 'up']
        record['avg_response_time'] = round(sum(successes) / len(successes), 2) if successes else 0
        self.save_users()

    # --- HANDLER METHODS ---

    async def handle_index(self, request):
        """Dashboard: if logged in, show monitored sites and a form to add new sites."""
        user = await self.get_current_user(request)
        if not user:
            raise web.HTTPFound('/login')
        # Build an HTML dashboard with a table of monitors and an add-site form.
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Storm X Uptime Monitor</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #eee; }}
        form {{ margin-top: 20px; }}
    </style>
</head>
<body>
    <h1>Welcome, {user.username}!</h1>
    <p><a href="/logout">Logout</a></p>
    <h2>Your Monitored Sites</h2>
    <table>
      <tr>
        <th>Name</th>
        <th>URL</th>
        <th>Status</th>
        <th>Uptime (%)</th>
        <th>Last Checked</th>
      </tr>"""
        # List monitors if any.
        for site in user.monitors:
            status_info = user.status_data.get(site.url, {})
            status = status_info.get("last_status", "unknown")
            uptime = status_info.get("uptime_percent", 0)
            last = status_info.get("last_checked", "Never")
            html += f"""
      <tr>
        <td>{site.name}</td>
        <td>{site.url}</td>
        <td>{status}</td>
        <td>{uptime}%</td>
        <td>{last}</td>
      </tr>"""
        html += """
    </table>

    <h2>Add New Site</h2>
    <form method="post" action="/add_site">
        <p>Name: <input type="text" name="name" required></p>
        <p>URL: <input type="url" name="url" required></p>
        <p>Interval (sec): <input type="number" name="interval" value="60" required></p>
        <p><button type="submit">Add Site</button></p>
    </form>
</body>
</html>"""
        return web.Response(text=html, content_type="text/html")

    async def handle_login_page(self, request):
        html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Login - Storm X Uptime Monitor</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    form { max-width: 300px; margin: auto; }
    input { display: block; width: 100%; margin-bottom: 10px; padding: 8px; }
  </style>
</head>
<body>
  <h1>Login</h1>
  <form method="post" action="/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
  <p>Don't have an account? <a href="/signup">Sign up</a></p>
</body>
</html>"""
        return web.Response(text=html, content_type="text/html")

    async def handle_signup_page(self, request):
        html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sign Up - Storm X Uptime Monitor</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    form { max-width: 300px; margin: auto; }
    input { display: block; width: 100%; margin-bottom: 10px; padding: 8px; }
  </style>
</head>
<body>
  <h1>Sign Up</h1>
  <form method="post" action="/signup">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="password" name="confirm_password" placeholder="Confirm Password" required>
    <button type="submit">Sign Up</button>
  </form>
  <p>Already have an account? <a href="/login">Login</a></p>
</body>
</html>"""
        return web.Response(text=html, content_type="text/html")

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
        self.users[username] = User(username=username, password_hash=password_hash, salt=salt, monitors=[], status_data={})
        self.save_users()
        session = await get_session(request)
        session['username'] = username
        raise web.HTTPFound('/')

    async def handle_logout(self, request):
        session = await get_session(request)
        session.pop('username', None)
        raise web.HTTPFound('/login')

    async def handle_add_site(self, request):
        # This handler supports both POSTed form data and JSON.
        user = await self.get_current_user(request)
        if not user:
            return web.Response(text="Not authenticated", status=401)
        if request.content_type == 'application/json':
            data = await request.json()
        else:
            data = await request.post()
        if any(site.url == data['url'] for site in user.monitors):
            return web.Response(text="Site already exists", status=400)
        new_site = MonitoredSite(name=data['name'], url=data['url'], interval=int(data['interval']))
        user.monitors.append(new_site)
        self.save_users()
        # Perform initial check asynchronously
        status = await self.check_site(user, new_site)
        # After adding, redirect back to dashboard.
        raise web.HTTPFound('/')

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 5000)
        self.monitor_task = asyncio.create_task(self.monitor_sites())
        await site.start()
        print("Server started at http://0.0.0.0:5000")

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    monitor = UptimeMonitor()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor.start())
        loop.run_forever()
    except KeyboardInterrupt:
        print("Server stopped")
