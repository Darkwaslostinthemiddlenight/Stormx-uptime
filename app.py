# ✅ Full fixed code with working 'handle_add_site' method and unified UptimeMonitor class

# Imports
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
COOKIE_SECRET = secrets.token_bytes(32)
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
            # Add other handlers if needed
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
        while True:
            tasks = []
            for user in self.users.values():
                for site in user.monitors:
                    if not site.paused:
                        tasks.append(self.check_site(user, site))
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
        successful = [r['response_time'] for r in record['history'] if r['status'] == 'up']
        record['avg_response_time'] = round(sum(successful) / len(successful), 2) if successful else 0
        self.save_users()

    async def handle_index(self, request):
        return web.Response(text="Storm X Uptime Monitor Running!", content_type="text/plain")

    async def handle_login_page(self, request):
        return web.Response(text="Login Page Placeholder", content_type="text/plain")

    async def handle_signup_page(self, request):
        return web.Response(text="Signup Page Placeholder", content_type="text/plain")

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
        user = await self.get_current_user(request)
        if not user:
            return web.json_response({'success': False, 'error': 'Not authenticated'}, status=401)
        data = await request.json()
        if any(site.url == data['url'] for site in user.monitors):
            return web.json_response({'success': False, 'error': 'Site already exists'})
        user.monitors.append(MonitoredSite(name=data['name'], url=data['url'], interval=int(data['interval'])))
        self.save_users()
        status = await self.check_site(user, user.monitors[-1])
        return web.json_response({'success': True, 'status': status})

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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(monitor.start())
        loop.run_forever()
    except KeyboardInterrupt:
        print("Server stopped")
