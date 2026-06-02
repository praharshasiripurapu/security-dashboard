"""
sim.py — Traffic Simulator for SecurityDash
Usage:
    python sim.py                   # default: http://localhost:8000
    python sim.py --rate 2          # requests per second
    python sim.py --duration 60     # run for 60 seconds then stop
"""

import httpx
import random
import time
import argparse
import signal
import sys
from typing import Optional
from datetime import datetime

USERNAMES = ["alice", "bob", "charlie", "admin", "root", "user123", "test", "devops"]
PASSWORDS = ["correct_password", "wrong1", "wrong2", "123456", "password", "letmein"]
CORRECT_PASSWORD = "correct_password"

FAKE_IPS = [
    "192.168.1.10", "192.168.1.11", "10.0.0.5",
    "10.0.0.6",    "172.16.0.3",   "172.16.0.4",
    "203.0.113.1", "203.0.113.2",  "198.51.100.1",
    "45.33.32.156", "104.21.14.101", "198.199.68.90"
]
IP_WEIGHTS = [1]*9 + [5, 5, 5]

running = True

def signal_handler(sig, frame):
    global running
    print("\n\n[sim] Stopping gracefully...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

def random_ip():
    return random.choices(FAKE_IPS, weights=IP_WEIGHTS, k=1)[0]

def attempt_login(client, base_url):
    username = random.choice(USERNAMES)
    password = CORRECT_PASSWORD if random.random() < 0.3 else random.choice(PASSWORDS[1:])
    ip = random_ip()
    try:
        resp = client.post(
            f"{base_url}/login",
            json={"username": username, "password": password},
            headers={"X-Forwarded-For": ip},
            timeout=5
        )
        status = "SUCCESS" if resp.status_code == 200 else f"FAIL ({resp.status_code})"
        return f"LOGIN  {status:20s} user={username:10s} ip={ip}"
    except Exception as e:
        return f"LOGIN  ERROR  {e}"

def hit_dashboard(client, base_url):
    try:
        resp = client.get(f"{base_url}/dashboard", timeout=5)
        return f"GET    /dashboard        status={resp.status_code}"
    except Exception as e:
        return f"GET    /dashboard  ERROR {e}"

def hit_api_data(client, base_url):
    try:
        resp = client.get(f"{base_url}/api/data", timeout=5)
        return f"GET    /api/data         status={resp.status_code}"
    except Exception as e:
        return f"GET    /api/data   ERROR {e}"

def hit_health(client, base_url):
    try:
        resp = client.get(f"{base_url}/health", timeout=5)
        return f"GET    /health           status={resp.status_code}"
    except Exception as e:
        return f"GET    /health     ERROR {e}"

ACTIONS = [
    (attempt_login, 0.5),
    (hit_dashboard, 0.2),
    (hit_api_data,  0.2),
    (hit_health,    0.1),
]

def run(base_url: str, rate: float, duration: Optional[float]):
    global running
    print(f"[sim] Starting traffic simulator -> {base_url}")
    print(f"[sim] Rate: {rate} req/s  |  Duration: {'inf' if duration is None else f'{duration}s'}")
    print("[sim] Press Ctrl+C to stop\n")

    interval = 1.0 / rate
    start_time = time.time()
    total = 0

    with httpx.Client() as client:
        while running:
            if duration and (time.time() - start_time) >= duration:
                print(f"\n[sim] Duration {duration}s reached. Stopping.")
                break

            action_fn = random.choices(
                [a[0] for a in ACTIONS],
                weights=[a[1] for a in ACTIONS],
                k=1
            )[0]

            result = action_fn(client, base_url)
            total += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] #{total:05d}  {result}")
            time.sleep(interval)

    elapsed = time.time() - start_time
    print(f"\n[sim] Done. {total} requests in {elapsed:.1f}s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecurityDash traffic simulator")
    parser.add_argument("--url",      default="http://localhost:8000")
    parser.add_argument("--rate",     type=float, default=1.0)
    parser.add_argument("--duration", type=float, default=None)
    args = parser.parse_args()
    run(args.url, args.rate, args.duration)
