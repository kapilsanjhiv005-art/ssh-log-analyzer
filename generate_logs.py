"""
Synthetic SSH Authentication Log Generator
-------------------------------------------
Generates controlled SSH authentication events for testing
our SSH Brute-Force Log Analyzer.

All events are synthetic. No network traffic is generated.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

# Documentation-only IP addresses; these do not identify real attackers.
NORMAL_IP = "192.0.2.10"
BRUTE_FORCE_IP = "198.51.100.20"
SPRAY_IP = "198.51.100.30"
ENUMERATION_IP = "203.0.113.40"
ROOT_IP = "203.0.113.50"
COMPROMISE_TEST_IP = "198.51.100.60"

HOSTNAME = "sentinel-server"

OUTPUT_DIR = Path("sample_logs")
OUTPUT_FILE = OUTPUT_DIR / "auth.log"

USERS = ["analyst", "kapil", "developer", "backup", "admin"]
INVALID_USERS = ["testuser", "guest123", "unknown", "fakeadmin"]


def format_log(timestamp, message, process_id):
    """Format one synthetic SSH authentication log entry."""
    timestamp_text = timestamp.strftime("%b %d %H:%M:%S")

    return f"{timestamp_text} {HOSTNAME} sshd[{process_id}]: {message}"


def generate_logs():
    """Generate normal events and controlled suspicious scenarios."""

    events = []
    start_time = datetime(2026, 10, 19, 9, 0, 0)
    process_id = 1000

    def add_event(timestamp, message):
        nonlocal process_id

        events.append((timestamp, format_log(timestamp, message, process_id)))

        process_id += 1

    # -------------------------------------------------
    # 1. Normal authentication activity
    # -------------------------------------------------
    for i in range(8):
        timestamp = start_time + timedelta(minutes=i * 3)

        username = USERS[i % len(USERS)]
        port = random.randint(40000, 60000)

        add_event(timestamp, f"Accepted password for {username} from {NORMAL_IP} port {port} ssh2")

    # -------------------------------------------------
    # 2. Brute-force simulation
    # Ten failures from one IP within one minute
    # -------------------------------------------------
    brute_start = start_time + timedelta(minutes=30)

    for i in range(10):
        timestamp = brute_start + timedelta(seconds=i * 4)
        port = random.randint(40000, 60000)

        add_event(timestamp, f"Failed password for analyst from {BRUTE_FORCE_IP} port {port} ssh2")

    # -------------------------------------------------
    # 3. Password-spraying simulation
    # One IP attempts several different usernames
    # -------------------------------------------------
    spray_start = start_time + timedelta(minutes=40)

    for i, username in enumerate(USERS):
        timestamp = spray_start + timedelta(seconds=i * 10)
        port = random.randint(40000, 60000)

        add_event(timestamp, f"Failed password for {username} from {SPRAY_IP} port {port} ssh2")

    # -------------------------------------------------
    # 4. Username-enumeration simulation
    # Attempts using invalid usernames
    # -------------------------------------------------
    enumeration_start = start_time + timedelta(minutes=50)

    for i, username in enumerate(INVALID_USERS):
        timestamp = enumeration_start + timedelta(seconds=i * 5)
        port = random.randint(40000, 60000)

        add_event(
            timestamp,
            f"Failed password for invalid user {username} from {ENUMERATION_IP} port {port} ssh2",
        )

    # -------------------------------------------------
    # 5. Root-login attempts
    # -------------------------------------------------
    root_start = start_time + timedelta(minutes=55)

    for i in range(3):
        timestamp = root_start + timedelta(seconds=i * 10)
        port = random.randint(40000, 60000)

        add_event(timestamp, f"Failed password for root from {ROOT_IP} port {port} ssh2")

    # -------------------------------------------------
    # 6. Failed logins followed by a successful login
    # This is a high-priority investigation scenario.
    # -------------------------------------------------
    compromise_start = start_time + timedelta(minutes=60)

    for i in range(6):
        timestamp = compromise_start + timedelta(seconds=i * 5)
        port = random.randint(40000, 60000)

        add_event(
            timestamp, f"Failed password for admin from {COMPROMISE_TEST_IP} port {port} ssh2"
        )

    success_time = compromise_start + timedelta(seconds=35)

    add_event(
        success_time, f"Accepted password for admin from {COMPROMISE_TEST_IP} port 54321 ssh2"
    )

    # Sort chronologically before writing.
    events.sort(key=lambda event: event[0])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as log_file:
        for _, log_line in events:
            log_file.write(log_line + "\n")

    print("=" * 60)
    print("SYNTHETIC SSH LOG GENERATOR")
    print("=" * 60)
    print(f"Events generated : {len(events)}")
    print(f"Output file      : {OUTPUT_FILE}")
    print("Network activity : None")
    print("=" * 60)


if __name__ == "__main__":
    random.seed(42)
    generate_logs()
