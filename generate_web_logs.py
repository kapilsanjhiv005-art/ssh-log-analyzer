"""Generate safe synthetic combined access logs with documentation IPs only."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_FILE = Path("sample_logs/web_access.log")
NORMAL_IP = "192.0.2.50"
LOGIN_IP = "198.51.100.80"
SCAN_IP = "203.0.113.90"
TOOL_IP = "198.51.100.91"


def format_access(
    timestamp: datetime, ip: str, method: str, path: str, status: int, user_agent: str
) -> str:
    """Format one Apache/Nginx combined access-log row."""
    stamp = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 512 "-" "{user_agent}"'


def generate_web_logs(output_file: str | Path = OUTPUT_FILE) -> Path:
    """Write representative successful and suspicious HTTP events offline."""
    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    start = datetime(2026, 10, 19, 8, 0)
    rows = []
    for index in range(5):
        rows.append(
            format_access(
                start + timedelta(minutes=index),
                NORMAL_IP,
                "GET",
                "/",
                200,
                "Mozilla/5.0 (Example Browser)",
            )
        )
    for index in range(5):
        rows.append(
            format_access(
                start + timedelta(minutes=10, seconds=index * 5),
                LOGIN_IP,
                "POST",
                "/login",
                401,
                "Mozilla/5.0 (Example Browser)",
            )
        )
    for index in range(12):
        rows.append(
            format_access(
                start + timedelta(minutes=20, seconds=index * 3),
                SCAN_IP,
                "GET",
                f"/missing-{index}",
                404,
                "Mozilla/5.0 (Example Browser)",
            )
        )
    rows.append(
        format_access(
            start + timedelta(minutes=30), TOOL_IP, "GET", "/", 200, "Nmap Scripting Engine"
        )
    )
    rows.sort()
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"Synthetic web events: {len(rows)}")
    print(f"Output file         : {output}")
    print("Network activity    : None")
    return output


if __name__ == "__main__":
    generate_web_logs()
