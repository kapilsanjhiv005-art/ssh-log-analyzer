"""Configuration and allowlist loading for SSH detections."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "brute_force": {"threshold": 5, "window_seconds": 60},
    "password_spraying": {"username_threshold": 5, "window_seconds": 60},
    "username_enumeration": {"threshold": 4, "window_seconds": 60},
    "distributed_bruteforce": {"ip_threshold": 5, "window_seconds": 120},
    "root_attempts": {"minimum_attempts": 3, "window_seconds": 60},
    # None means use each rule's own detection window as its merge gap.
    "alert_merging": {"merge_gap_seconds": None},
    "severity_thresholds": {"high_attempts": 50, "sustained_attempts": 200},
    "success_after_failures": {"failure_threshold": 5, "lookback_seconds": 300},
    "new_source_ip": {"trusted_local_sources": ["127.0.0.1/32", "::1/128"]},
    "off_hours": {"business_start": "08:00", "business_end": "19:00"},
    "web": {
        "login_paths": ["/login", "/wp-login.php", "/admin"],
        "login_threshold": 5,
        "login_window_seconds": 60,
        "scanning_404_threshold": 10,
        "scanning_window_seconds": 60,
        "suspicious_user_agents": ["sqlmap", "nikto", "nmap", "masscan", "acunetix"],
        "user_agent_window_seconds": 60,
        "success_after_failures_threshold": 5,
    },
}


def _merge_defaults(
    defaults: dict[str, Any], supplied: dict[str, Any], path: str = "config"
) -> dict[str, Any]:
    """Merge nested user values with defaults and reject unknown keys."""
    result = {}
    for key, default in defaults.items():
        value = supplied.get(key, {})
        if isinstance(default, dict):
            if not isinstance(value, dict):
                raise ValueError(f"{path}.{key} must be a mapping")
            result[key] = _merge_defaults(default, value, f"{path}.{key}")
        else:
            result[key] = value if key in supplied else default
    unknown = set(supplied) - set(defaults)
    if unknown:
        raise ValueError(f"Unknown {path} key(s): {', '.join(sorted(unknown))}")
    return result


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _clock_minutes(value: Any, name: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{name} must use HH:MM format")
    try:
        hour_text, minute_text = value.split(":")
        hour, minute = int(hour_text), int(minute_text)
    except (ValueError, TypeError):
        raise ValueError(f"{name} must use valid HH:MM format") from None
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"{name} must be a valid time from 00:00 through 23:59")
    return hour * 60 + minute


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """Validate thresholds and business-hour boundaries with clear errors."""
    for section, keys in {
        "brute_force": ("threshold", "window_seconds"),
        "password_spraying": ("username_threshold", "window_seconds"),
        "username_enumeration": ("threshold", "window_seconds"),
        "distributed_bruteforce": ("ip_threshold", "window_seconds"),
        "root_attempts": ("minimum_attempts", "window_seconds"),
        "success_after_failures": ("failure_threshold", "lookback_seconds"),
        "web": (
            "login_threshold",
            "login_window_seconds",
            "scanning_404_threshold",
            "scanning_window_seconds",
            "user_agent_window_seconds",
            "success_after_failures_threshold",
        ),
    }.items():
        for key in keys:
            config[section][key] = _positive_int(config[section][key], f"{section}.{key}")
    merge_gap = config["alert_merging"]["merge_gap_seconds"]
    if merge_gap is not None and (
        isinstance(merge_gap, bool) or not isinstance(merge_gap, int) or merge_gap < 0
    ):
        raise ValueError("alert_merging.merge_gap_seconds must be null or a non-negative integer")
    for key in ("high_attempts", "sustained_attempts"):
        config["severity_thresholds"][key] = _positive_int(
            config["severity_thresholds"][key], f"severity_thresholds.{key}"
        )
    if (
        config["severity_thresholds"]["sustained_attempts"]
        < config["severity_thresholds"]["high_attempts"]
    ):
        raise ValueError("severity_thresholds.sustained_attempts must be at least high_attempts")
    local_sources = config["new_source_ip"]["trusted_local_sources"]
    if not isinstance(local_sources, list):
        raise ValueError("new_source_ip.trusted_local_sources must be a list of IP/CIDR strings")
    for source in local_sources:
        if not isinstance(source, str) or not source.strip():
            raise ValueError(
                "new_source_ip.trusted_local_sources entries must be non-empty IP/CIDR strings"
            )
        try:
            ipaddress.ip_network(source, strict=False)
        except ValueError as error:
            raise ValueError(
                f"Invalid new_source_ip.trusted_local_sources entry: {source}"
            ) from error
    start = _clock_minutes(config["off_hours"]["business_start"], "off_hours.business_start")
    end = _clock_minutes(config["off_hours"]["business_end"], "off_hours.business_end")
    if start == end:
        raise ValueError("off_hours business_start and business_end must differ")
    web = config["web"]
    if not isinstance(web["login_paths"], list) or not web["login_paths"]:
        raise ValueError("web.login_paths must be a non-empty list of path strings")
    if any(not isinstance(path, str) or not path.startswith("/") for path in web["login_paths"]):
        raise ValueError("web.login_paths entries must be strings starting with '/'")
    if not isinstance(web["suspicious_user_agents"], list):
        raise ValueError("web.suspicious_user_agents must be a list of strings")
    if any(
        not isinstance(agent, str) or not agent.strip() for agent in web["suspicious_user_agents"]
    ):
        raise ValueError("web.suspicious_user_agents entries must be non-empty strings")
    return config


def load_config(path: str | Path | None = "config.yaml") -> dict[str, Any]:
    """Load validated configuration; a missing file uses built-in defaults."""
    supplied: dict[str, Any] = {}
    if path is not None and Path(path).is_file():
        try:
            loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid YAML in {path}: {error}") from error
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ValueError("Configuration root must be a mapping")
            supplied = loaded
    return validate_config(_merge_defaults(DEFAULT_CONFIG, supplied))


def load_allowlist(
    path: str | Path | None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    """Read IP/CIDR entries, ignoring blank lines and comments."""
    if path is None:
        return None
    networks = []
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as error:
            raise ValueError(f"Invalid IP/CIDR on {path}:{line_number}: {value}") from error
    return networks


def is_allowlisted(source_ip: str | None, allowlist: list[Any] | None) -> bool:
    """Return whether an IP address belongs to any supplied trusted network."""
    if not source_ip or not allowlist:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in allowlist)


def is_trusted_source(
    source_ip: str | None,
    allowlist: list[Any] | None = None,
    trusted_networks: list[str | ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
) -> bool:
    """Apply the shared allowlist plus detection-specific trusted-network policy."""
    if is_allowlisted(source_ip, allowlist):
        return True
    if not source_ip:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    for item in trusted_networks or []:
        network = ipaddress.ip_network(item, strict=False) if isinstance(item, str) else item
        if address.version == network.version and address in network:
            return True
    return False
