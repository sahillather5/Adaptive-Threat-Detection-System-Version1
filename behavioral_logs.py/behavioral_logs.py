import os
import csv
import socket
import uuid
import platform
import ctypes
import time
import win32evtlog
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# =========================
# CONFIGURATION
# =========================

BEHAVIORAL_DIR  = "behavioral_data"
BEHAVIORAL_FILE = os.path.join(BEHAVIORAL_DIR, "behavioral_logs.csv")
LOG_TYPE        = "Security"
SUCCESS_ID      = 4624
FAILURE_ID      = 4625

# 24 columns — includes lat/lon for real geo-velocity
COLUMNS = [
    "timestamp",
    "date",
    "login_hour",
    "login_minute",
    "day_of_week",
    "status",
    "user",
    "ip_address",
    "location",
    "location_lat",       # NEW: latitude for haversine
    "location_lon",       # NEW: longitude for haversine
    "hostname",
    "os_version",
    "mac_address",
    "screen_resolution",
    "typing_speed_category",
    "typing_speed_seconds",
    "rapid_retries_10sec",
    "login_source_type",
    "failed_to_success_ratio",
    "is_first_seen_device",
    "is_first_seen_ip",
    "is_first_seen_location",
    "session_gap_minutes",
]

# =========================
# DEVICE INFO
# Collected once — same for every login event
# =========================

def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "unknown"

def get_os_version():
    try:
        return f"Windows {platform.version()}"
    except:
        return "unknown"

def get_mac_address():
    try:
        mac = uuid.getnode()
        return ':'.join(
            f'{(mac >> (8*i)) & 0xff:02x}'
            for i in reversed(range(6))
        )
    except:
        return "unknown"

def get_screen_resolution():
    try:
        u32 = ctypes.windll.user32
        return f"{u32.GetSystemMetrics(0)}x{u32.GetSystemMetrics(1)}"
    except:
        return "unknown"

def get_location_from_ip(ip):
    """
    Returns (location_str, latitude, longitude).
    Now returns lat/lon for real haversine distance calculation.
    """
    if not REQUESTS_AVAILABLE:
        return "unknown", 0.0, 0.0
    try:
        if ip in ("local", "unknown", "::1",
                  "127.0.0.1", "-", ""):
            r = requests.get(
                "http://ip-api.com/json/", timeout=5)
        else:
            r = requests.get(
                f"http://ip-api.com/json/{ip}", timeout=5)

        data = r.json()
        if data.get("status") == "success":
            city    = data.get("city",       "unknown")
            region  = data.get("regionName", "unknown")
            country = data.get("country",    "unknown")
            lat     = float(data.get("lat",  0.0))
            lon     = float(data.get("lon",  0.0))
            return f"{city}, {region}, {country}", lat, lon

        return "unknown", 0.0, 0.0
    except:
        return "unknown", 0.0, 0.0

# =========================
# TYPING SPEED ANALYSIS
# Detects automated bots vs human typing
# =========================

def analyze_typing_speed():
    try:
        h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        batch = win32evtlog.ReadEventLog(h, flags, 0)
        win32evtlog.CloseEventLog(h)

        if not batch:
            return "unknown", -1

        failures = [e for e in batch
                    if (e.EventID & 0xFFFF) == FAILURE_ID][:3]

        if len(failures) < 2:
            return "unknown", -1

        t1   = datetime.fromtimestamp(int(failures[0].TimeGenerated))
        t2   = datetime.fromtimestamp(int(failures[1].TimeGenerated))
        diff = abs((t1 - t2).total_seconds())

        if diff < 1:
            return "automated", round(diff, 3)
        elif diff <= 10:
            return "normal", round(diff, 1)
        elif diff <= 30:
            return "slow", round(diff, 1)
        else:
            return "very_slow", round(diff, 1)
    except:
        return "unknown", -1

# =========================
# RAPID RETRY COUNT
# Failures in last 10 seconds = brute force indicator
# =========================

def get_rapid_retry_count():
    try:
        h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        batch = win32evtlog.ReadEventLog(h, flags, 0)
        win32evtlog.CloseEventLog(h)

        if not batch:
            return 0

        cutoff = time.time() - 10
        count  = 0
        for e in batch:
            if (e.EventID & 0xFFFF) != FAILURE_ID:
                continue
            try:
                if int(e.TimeGenerated) >= cutoff:
                    count += 1
            except:
                continue
        return count
    except:
        return 0

# =========================
# LOGIN SOURCE TYPE
# Interactive=2, Network=3, RDP=10
# =========================

def get_login_source_type(event):
    try:
        if event.StringInserts and len(event.StringInserts) > 8:
            logon_type = str(event.StringInserts[8]).strip()
            return {
                "2":  "interactive",
                "3":  "network",
                "7":  "unlock",
                "10": "remote_desktop",
                "11": "cached_interactive"
            }.get(logon_type, f"type_{logon_type}")
        return "unknown"
    except:
        return "unknown"

# =========================
# FAILURE/SUCCESS RATIO
# Failures in last 5 minutes before this success
# =========================

def get_failure_success_ratio():
    try:
        h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        batch = win32evtlog.ReadEventLog(h, flags, 0)
        win32evtlog.CloseEventLog(h)

        if not batch:
            return 0

        cutoff   = time.time() - 300
        failures = 0
        for e in batch:
            eid = e.EventID & 0xFFFF
            try:
                et = int(e.TimeGenerated)
            except:
                continue
            if et < cutoff:
                break
            if eid == FAILURE_ID:
                failures += 1
        return failures
    except:
        return 0

# =========================
# SESSION GAP
# Time since last successful login
# =========================

def get_session_gap():
    try:
        if not os.path.exists(BEHAVIORAL_FILE):
            return -1
        last_ts = None
        with open(BEHAVIORAL_FILE, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("status") == "success":
                    last_ts = row.get("timestamp", "")
        if not last_ts:
            return -1
        last_dt = datetime.strptime(
            last_ts, "%Y-%m-%d %H:%M:%S")
        return round(
            (datetime.now() - last_dt).total_seconds() / 60, 1)
    except:
        return -1

# =========================
# FIRST SEEN CHECKS
# =========================

def load_known_values():
    known_macs      = set()
    known_ips       = set()
    known_locations = set()

    if not os.path.exists(BEHAVIORAL_FILE):
        return known_macs, known_ips, known_locations

    try:
        with open(BEHAVIORAL_FILE, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("mac_address"):
                    known_macs.add(row["mac_address"])
                if row.get("ip_address"):
                    known_ips.add(row["ip_address"])
                if row.get("location"):
                    known_locations.add(row["location"])
    except:
        pass

    return known_macs, known_ips, known_locations

# =========================
# MAIN COLLECTION FUNCTION
# Called from collector_windows.py on each event
# =========================

def collect_behavioral_data(event):
    eid  = event.EventID & 0xFFFF
    user = "unknown"
    ip   = "local"

    if event.StringInserts:
        if len(event.StringInserts) > 5:
            user = str(event.StringInserts[5]).strip()
        if len(event.StringInserts) > 18:
            raw  = str(event.StringInserts[18]).strip()
            # FIX: reject Windows process paths as IPs
            if (raw not in ("-", "", "::1", "127.0.0.1")
                    and not raw.startswith("C:\\")
                    and not raw.startswith("\\")):
                ip = raw

    status = "success" if eid == SUCCESS_ID else "failure"
    now    = datetime.now()

    location, lat, lon      = get_location_from_ip(ip)
    typing_cat, typing_secs = analyze_typing_speed()
    rapid_retries           = get_rapid_retry_count()
    login_source            = get_login_source_type(event)
    fail_ratio              = get_failure_success_ratio()
    session_gap             = get_session_gap()

    known_macs, known_ips, known_locs = load_known_values()
    current_mac = get_mac_address()

    return {
        "timestamp":              now.strftime("%Y-%m-%d %H:%M:%S"),
        "date":                   now.strftime("%Y-%m-%d"),
        "login_hour":             now.hour,
        "login_minute":           now.minute,
        "day_of_week":            now.strftime("%A"),
        "status":                 status,
        "user":                   user,
        "ip_address":             ip,
        "location":               location,
        "location_lat":           lat,
        "location_lon":           lon,
        "hostname":               get_hostname(),
        "os_version":             get_os_version(),
        "mac_address":            current_mac,
        "screen_resolution":      get_screen_resolution(),
        "typing_speed_category":  typing_cat,
        "typing_speed_seconds":   typing_secs,
        "rapid_retries_10sec":    rapid_retries,
        "login_source_type":      login_source,
        "failed_to_success_ratio": fail_ratio,
        "is_first_seen_device":   str(current_mac not in known_macs),
        "is_first_seen_ip":       str(ip not in known_ips),
        "is_first_seen_location": str(location not in known_locs),
        "session_gap_minutes":    session_gap,
    }

def save_behavioral_data(data):
    os.makedirs(BEHAVIORAL_DIR, exist_ok=True)
    file_exists = os.path.exists(BEHAVIORAL_FILE)
    with open(BEHAVIORAL_FILE, "a", newline="",
              encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# =========================
# STANDALONE TEST
# =========================

if __name__ == "__main__":
    print("="*50)
    print("  Behavioral Collector — Device Info Test")
    print("="*50 + "\n")
    print(f"  Hostname    : {get_hostname()}")
    print(f"  OS          : {get_os_version()}")
    print(f"  MAC Address : {get_mac_address()}")
    print(f"  Resolution  : {get_screen_resolution()}")
    loc, lat, lon = get_location_from_ip("local")
    print(f"  Location    : {loc}")
    print(f"  Coordinates : {lat}, {lon}")
    print(f"  Rapid retry : {get_rapid_retry_count()}")
    print(f"  Fail ratio  : {get_failure_success_ratio()}")
    print(f"  Session gap : {get_session_gap()} mins")
    typing_cat, typing_secs = analyze_typing_speed()
    print(f"  Typing speed: {typing_cat} ({typing_secs}s)")
    print(f"\n[+] Behavioral collector ready!")
    print(f"[+] Data will save to: {BEHAVIORAL_FILE}")