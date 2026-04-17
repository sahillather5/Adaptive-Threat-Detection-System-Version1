import os
import csv
import json
from datetime import datetime, timedelta
from collections import Counter

# =========================
# CONFIGURATION
# =========================

BEHAVIORAL_DIR  = "behavioral_data"
BEHAVIORAL_FILE = os.path.join(BEHAVIORAL_DIR, "behavioral_logs.csv")
BASELINE_FILE   = os.path.join(BEHAVIORAL_DIR, "baseline.json")
ROLLING_DAYS    = 45


# Must match COLUMNS in behavioral_collector.py exactly
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
    "location_lat",
    "location_lon",
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
# LOAD DATA
# =========================

def load_behavioral_data(days=ROLLING_DAYS):
    if not os.path.exists(BEHAVIORAL_FILE):
        return []
    cutoff = datetime.now() - timedelta(days=days)
    rows   = []
    try:
        with open(BEHAVIORAL_FILE, "r",
                  encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    ts = datetime.strptime(
                        row["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff:
                        rows.append(row)
                except:
                    continue
    except Exception as e:
        print(f"[-] Error loading data: {e}")
    return rows

# =========================
# CALCULATE BASELINE
# =========================

def calculate_baseline(rows):
    if not rows:
        return {}

    success_rows = ([r for r in rows
                     if r.get("status") == "success"]
                    or rows)
    failure_rows = [r for r in rows
                    if r.get("status") == "failure"]

    # 1. Login Hours
    hours = [int(r["login_hour"]) for r in success_rows
             if r.get("login_hour", "").isdigit()]
    hour_counts   = Counter(hours)
    total_logins  = len(hours)
    normal_hours  = sorted(set(hours))
    typical_hours = sorted({
        h for h, c in hour_counts.items()
        if c / max(total_logins, 1) > 0.1
    })

    # 2. Login Frequency
    dates          = [r["date"] for r in success_rows
                      if r.get("date")]
    date_counts    = Counter(dates)
    avg_logins_per_day = (
        sum(date_counts.values()) /
        max(len(date_counts), 1)
    )
    max_logins_per_day = (
        max(date_counts.values()) if date_counts else 5)

    # 3. Known IPs
    known_ips = list({
        r["ip_address"] for r in rows
        if r.get("ip_address") and
        r["ip_address"] not in ("unknown", "-")
    })

    # 4. Known MACs
    known_macs = list({
        r["mac_address"] for r in rows
        if r.get("mac_address") and
        r["mac_address"] != "unknown"
    })

    # 5. Known Hostnames
    known_hostnames = list({
        r["hostname"] for r in rows
        if r.get("hostname") and
        r["hostname"] != "unknown"
    })

    # 6. Known Locations (case-normalized)
    known_locations = list({
        r["location"].strip().lower() for r in rows
        if r.get("location") and
        r["location"] not in ("unknown", "")
    })

    # 7. Known Location Coordinates
    # Stores {location_str: [lat, lon]} for geo-velocity
    known_location_coords = {}
    for r in rows:
        loc = r.get("location", "").strip().lower()
        try:
            lat = float(r.get("location_lat", 0))
            lon = float(r.get("location_lon", 0))
            if loc and loc != "unknown" and (lat != 0.0
                                             or lon != 0.0):
                known_location_coords[loc] = [lat, lon]
        except:
            pass

    # 8. Known OS
    known_os = list({
        r["os_version"] for r in rows
        if r.get("os_version") and
        r["os_version"] != "unknown"
    })

    # 9. Known Resolutions
    known_resolutions = list({
        r["screen_resolution"] for r in rows
        if r.get("screen_resolution") and
        r["screen_resolution"] != "unknown"
    })

    # 10. Known Login Sources
    known_sources = list({
        r["login_source_type"] for r in success_rows
        if r.get("login_source_type") and
        r["login_source_type"] != "unknown"
    })

    # 11. Session Gaps
    gaps = []
    for r in success_rows:
        try:
            gap = float(r.get("session_gap_minutes", -1))
            if gap > 0:
                gaps.append(gap)
        except:
            continue
    avg_session_gap = (
        sum(gaps) / len(gaps) if gaps else -1)
    min_session_gap = (min(gaps) if gaps else -1)

    # 12. Failure Rate
    normal_failure_rate = (
        len(failure_rows) / max(len(rows), 1))

    # 13. Last Login
    last_login_str = ""
    if success_rows:
        try:
            last_login_str = max(
                datetime.strptime(r["timestamp"],
                                  "%Y-%m-%d %H:%M:%S")
                for r in success_rows
            ).strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass

    return {
        "generated_at":          datetime.now().strftime(
                                      "%Y-%m-%d %H:%M:%S"),
        "data_points":           len(rows),
        "days_analyzed":         len(date_counts),
        "last_login":            last_login_str,

        "normal_hours":          normal_hours,
        "typical_hours":         typical_hours,

        "avg_logins_per_day":    round(avg_logins_per_day, 2),
        "max_logins_per_day":    max_logins_per_day,

        "known_ips":             known_ips,
        "known_macs":            known_macs,
        "known_hostnames":       known_hostnames,
        "known_locations":       known_locations,
        "known_location_coords": known_location_coords,
        "known_os":              known_os,
        "known_resolutions":     known_resolutions,
        "known_sources":         known_sources,

        "avg_session_gap_mins":  round(avg_session_gap, 1),
        "min_session_gap_mins":  round(min_session_gap, 1),

        "normal_failure_rate":   round(normal_failure_rate, 3),

        "thresholds": {
            "max_logins_per_day":       max_logins_per_day * 2,
            "rapid_retry_limit":        5,
            "typing_speed_auto_secs":   1.0,
            "fail_before_success_high": 5,
            "fail_before_success_crit": 10,
            "session_gap_min_mins":     1,
            "long_absence_days":        30,
            "geo_velocity_km_per_hr":   900,
        }
    }

# =========================
# SAVE / LOAD BASELINE
# =========================

def save_baseline(baseline):
    os.makedirs(BEHAVIORAL_DIR, exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    print(f"[+] Baseline saved → {BASELINE_FILE}")

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

# =========================
# BUILD BASELINE
# =========================

def build_baseline():
    print("[*] Loading behavioral data...")
    rows = load_behavioral_data(days=ROLLING_DAYS)

    if not rows:
        print("[-] No behavioral data found.")
        print("    Run collector_windows.py to collect data.")
        return None

    print(f"[*] Analyzing {len(rows)} records "
          f"from last {ROLLING_DAYS} days...")

    baseline = calculate_baseline(rows)
    save_baseline(baseline)

    print(f"\n--- Baseline Summary ---")
    print(f"  Data points     : {baseline['data_points']}")
    print(f"  Days analyzed   : {baseline['days_analyzed']}")
    print(f"  Typical hours   : {baseline['typical_hours']}")
    print(f"  Avg logins/day  : {baseline['avg_logins_per_day']}")
    print(f"  Known IPs       : {len(baseline['known_ips'])}")
    print(f"  Known devices   : {len(baseline['known_macs'])}")
    print(f"  Known locations : {len(baseline['known_locations'])}")
    print(f"  Location coords : "
          f"{len(baseline['known_location_coords'])}")
    print(f"  Avg session gap : "
          f"{baseline['avg_session_gap_mins']} mins")

    return baseline

# =========================
# IMPORT FROM login_logs.csv
# Bootstraps System 2 from System 1 data
# =========================

def import_existing_logs():
    existing_file = "login_logs.csv"
    if not os.path.exists(existing_file):
        print("[-] login_logs.csv not found.")
        return 0

    os.makedirs(BEHAVIORAL_DIR, exist_ok=True)

    
    # (wrong columns in first row), wipe it and start fresh
    if os.path.exists(BEHAVIORAL_FILE):
        try:
            with open(BEHAVIORAL_FILE, "r",
                      encoding="utf-8") as f:
                header = f.readline().strip()
            # If first column is not "timestamp" the file
            # is malformed — delete and recreate
            if not header.startswith("timestamp"):
                os.remove(BEHAVIORAL_FILE)
                print("[!] Malformed behavioral_logs.csv "
                      "detected — rebuilding...")
        except:
            pass

    file_exists = os.path.exists(BEHAVIORAL_FILE)
    imported    = 0

    # Get current device info
    current_mac      = "unknown"
    current_hostname = "unknown"
    current_os       = "unknown"
    current_res      = "unknown"

    try:
        import socket, uuid, platform, ctypes
        mac = uuid.getnode()
        current_mac = ':'.join(
            f'{(mac >> (8*i)) & 0xff:02x}'
            for i in reversed(range(6))
        )
        current_hostname = socket.gethostname()
        current_os       = f"Windows {platform.version()}"
        u32 = ctypes.windll.user32
        current_res = (f"{u32.GetSystemMetrics(0)}"
                       f"x{u32.GetSystemMetrics(1)}")
    except:
        pass

    # Skip users that are Windows internal accounts
    skip_users = {"SYSTEM", "LOCAL SERVICE",
                  "NETWORK SERVICE", "ANONYMOUS LOGON",
                  "-", "unknown"}

    print(f"[*] Importing from {existing_file}...")

    with open(existing_file, "r",
              encoding="utf-8") as src:
        reader = csv.DictReader(src)
        with open(BEHAVIORAL_FILE, "a", newline="",
                  encoding="utf-8") as dst:
            writer = csv.DictWriter(dst, fieldnames=COLUMNS)
            if not file_exists:
                writer.writeheader()
            for row in reader:
                try:
                    ts = row.get("timestamp", "")
                    dt = datetime.strptime(
                        ts, "%Y-%m-%d %H:%M:%S")
                    user = row.get("user_hash", "")

                    # Skip Windows internal accounts
                    if user in skip_users:
                        continue
                    if (user.startswith("DWM-") or
                            user.startswith("UMFD-")):
                        continue

                    # Fix IP — skip svchost paths
                    ip = row.get("ip_address", "")
                    if (ip.startswith("C:\\") or
                            ip.startswith("\\")):
                        ip = "local"

                    new = {
                        "timestamp":    ts,
                        "date":         dt.strftime("%Y-%m-%d"),
                        "login_hour":   str(dt.hour),
                        "login_minute": str(dt.minute),
                        "day_of_week":  dt.strftime("%A"),
                        "status":       row.get("login_status", ""),
                        "user":         user,
                        "ip_address":   ip,
                        "location":          "unknown",
                        "location_lat":      "0.0",
                        "location_lon":      "0.0",
                        "hostname":          current_hostname,
                        "os_version":        current_os,
                        "mac_address":       current_mac,
                        "screen_resolution": current_res,
                        "typing_speed_category": "unknown",
                        "typing_speed_seconds":  "-1",
                        "rapid_retries_10sec":   "0",
                        "login_source_type":     "unknown",
                        "failed_to_success_ratio": "0",
                        "is_first_seen_device":  "False",
                        "is_first_seen_ip":      "False",
                        "is_first_seen_location":"False",
                        "session_gap_minutes":   "-1",
                    }
                    writer.writerow(new)
                    imported += 1
                except:
                    continue

    print(f"[+] Imported {imported} records "
          f"(SYSTEM/service accounts filtered out)")
    return imported

# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    print("="*50)
    print("  Baseline Engine")
    print("="*50 + "\n")

    if not os.path.exists(BEHAVIORAL_FILE):
        print("[*] No behavioral data found.")
        print("[*] Importing from login_logs.csv...")
        count = import_existing_logs()
        if count == 0:
            print("[-] No data to import.")
            print("    Run collector_windows.py first.")
            exit()
        print(f"[+] {count} records imported!")

    print()
    baseline = build_baseline()
    if baseline:
        print(f"\n[+] Baseline built successfully!")
        print(f"[+] Saved to: behavioral_data/baseline.json")