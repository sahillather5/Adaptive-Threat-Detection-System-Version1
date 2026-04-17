import os
import csv
import json
import smtplib
import threading
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from baseline_engine import load_baseline

BEHAVIORAL_DIR  = "behavioral_data"
ANOMALY_FILE    = os.path.join(BEHAVIORAL_DIR, "anomaly_log.csv")
CONFIG_FILE     = "alert_config.json"
SENDER_EMAIL    = ""
SENDER_PASSWORD = ""
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 465

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

def haversine_km(lat1, lon1, lat2, lon2):
    R    = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a    = (sin(dlat/2)**2 +
            cos(radians(lat1)) * cos(radians(lat2)) *
            sin(dlon/2)**2)
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))

def get_receiver_email():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                return json.load(f)["email"]
    except:
        pass
    return ""

def send_anomaly_email(subject, body, alert_level):
    def _send():
        try:
            receiver = get_receiver_email()
            if not receiver or not SENDER_EMAIL:
                return
            prefix = {CRITICAL:"[CRITICAL ALERT]",
                      HIGH:"[HIGH ALERT]",
                      MEDIUM:"[MEDIUM ALERT]",
                      LOW:"[LOW ALERT]"}.get(alert_level,"[ALERT]")
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"{prefix} {subject}"
            msg["From"]    = SENDER_EMAIL
            msg["To"]      = receiver
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
                s.login(SENDER_EMAIL, SENDER_PASSWORD)
                s.send_message(msg)
            print(f"[+] {alert_level} anomaly email sent.")
        except Exception as e:
            print(f"[-] Email error: {e}")
    threading.Thread(target=_send, daemon=True).start()

def save_anomaly(anomaly):
    os.makedirs(BEHAVIORAL_DIR, exist_ok=True)
    file_exists = os.path.exists(ANOMALY_FILE)
    columns = ["timestamp","alert_level","anomaly_type",
               "description","user","ip_address",
               "location","device","details"]
    with open(ANOMALY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        if not file_exists:
            writer.writeheader()
        writer.writerow(anomaly)

# =========================
# 11 ANOMALY CHECKS
# =========================

def check_geographic_velocity(data, baseline, prev_login):
    if not prev_login or not baseline:
        return None
    try:
        lat1 = float(prev_login.get("location_lat", 0))
        lon1 = float(prev_login.get("location_lon", 0))
        lat2 = float(data.get("location_lat", 0))
        lon2 = float(data.get("location_lon", 0))
        if (lat1 == 0.0 and lon1 == 0.0) or (lat2 == 0.0 and lon2 == 0.0):
            return None
        if lat1 == lat2 and lon1 == lon2:
            return None
        dist_km   = haversine_km(lat1, lon1, lat2, lon2)
        if dist_km < 50:
            return None
        prev_ts   = datetime.strptime(prev_login["timestamp"], "%Y-%m-%d %H:%M:%S")
        curr_ts   = datetime.strptime(data["timestamp"],       "%Y-%m-%d %H:%M:%S")
        gap_hrs   = max(abs((curr_ts - prev_ts).total_seconds() / 3600), 0.01)
        speed_kmh = dist_km / gap_hrs
        max_speed = baseline.get("thresholds",{}).get("geo_velocity_km_per_hr", 900)
        if speed_kmh > max_speed:
            return (CRITICAL, "Geographic Velocity",
                    f"Impossible travel: {round(dist_km)} km in {round(gap_hrs,1)} hrs",
                    f"From: {prev_login.get('location')} → To: {data.get('location')} | "
                    f"Distance: {round(dist_km)} km | Speed: {round(speed_kmh)} km/h")
    except:
        pass
    return None

def check_unknown_device(data, baseline):
    if not baseline:
        return None
    mac         = data.get("mac_address", "unknown")
    known_macs  = baseline.get("known_macs", [])
    hostname    = data.get("hostname", "unknown")
    known_hosts = baseline.get("known_hostnames", [])
    if mac == "unknown":
        return None
    if mac not in known_macs and len(known_macs) > 0:
        return (HIGH, "Unknown Device",
                "Login from device never seen before",
                f"Unknown MAC: {mac} | Hostname: {hostname} | Known devices: {len(known_macs)}")
    if (hostname not in known_hosts and hostname != "unknown" and len(known_hosts) > 0):
        return (HIGH, "Unknown Hostname", "Login from unknown hostname",
                f"Unknown hostname: {hostname} | MAC: {mac}")
    return None

def check_automated_attack(data, baseline):
    typing_cat    = data.get("typing_speed_category", "")
    typing_secs   = float(data.get("typing_speed_seconds", -1))
    rapid_retries = int(data.get("rapid_retries_10sec", 0))
    threshold     = baseline.get("thresholds",{}).get("rapid_retry_limit", 5) if baseline else 5
    if typing_cat == "automated":
        return (HIGH, "Automated Attack",
                "Password attempts too fast for human typing",
                f"Typing speed: {typing_secs}s (automated: <1s) | Rapid retries: {rapid_retries}")
    if rapid_retries >= threshold:
        return (HIGH, "Brute Force Detected",
                f"{rapid_retries} login attempts in 10 seconds",
                f"Rapid retries: {rapid_retries} | Threshold: {threshold} | Typing: {typing_cat}")
    return None

def check_account_takeover(data, baseline):
    if not baseline:
        return None
    fail_ratio = int(data.get("failed_to_success_ratio", 0))
    if data.get("status") != "success":
        return None
    thresholds = baseline.get("thresholds", {})
    high_limit = thresholds.get("fail_before_success_high", 5)
    crit_limit = thresholds.get("fail_before_success_crit", 10)
    if fail_ratio >= crit_limit:
        return (CRITICAL, "Account Takeover Suspected",
                f"{fail_ratio} failed attempts before success",
                f"Failures before success: {fail_ratio} | Critical threshold: {crit_limit}")
    if fail_ratio >= high_limit:
        return (HIGH, "Suspicious Login Pattern",
                f"{fail_ratio} failed attempts then success",
                f"Failures before success: {fail_ratio} | High threshold: {high_limit}")
    return None

def check_unusual_time(data, baseline):
    if not baseline:
        return None
    hour        = int(data.get("login_hour", -1))
    typical_hrs = baseline.get("typical_hours", [])
    if hour < 0 or not typical_hrs:
        return None
    if hour not in typical_hrs:
        return (MEDIUM, "Unusual Login Time",
                f"Login at {hour:02d}:00 outside normal hours",
                f"Login hour: {hour:02d}:00 | Normal hours: {typical_hrs}")
    return None

def check_unknown_ip(data, baseline):
    if not baseline:
        return None
    ip        = data.get("ip_address", "local")
    known_ips = baseline.get("known_ips", [])
    if ip in ("local", "unknown", "-") or not known_ips:
        return None
    if ip not in known_ips:
        return (MEDIUM, "Unknown IP Address",
                "Login from IP never seen before",
                f"Unknown IP: {ip} | Known IPs: {len(known_ips)}")
    return None

def check_high_frequency(data, baseline):
    if not baseline:
        return None
    today     = data.get("date", "")
    threshold = baseline.get("thresholds",{}).get("max_logins_per_day", 10)
    bf        = os.path.join(BEHAVIORAL_DIR, "behavioral_logs.csv")
    if not today or not os.path.exists(bf):
        return None
    count = 0
    try:
        with open(bf, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("date") == today:
                    count += 1
    except:
        return None
    if count >= threshold:
        return (MEDIUM, "High Login Frequency",
                f"{count} login events today — unusually high",
                f"Today's events: {count} | Threshold: {threshold} | "
                f"Normal avg: {baseline.get('avg_logins_per_day','?')}/day")
    return None

def check_long_absence(data, baseline):
    if not baseline:
        return None
    last_login = baseline.get("last_login", "")
    if not last_login:
        return None
    try:
        days_absent   = (datetime.now() -
                         datetime.strptime(last_login, "%Y-%m-%d %H:%M:%S")).days
        absence_limit = baseline.get("thresholds",{}).get("long_absence_days", 30)
        if days_absent >= absence_limit:
            return (MEDIUM, "Long Absence Detected",
                    f"Account inactive for {days_absent} days",
                    f"Last login: {last_login} | Days absent: {days_absent} | "
                    f"Threshold: {absence_limit} days")
    except:
        pass
    return None

def check_new_location(data, baseline):
    if not baseline:
        return None
    location        = data.get("location", "unknown")
    known_locations = baseline.get("known_locations", [])
    if location in ("unknown", "") or not known_locations:
        return None
    if location.strip().lower() not in known_locations:
        return (LOW, "New Location", "Login from new location",
                f"New location: {location} | Known locations: {known_locations}")
    return None

def check_different_os(data, baseline):
    if not baseline:
        return None
    os_ver   = data.get("os_version", "unknown")
    known_os = baseline.get("known_os", [])
    if os_ver == "unknown" or not known_os:
        return None
    if os_ver not in known_os:
        return (LOW, "Different OS", "Login from different OS version",
                f"Current OS: {os_ver} | Known OS: {known_os}")
    return None

def check_different_resolution(data, baseline):
    if not baseline:
        return None
    res       = data.get("screen_resolution", "unknown")
    known_res = baseline.get("known_resolutions", [])
    if res == "unknown" or not known_res:
        return None
    if res not in known_res:
        return (LOW, "Different Screen Resolution",
                "Login from device with different resolution",
                f"Current: {res} | Known: {known_res}")
    return None

# =========================
# EMAIL BODY
# =========================

def build_email_body(anomaly_type, alert_level, description, details, data):
    ts   = data.get("timestamp",  "")
    user = data.get("user",       "unknown")
    ip   = data.get("ip_address", "local")
    loc  = data.get("location",   "unknown")
    messages = {
        "Geographic Velocity":      "IMPOSSIBLE TRAVEL DETECTED\n\nLogin from two locations impossible to travel\nbetween in that time. Change password IMMEDIATELY!",
        "Unknown Device":           "UNKNOWN DEVICE LOGIN\n\nLogin from a device never seen before.\nIf not you, someone has access.",
        "Unknown Hostname":         "UNKNOWN HOSTNAME DETECTED\n\nLogin from machine with unrecognized name.",
        "Automated Attack":         "AUTOMATED ATTACK DETECTED\n\nAttempts arriving too fast for a human.\nA script or bot is attacking your account.",
        "Brute Force Detected":     "BRUTE FORCE ATTACK\n\nMultiple rapid login attempts detected.",
        "Account Takeover Suspected": "ACCOUNT TAKEOVER SUSPECTED\n\nMany failures then success.\nChange your password IMMEDIATELY!",
    }
    specific_msg = messages.get(anomaly_type, "Suspicious activity detected.")
    body = (f"UEBA SECURITY — {alert_level} ALERT\n{'='*50}\n\n"
            f"Anomaly : {anomaly_type}\nLevel   : {alert_level}\n"
            f"Details : {description}\n\n{'='*50}\n\n{specific_msg}\n\n"
            f"{'='*50}\nTime: {ts} | User: {user} | IP: {ip} | Location: {loc}\n"
            f"Details: {details}\n{'='*50}\n")
    if alert_level == CRITICAL:
        body += "\nACTION: Change password immediately and check device access."
    elif alert_level == HIGH:
        body += "\nACTION: Verify this login was you."
    else:
        body += "\nACTION: Review if this activity was expected."
    return body

# =========================
# MAIN DETECTION FUNCTION
# =========================

def detect_anomalies(data, prev_login=None):
    baseline  = load_baseline()
    anomalies = []
    checks = [
        check_geographic_velocity(data, baseline, prev_login),
        check_unknown_device(data, baseline),
        check_automated_attack(data, baseline),
        check_account_takeover(data, baseline),
        check_unusual_time(data, baseline),
        check_unknown_ip(data, baseline),
        check_high_frequency(data, baseline),
        check_long_absence(data, baseline),
        check_new_location(data, baseline),
        check_different_os(data, baseline),
        check_different_resolution(data, baseline),
    ]
    for result in checks:
        if result is None:
            continue
        alert_level, anomaly_type, description, details = result
        print(f"  [{alert_level}] {anomaly_type}: {description}")
        anomaly = {
            "timestamp":    data.get("timestamp", ""),
            "alert_level":  alert_level,
            "anomaly_type": anomaly_type,
            "description":  description,
            "user":         data.get("user",       ""),
            "ip_address":   data.get("ip_address", ""),
            "location":     data.get("location",   ""),
            "device":       data.get("mac_address",""),
            "details":      details,
        }
        save_anomaly(anomaly)
        anomalies.append(anomaly)
        send_anomaly_email(
            f"{anomaly_type} — {description}",
            build_email_body(anomaly_type, alert_level, description, details, data),
            alert_level
        )
    return anomalies

# =========================
# ENTRY POINT — TEST MODE
# No hardcoded locations, IPs, or MACs
# =========================

if __name__ == "__main__":
    print("="*55)
    print("  Anomaly Detector — Test Mode")
    print("="*55 + "\n")

    baseline = load_baseline()
    if not baseline:
        print("[-] No baseline found.")
        print("    Run: python baseline_engine.py")
        exit()

    print(f"[+] Baseline loaded.")
    print(f"    Data points    : {baseline.get('data_points')}")
    print(f"    Typical hours  : {baseline.get('typical_hours')}")
    print(f"    Known IPs      : {len(baseline.get('known_ips',[]))}")
    print(f"    Known MACs     : {len(baseline.get('known_macs',[]))}")
    print(f"    Known locations: {baseline.get('known_locations')}")
    print(f"\n[*] Running tests...\n")

    # ── Read YOUR real values from baseline ──
    typical_hours = baseline.get("typical_hours", [15])
    known_ips     = baseline.get("known_ips", ["local"])
    known_macs    = baseline.get("known_macs", [])
    known_locs    = baseline.get("known_locations", [])
    known_hosts   = baseline.get("known_hostnames", [""])
    known_os_list = baseline.get("known_os", [""])
    known_res_list= baseline.get("known_resolutions", [""])
    coords        = baseline.get("known_location_coords", {})

    # Your known location string (title case)
    known_loc_str = known_locs[0].title() if known_locs else ""
    known_loc_key = known_locs[0] if known_locs else ""
    known_lat     = coords.get(known_loc_key, [])[0]
    known_lon     = coords.get(known_loc_key, [])[1]

    # An hour outside your normal hours
    all_hours     = list(range(0, 24))
    unusual_hours = [h for h in all_hours if h not in typical_hours]
    unusual_hour  = unusual_hours[0] if unusual_hours else 3

    # Unknown values (never in baseline)
    unknown_mac   = "ff:ff:ff:ff:ff:ff"
    unknown_ip    = "203.0.113.99"   # RFC 5737 test IP

    # ── TEST 1: Suspicious login ──
    print("--- TEST 1: Suspicious Login (expect 5+ alerts) ---")
    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    test_data = {
        "timestamp":               datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date":                    datetime.now().strftime("%Y-%m-%d"),
        "login_hour":              str(unusual_hour),
        "status":                  "success",
        "user":                    "test_user",
        "ip_address":              unknown_ip,
        "location":                "Tokyo, Kanto, Japan",
        "location_lat":            "35.6762",
        "location_lon":            "139.6503",
        "hostname":                "UNKNOWN-PC",
        "os_version":              "Windows Unknown",
        "mac_address":             unknown_mac,
        "screen_resolution":       "",
        "typing_speed_category":   "automated",
        "typing_speed_seconds":    "0.1",
        "rapid_retries_10sec":     "8",
        "login_source_type":       "network",
        "failed_to_success_ratio": "12",
        "session_gap_minutes":     "0.1",
    }

    # Previous login from YOUR real location
    # Tokyo → Rohtak in 1 hour = physically impossible
    prev_test = {
        "timestamp":    one_hour_ago,
        "location":     known_loc_str,
        "location_lat": str(known_lat),
        "location_lon": str(known_lon),
    }

    anomalies1 = detect_anomalies(test_data, prev_login=prev_test)
    print(f"\n[*] Test 1 result: {len(anomalies1)} anomalies\n")

    # ── TEST 2: Normal login (expect 0 alerts) ──
    print("--- TEST 2: Normal Login (expect 0 alerts) ---")

    normal_data = {
        "timestamp":               datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date":                    datetime.now().strftime("%Y-%m-%d"),
        "login_hour":              str(typical_hours[0]),
        "status":                  "success",
        "user":                    "pc",
        "ip_address":              known_ips[0],
        "location":                known_loc_str,
        "location_lat":            str(known_lat),
        "location_lon":            str(known_lon),
        "hostname":                known_hosts[0] if known_hosts else "",
        "os_version":              known_os_list[0] if known_os_list else "",
        "mac_address":             known_macs[0] if known_macs else "unknown",
        "screen_resolution":       known_res_list[0] if known_res_list else "",
        "typing_speed_category":   "normal",
        "typing_speed_seconds":    "3.0",
        "rapid_retries_10sec":     "0",
        "login_source_type":       "interactive",
        "failed_to_success_ratio": "0",
        "session_gap_minutes":     "120",
    }

    anomalies2 = detect_anomalies(normal_data, prev_login=None)

    print(f"\n{'='*55}")
    print(f"  RESULTS")
    print(f"{'='*55}")
    print(f"  Test 1 (suspicious) : {len(anomalies1)} anomalies")
    print(f"  Test 2 (normal)     : {len(anomalies2)} anomalies")

    if len(anomalies1) >= 5 and len(anomalies2) == 0:
        print(f"\n  [+] ALL WORKING CORRECTLY")
        print(f"      Detects attacks ✓")
        print(f"      Ignores normal logins ✓")
    elif len(anomalies1) >= 5 and len(anomalies2) > 0:
        print(f"\n  [~] Detection works but FALSE POSITIVES exist")
        print(f"      Baseline needs more data ({baseline.get('data_points')} points)")
        print(f"      Keep running collector for more days")
    else:
        print(f"\n  [!] Baseline too small to detect properly")
        print(f"      Run: python baseline_engine.py")
        print(f"      Make sure login_logs.csv is imported first")