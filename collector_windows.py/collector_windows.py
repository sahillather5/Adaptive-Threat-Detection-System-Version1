import os
import csv
import json
import time
import threading
import subprocess
import winsound
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from plyer import notification
import win32evtlog

from behavioral_collector import collect_behavioral_data, save_behavioral_data
from anomaly_detector      import detect_anomalies
from data_manager          import start_data_manager
from baseline_engine       import build_baseline, load_baseline

# =========================
# CONFIGURATION
# =========================

CONFIG_FILE         = "alert_config.json"
OUTPUT_FILE         = "login_logs.csv"
SENDER_EMAIL        = ""          # <-- your Gmail
SENDER_APP_PASSWORD = ""          # <-- your App Password
SMTP_SERVER         = "smtp.gmail.com"
SMTP_PORT           = 465
LOG_TYPE            = "Security"
SUCCESS_ID          = 4624
FAILURE_ID          = 4625
LOCK_ID             = 4800
UNLOCK_ID           = 4801
THRESHOLD           = 3           # failures before System 1 alert
CATCHUP_SECONDS     = 60

# =========================
# GLOBAL STATE
# =========================

failed_attempts    = 0
alert_sent         = False
screen_locked      = False
queued_popup       = None
seen_records       = set()
screen_last_record = 0
prev_login_data    = None          # for System 2 geo-velocity check
_login_count       = 0
REBUILD_EVERY      = 50            # rebuild baseline every N logins

# =========================
# SCREEN LOCK MONITOR
# Runs in background thread
# Detects lock (4800) and unlock (4801)
# =========================

def monitor_screen():
    global screen_locked, queued_popup, failed_attempts
    global alert_sent, screen_last_record

    print("[*] Screen monitor running.")
    try:
        h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        batch = win32evtlog.ReadEventLog(h, flags, 0)
        win32evtlog.CloseEventLog(h)
        if batch:
            screen_last_record = max(e.RecordNumber for e in batch)
    except:
        pass

    while True:
        try:
            h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            batch = win32evtlog.ReadEventLog(h, flags, 0)
            win32evtlog.CloseEventLog(h)

            if batch:
                new = [e for e in batch
                       if e.RecordNumber > screen_last_record]
                if new:
                    screen_last_record = max(
                        e.RecordNumber for e in new)
                    for e in new:
                        eid = e.EventID & 0xFFFF
                        if eid == LOCK_ID and not screen_locked:
                            screen_locked = True
                            print("[*] Screen locked.")
                        elif eid == UNLOCK_ID and screen_locked:
                            screen_locked = False
                            print("[*] Screen unlocked.")
                            failed_attempts = 0
                            alert_sent      = False
                            if queued_popup:
                                q = queued_popup
                                show_popup(q["user"],
                                           q["count"],
                                           q["ts"])
                                queued_popup = None
        except:
            pass
        time.sleep(2)

# =========================
# EMAIL
# =========================

def get_alert_email():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)["email"]
        except:
            pass
    email = input("Enter email for security alerts: ").strip()
    with open(CONFIG_FILE, "w") as f:
        json.dump({"email": email}, f)
    return email

def send_email_alert(subject, message):
    def _send():
        try:
            receiver = get_alert_email()
            if not receiver or not SENDER_EMAIL:
                print("[!] Email not configured — skipping.")
                return
            msg            = MIMEText(message)
            msg["Subject"] = subject
            msg["From"]    = SENDER_EMAIL
            msg["To"]      = receiver
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
                s.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
                s.send_message(msg)
            print("[+] System 1 email sent.")
        except Exception as e:
            print(f"[-] Email error: {e}")
    threading.Thread(target=_send, daemon=True).start()

# =========================
# BEEP ALARM
# 3 beeps on threshold breach
# =========================

def beep_alarm():
    def _beep():
        try:
            for _ in range(3):
                winsound.Beep(1000, 500)
                time.sleep(0.2)
            print("[+] Beep done.")
        except Exception as e:
            print(f"[-] Beep error: {e}")
    t = threading.Thread(target=_beep, daemon=False)
    t.start()
    t.join(timeout=5)

# =========================
# POPUP NOTIFICATION
# =========================

def show_popup(user, count, ts):
    try:
        subprocess.Popen(
            ["msg", "*",
             f"SECURITY ALERT! Wrong password {count} times! "
             f"User: {user} Time: {ts} "
             f"Change your password if this was not you!"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[+] Popup shown.")
    except Exception as e:
        print(f"[-] Popup error: {e}")

# =========================
# SYSTEM 2 — BACKGROUND
# Behavioral collection + anomaly detection
# Runs in its own thread per event
# Does NOT block System 1 alerts
# =========================

def run_system2(event):
    """
    Runs System 2 pipeline in background for each login event.
    1. Collects rich behavioral data (22+ fields)
    2. Saves to behavioral_data/behavioral_logs.csv
    3. Runs all 11 anomaly checks against baseline
    """
    global prev_login_data, _login_count

    try:
        # Collect all behavioral data from this event
        data = collect_behavioral_data(event)
        save_behavioral_data(data)

        # Run anomaly detection
        baseline = load_baseline()
        if baseline:
            anomalies = detect_anomalies(
                data, prev_login=prev_login_data)
            if anomalies:
                print(f"\n[SYSTEM-2] {len(anomalies)} "
                      f"behavioral anomaly(s) detected!")
            else:
                print(f"[SYSTEM-2] No anomalies — normal.")
        else:
            print("[SYSTEM-2] No baseline yet — "
                  "run baseline_engine.py first.")

        # Update previous login for next geo-velocity check
        prev_login_data = data

        # Periodically rebuild baseline
        _login_count += 1
        if _login_count % REBUILD_EVERY == 0:
            print(f"\n[SYSTEM-2] {_login_count} logins — "
                  f"rebuilding baseline...")
            build_baseline()

    except Exception as e:
        print(f"[-] System 2 error: {e}")

# =========================
# CATCHUP ON STARTUP
# Checks for missed events before script started
# =========================

def catchup_on_startup():
    print(f"[*] Checking last {CATCHUP_SECONDS}s "
          f"for missed events...")
    try:
        h     = win32evtlog.OpenEventLog("localhost", LOG_TYPE)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        batch = win32evtlog.ReadEventLog(h, flags, 0)
        win32evtlog.CloseEventLog(h)

        if not batch:
            print("[*] No events in catchup.")
            return

        catchup_failures = 0
        catchup_user     = "unknown"
        catchup_ip       = "local"
        catchup_ts       = ""
        cutoff = datetime.now() - timedelta(seconds=CATCHUP_SECONDS)

        for e in batch:
            seen_records.add(e.RecordNumber)
            eid = e.EventID & 0xFFFF
            if eid != FAILURE_ID:
                continue
            try:
                event_time = datetime.fromtimestamp(
                    int(e.TimeGenerated))
            except:
                continue
            if event_time < cutoff:
                continue

            catchup_failures += 1
            if e.StringInserts:
                if len(e.StringInserts) > 5:
                    catchup_user = str(
                        e.StringInserts[5]).strip()
                if len(e.StringInserts) > 18:
                    raw = str(e.StringInserts[18]).strip()
                    if raw not in ("-", "", "::1", "127.0.0.1"):
                        catchup_ip = raw
            catchup_ts = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S")

        if catchup_failures >= THRESHOLD:
            print(f"\n{'!'*40}")
            print(f"  CATCHUP ALERT — {catchup_failures} "
                  f"failures before script started!")
            print(f"{'!'*40}\n")
            send_email_alert(
                "UEBA Alert: Failures at Startup",
                f"UEBA ALERT: Failed Logins at Startup\n\n"
                f"Failures before monitoring started!\n\n"
                f"  User     : {catchup_user}\n"
                f"  IP       : {catchup_ip}\n"
                f"  Time     : {catchup_ts}\n"
                f"  Attempts : {catchup_failures}\n\n"
                f"Someone tried to access your device "
                f"before monitoring started!"
            )
        else:
            print(f"[*] Catchup clean — "
                  f"{catchup_failures} failures found.")
    except Exception as e:
        print(f"[-] Catchup error: {e}")

# =========================
# MAIN COLLECTION LOOP
# Watches Windows Security Event Log
# Triggers BOTH System 1 and System 2 per event
# =========================

def collect_logs():
    global failed_attempts, alert_sent, queued_popup

    # Create login_logs.csv if not exists
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", newline="",
                  encoding="utf-8") as f:
            csv.writer(f).writerow(
                ["user_hash", "timestamp",
                 "ip_address", "login_status"])

    catchup_on_startup()
    print("[*] Monitoring started. Ctrl+C to stop.\n")
    rows_written = 0

    while True:
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(
                "localhost", LOG_TYPE)
            flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                      win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            if events:
                # Find new events not yet processed
                new_events = [e for e in events
                              if e.RecordNumber
                              not in seen_records]

                # Process oldest first
                for event in reversed(new_events):
                    seen_records.add(event.RecordNumber)

                    eid = event.EventID & 0xFFFF
                    if eid not in (SUCCESS_ID, FAILURE_ID):
                        continue

                    # Extract user and IP
                    user_hash  = "unknown"
                    ip_address = "local"
                    logon_type = ""
                    if event.StringInserts:
                        if len(event.StringInserts) > 5:
                            user_hash = str(
                                event.StringInserts[5]).strip()
                        if len(event.StringInserts) > 8:
                            logon_type = str(
                                event.StringInserts[8]).strip()
                        if len(event.StringInserts) > 18:
                            raw = str(
                                event.StringInserts[18]).strip()
                            # FIX: reject paths as IPs
                            if (raw not in ("-", "",
                                            "::1", "127.0.0.1")
                                    and not raw.startswith(
                                        "C:\\")
                                    and not raw.startswith(
                                        "\\")):
                                ip_address = raw

                    # FIX: Skip Windows internal service
                    # logons — these are NOT real human logins
                    # Type 5 = Service, Type 0 = System
                    # SYSTEM account = Windows internal
                    skip_users = {"SYSTEM", "LOCAL SERVICE",
                                  "NETWORK SERVICE",
                                  "ANONYMOUS LOGON",
                                  "Window Manager",
                                  "DWM-1", "DWM-2"}
                    if user_hash in skip_users:
                        continue
                    if logon_type in ("5", "0"):
                        continue
                    # Skip if username looks like a
                    # Windows internal account
                    if (user_hash.startswith("DWM-") or
                            user_hash.startswith("UMFD-")):
                        continue

                    status    = ("success"
                                 if eid == SUCCESS_ID
                                 else "failure")
                    timestamp = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S")

                    # ── SYSTEM 1: Write to login_logs.csv ──
                    with open(OUTPUT_FILE, "a",
                              newline="",
                              encoding="utf-8") as f:
                        csv.writer(f).writerow(
                            [user_hash, timestamp,
                             ip_address, status])
                    rows_written += 1

                    # ── SYSTEM 1: Beep / Popup / Email ──
                    if status == "failure":
                        failed_attempts += 1
                        print(f"[!] Failure "
                              f"#{failed_attempts} "
                              f"— User: {user_hash}")

                        # Beep on every failure at/above threshold
                        if failed_attempts >= THRESHOLD:
                            beep_alarm()

                        # Alert once at threshold
                        if (failed_attempts == THRESHOLD
                                and not alert_sent):
                            print(f"\n{'!'*40}")
                            print(f"  ALERT — "
                                  f"{failed_attempts}"
                                  f" failed logins!")
                            print(f"{'!'*40}\n")

                            if screen_locked:
                                queued_popup = {
                                    "user":  str(user_hash),
                                    "count": failed_attempts,
                                    "ts":    timestamp
                                }
                                print("[*] Popup queued "
                                      "(screen locked).")
                            else:
                                show_popup(str(user_hash),
                                           failed_attempts,
                                           timestamp)

                            send_email_alert(
                                "UEBA Alert: Failed Login",
                                f"UEBA ALERT: Failed Login\n\n"
                                f"User     : {user_hash}\n"
                                f"Time     : {timestamp}\n"
                                f"IP       : {ip_address}\n"
                                f"Attempts : {failed_attempts}"
                            )
                            alert_sent = True

                    else:  # success
                        if failed_attempts > 0:
                            print(f"[+] Login OK after "
                                  f"{failed_attempts} "
                                  f"failures — reset.")
                        else:
                            print(f"[+] Login OK "
                                  f"— {user_hash}")
                        failed_attempts = 0
                        alert_sent      = False

                    # ── SYSTEM 2: Background behavioral ──
                    # Runs in separate thread — never blocks
                    # System 1 alerts above
                    threading.Thread(
                        target=run_system2,
                        args=(event,),
                        daemon=True
                    ).start()

        except KeyboardInterrupt:
            print(f"\n[*] Stopped. "
                  f"{rows_written} events saved.")
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(2)
        finally:
            if handle:
                try:
                    win32evtlog.CloseEventLog(handle)
                except:
                    pass

        time.sleep(1)

# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    print("="*45)
    print("  UEBA Security Monitor v2.0")
    print("  System 1 + System 2 Unified")
    print("="*45 + "\n")

    # Setup email
    print("[*] Checking alert email config...")
    get_alert_email()

    # Start System 2 background data manager (2am cleanup)
    start_data_manager()

    # Ensure baseline exists for System 2
    baseline = load_baseline()
    if not baseline:
        print("[*] No baseline found — attempting build...")
        build_baseline()
        if not load_baseline():
            print("[!] No baseline yet. Run baseline_engine.py")
            print("[!] System 2 detection will start after")
            print("[!] baseline is built. System 1 runs normally.")

    # Start screen lock monitor
    threading.Thread(
        target=monitor_screen, daemon=True).start()

    # Start main collection loop (blocks here)
    try:
        collect_logs()
    except PermissionError:
        print("\n[-] PERMISSION DENIED")
        print("    Windows Security Event Log needs Admin.")
        print("    Right-click CMD → 'Run as Administrator'")
        print("    Then: python collector_windows.py")