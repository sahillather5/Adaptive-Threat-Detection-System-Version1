import os
import csv
import time
import threading
from datetime import datetime, timedelta
from baseline_engine import build_baseline, BEHAVIORAL_FILE, BEHAVIORAL_DIR

# =========================
# CONFIGURATION
# =========================

ROLLING_DAYS = 45
CLEANUP_HOUR = 2     # run cleanup at 2am daily

# =========================
# DELETE OLD DATA
# =========================

def delete_old_data():
    if not os.path.exists(BEHAVIORAL_FILE):
        print("[*] No behavioral data to clean.")
        return 0

    cutoff  = datetime.now() - timedelta(days=ROLLING_DAYS)
    kept    = []
    deleted = 0

    try:
        with open(BEHAVIORAL_FILE, "r",
                  encoding="utf-8") as f:
            reader  = csv.DictReader(f)
            headers = reader.fieldnames

            for row in reader:
                try:
                    ts = datetime.strptime(
                        row["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff:
                        kept.append(row)
                    else:
                        deleted += 1
                except:
                    kept.append(row)  # keep if unparseable

        with open(BEHAVIORAL_FILE, "w", newline="",
                  encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(kept)

        print(f"[+] Cleanup: {deleted} old records deleted, "
              f"{len(kept)} records kept.")
        return deleted

    except Exception as e:
        print(f"[-] Cleanup error: {e}")
        return 0

# =========================
# DAILY MAINTENANCE
# 1. Delete old data
# 2. Rebuild baseline with fresh data
# =========================

def daily_maintenance():
    print(f"\n[*] Daily maintenance at "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    deleted  = delete_old_data()
    baseline = build_baseline()

    if baseline:
        print(f"[+] Maintenance complete.")
        print(f"    Deleted  : {deleted} old records")
        print(f"    Baseline : {baseline['data_points']} "
              f"records analyzed")
    else:
        print("[-] Maintenance failed — not enough data.")

# =========================
# BACKGROUND SCHEDULER
# Waits until 2am then runs maintenance
# Repeats every 24 hours
# =========================

def schedule_daily_maintenance():
    print(f"[*] Daily maintenance scheduler running. "
          f"Next run at {CLEANUP_HOUR:02d}:00")

    while True:
        try:
            now      = datetime.now()
            next_run = now.replace(
                hour=CLEANUP_HOUR, minute=0,
                second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)

            wait_secs = (next_run - now).total_seconds()
            print(f"[*] Next maintenance in "
                  f"{int(wait_secs/3600)}h "
                  f"{int((wait_secs%3600)/60)}m")

            time.sleep(wait_secs)
            daily_maintenance()

        except Exception as e:
            print(f"[-] Scheduler error: {e}")
            time.sleep(3600)

# =========================
# START BACKGROUND SCHEDULER
# Called from collector_windows.py at startup
# =========================

def start_data_manager():
    t = threading.Thread(
        target=schedule_daily_maintenance,
        daemon=True
    )
    t.start()
    print("[*] Data manager started in background.")

# =========================
# DATA STATISTICS
# =========================

def get_data_stats():
    stats = {
        "total_records": 0,
        "oldest_record": None,
        "newest_record": None,
        "days_of_data":  0,
        "file_size_kb":  0,
    }

    if not os.path.exists(BEHAVIORAL_FILE):
        return stats

    try:
        timestamps = []
        with open(BEHAVIORAL_FILE, "r",
                  encoding="utf-8") as f:
            for row in csv.DictReader(f):
                stats["total_records"] += 1
                try:
                    timestamps.append(
                        datetime.strptime(
                            row["timestamp"],
                            "%Y-%m-%d %H:%M:%S"))
                except:
                    pass

        if timestamps:
            stats["oldest_record"] = min(
                timestamps).strftime("%Y-%m-%d")
            stats["newest_record"] = max(
                timestamps).strftime("%Y-%m-%d")
            stats["days_of_data"]  = (
                max(timestamps) - min(timestamps)).days

        stats["file_size_kb"] = round(
            os.path.getsize(BEHAVIORAL_FILE) / 1024, 1)

    except Exception as e:
        print(f"[-] Stats error: {e}")

    return stats

# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    print("="*50)
    print("  Data Manager")
    print("="*50 + "\n")

    stats = get_data_stats()
    print(f"[*] Current data statistics:")
    print(f"    Total records : {stats['total_records']}")
    print(f"    Oldest record : {stats['oldest_record']}")
    print(f"    Newest record : {stats['newest_record']}")
    print(f"    Days of data  : {stats['days_of_data']}")
    print(f"    File size     : {stats['file_size_kb']} KB")

    print(f"\n[*] Running manual maintenance now...")
    daily_maintenance()