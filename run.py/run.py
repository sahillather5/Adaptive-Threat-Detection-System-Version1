"""
run.py — Unified launcher for UEBA System

Usage:
    python run.py           → starts collector only
    python run.py --dash    → starts collector + dashboard
    python run.py --setup   → builds baseline from existing data

Must be run as Administrator for Windows Event Log access.
"""
import sys
import threading
import subprocess


def start_collector():
    """Starts the main collector (System 1 + System 2)."""
    print("[*] Starting collector_windows.py...")
    from collector_windows import (
        collect_logs, monitor_screen,
        get_alert_email
    )
    from data_manager  import start_data_manager
    from baseline_engine import load_baseline, build_baseline

    # Setup
    get_alert_email()
    start_data_manager()

    if not load_baseline():
        print("[*] No baseline — attempting to build...")
        build_baseline()

    threading.Thread(
        target=monitor_screen, daemon=True).start()
    collect_logs()  # blocks here


def start_dashboard():
    """Launches Streamlit dashboard in a subprocess."""
    print("[*] Starting Streamlit dashboard...")
    print("[*] Open http://localhost:8501 in your browser")
    subprocess.Popen(
        ["streamlit", "run", "main.py",
         "--server.headless", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def run_setup():
    """Bootstrap baseline from existing login_logs.csv."""
    print("="*50)
    print("  UEBA Setup — Building Initial Baseline")
    print("="*50 + "\n")
    from baseline_engine import (
        import_existing_logs, build_baseline,
        BEHAVIORAL_FILE
    )
    import os
    if not os.path.exists(BEHAVIORAL_FILE):
        print("[*] Importing from login_logs.csv...")
        count = import_existing_logs()
        if count == 0:
            print("[-] No data found.")
            print("    Run collector_windows.py first.")
            return
        print(f"[+] {count} records imported!")

    print("\n[*] Building baseline...")
    baseline = build_baseline()
    if baseline:
        print(f"\n[+] Setup complete!")
        print(f"    Baseline has {baseline['data_points']}"
              f" data points.")
        print(f"    You can now run: python run.py")
    else:
        print("[-] Setup failed — not enough data.")


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    args = sys.argv[1:]

    if "--setup" in args:
        run_setup()

    elif "--dash" in args:
        # Start dashboard in background, collector in foreground
        start_dashboard()
        try:
            start_collector()
        except KeyboardInterrupt:
            print("\n[*] UEBA stopped.")

    else:
        print("="*45)
        print("  UEBA Security Monitor v2.0")
        print("="*45)
        print("\nUsage:")
        print("  python run.py           — collector only")
        print("  python run.py --dash    — collector + dashboard")
        print("  python run.py --setup   — build baseline first")
        print("\nTip: Run as Administrator!\n")
        try:
            start_collector()
        except KeyboardInterrupt:
            print("\n[*] UEBA stopped.")
        except PermissionError:
            print("\n[-] PERMISSION DENIED")
            print("    Right-click CMD → "
                  "'Run as Administrator'")
            print("    Then: python run.py")