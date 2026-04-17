import os
import pandas as pd
import streamlit as st
from datetime import datetime
from config.scoring_engine import RiskScoringEngine
from services.alert_engine  import AlertEngine

try:
    from winotify import Notification
    WINOTIFY_AVAILABLE = True
except ImportError:
    WINOTIFY_AVAILABLE = False

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title = "UEBA Dashboard",
    page_icon  = "🛡️",
    layout     = "wide"
)

# =========================
# DATA LOADERS
# @st.cache_data — data refreshes every 30s
# =========================

@st.cache_data(ttl=30)
def load_login_logs():
    try:
        df = pd.read_csv("login_logs.csv")
        required = ['user_hash', 'timestamp',
                    'ip_address', 'login_status']
        if not all(c in df.columns for c in required):
            raise ValueError("CSV missing required columns")
        df['timestamp'] = pd.to_datetime(
            df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp', 'user_hash',
                                'ip_address', 'login_status'])
        return df.sort_values(by='timestamp')
    except Exception as e:
        st.error(f"Error loading login_logs.csv: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=30)
def load_system2_anomalies():
    path = os.path.join("behavioral_data", "anomaly_log.csv")
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        df['timestamp'] = pd.to_datetime(
            df['timestamp'], errors='coerce')
        return df.dropna(subset=['timestamp']).sort_values(
            by='timestamp', ascending=False)
    except:
        return pd.DataFrame()

@st.cache_data(ttl=30)
def load_behavioral_logs():
    path = os.path.join("behavioral_data",
                        "behavioral_logs.csv")
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        df['timestamp'] = pd.to_datetime(
            df['timestamp'], errors='coerce')
        return df.dropna(subset=['timestamp']).sort_values(
            by='timestamp', ascending=False)
    except:
        return pd.DataFrame()

# =========================
# BASELINE
# Not on every page refresh like before
# =========================

@st.cache_data(ttl=3600)
def build_baselines(df_hash: str, df: pd.DataFrame):
    """
    df_hash is used as a stable cache key.
    Prevents Streamlit from re-running on every refresh.
    """
    baselines = {}
    if df.empty:
        return baselines

    start_date   = df['timestamp'].min()
    baseline_end = start_date + pd.Timedelta(days=7)
    baseline_df  = df[df['timestamp'] <= baseline_end]

    for user in baseline_df['user_hash'].unique():
        user_logs = baseline_df[
            baseline_df['user_hash'] == user]
        if user_logs.empty:
            continue
        total_hours = (
            user_logs['timestamp'].max() -
            user_logs['timestamp'].min()
        ).total_seconds() / 3600

        baselines[user] = {
            "avg_attempts_per_hour": (
                len(user_logs) / max(total_hours, 1)),
            "typical_hours": set(
                user_logs['timestamp'].dt.hour),
            "known_ips": set(user_logs['ip_address']),
        }

    return baselines

def update_baseline(user, row, baseline, risk_score):
    if risk_score >= 40:
        return baseline
    baseline['typical_hours'].add(row['timestamp'].hour)
    baseline['known_ips'].add(row['ip_address'])
    baseline['avg_attempts_per_hour'] = (
        baseline['avg_attempts_per_hour'] * 0.9 + 1 * 0.1)
    return baseline

# =========================
# ANOMALY DETECTION
# System 1 scoring on login_logs.csv
# =========================

@st.cache_data(ttl=60)
def run_system1_detection(df_json: str):
    """
    df_json is a JSON string used as a stable cache key.
    """
    df           = pd.read_json(df_json)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    risk_engine  = RiskScoringEngine()
    alert_engine = AlertEngine()
    alerts       = []

    if df.empty:
        return alerts

    # Use first 7 days as baseline, rest as analysis
    start_date   = df['timestamp'].min()
    baseline_end = start_date + pd.Timedelta(days=7)
    analysis_df  = df[df['timestamp'] > baseline_end]

    # Build fresh baselines for detection
    baselines    = {}
    baseline_df  = df[df['timestamp'] <= baseline_end]
    for user in baseline_df['user_hash'].unique():
        user_logs = baseline_df[
            baseline_df['user_hash'] == user]
        if user_logs.empty:
            continue
        total_hours = (
            user_logs['timestamp'].max() -
            user_logs['timestamp'].min()
        ).total_seconds() / 3600
        baselines[user] = {
            "avg_attempts_per_hour": (
                len(user_logs) / max(total_hours, 1)),
            "typical_hours": set(
                user_logs['timestamp'].dt.hour),
            "known_ips": set(user_logs['ip_address']),
        }

    for user in analysis_df['user_hash'].unique():
        if user not in baselines:
            continue

        baseline  = baselines[user]
        user_logs = analysis_df[
            analysis_df['user_hash'] == user
        ].copy().sort_values(by='timestamp')

        user_logs['hour']         = user_logs[
            'timestamp'].dt.floor('h')
        hourly_counts             = user_logs.groupby(
            'hour').size()
        user_logs['failure_window'] = (
            user_logs['timestamp'] -
            user_logs['timestamp'].shift()
        ).dt.total_seconds() / 60

        failure_counts = []
        current_failures = 0
        for _, row in user_logs.iterrows():
            if row['login_status'] == "failure":
                current_failures += 1
            else:
                current_failures = 0
            if (pd.notna(row['failure_window'])
                    and row['failure_window'] > 10):
                current_failures = (
                    1 if row['login_status'] == "failure"
                    else 0)
            failure_counts.append(current_failures)
        user_logs['failure_count'] = failure_counts

        for _, row in user_logs.iterrows():
            features = {
                "time": 0, "geo": 0, "device": 0,
                "fail": 0, "frequency": 0,
                "session": 0, "sequence": 0
            }
            hour_attempts = hourly_counts.get(
                row['hour'], 0)
            if (hour_attempts >
                    2 * baseline['avg_attempts_per_hour']):
                features["frequency"] = 1
            if row['timestamp'].hour not in (
                    baseline['typical_hours']):
                features["time"] = 1
            if row['ip_address'] not in (
                    baseline['known_ips']):
                features["geo"] = 1
            if row['failure_count'] >= 3:
                features["fail"] = 1

            risk_score = risk_engine.calculate_risk(features)
            risk_level = risk_engine.risk_level(risk_score)
            confidence = risk_engine.confidence_score(
                features)

            risk_output = {
                "user_hash":     user,
                "timestamp":     row["timestamp"],
                "risk_score":    risk_score,
                "risk_level":    risk_level,
                "confidence":    confidence,
                "anomaly_vector": features,
            }

            alert = alert_engine.generate_alert(risk_output)
            if alert:
                alerts.append(alert)
                if WINOTIFY_AVAILABLE:
                    try:
                        toast = Notification(
                            app_id = "UEBA Security System",
                            title  = "UEBA Security Alert",
                            msg    = (f"User "
                                      f"{alert['user_hash']} "
                                      f"Risk "
                                      f"{alert['risk_score']}"
                                      f" ({alert['severity']})")
                        )
                        toast.show()
                    except:
                        pass

            baselines[user] = update_baseline(
                user, row, baselines[user], risk_score)

    return alerts

# =========================
# DASHBOARD MAIN
# =========================

def main():
    st.title("🛡️ UEBA Login Behavior Monitoring System")
    st.caption(
        f"Dashboard refreshes every 30 seconds. "
        f"Last loaded: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # Auto-refresh every 30 seconds
    st.markdown(
        '<meta http-equiv="refresh" content="30">',
        unsafe_allow_html=True
    )

    # ── Load all data ──
    df           = load_login_logs()
    s2_anomalies = load_system2_anomalies()
    behavioral   = load_behavioral_logs()

    if df.empty:
        st.error(
            "⚠️ login_logs.csv not found or invalid. "
            "Run collector_windows.py first.")
        return

    # ── Sidebar Filters ──
    st.sidebar.header("🔍 Filters")
    users         = sorted(df['user_hash'].unique())
    selected_user = st.sidebar.selectbox(
        "Select User", ["All"] + list(users))
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "**System Status**\n\n"
        f"📁 Login events: {len(df)}\n\n"
        f"🔴 S2 Anomalies: {len(s2_anomalies)}\n\n"
        f"📋 Behavioral records: {len(behavioral)}"
    )

    df_view = df.copy()
    if selected_user != "All":
        df_view = df_view[
            df_view['user_hash'] == selected_user]

    # ── Top Metrics Row ──
    c1, c2, c3, c4, c5 = st.columns(5)

    df_hash    = str(len(df)) + str(df['timestamp'].max())
    alerts     = run_system1_detection(df_view.to_json())
    alerts_df  = pd.DataFrame(alerts)

    s2_view    = s2_anomalies.copy()
    if selected_user != "All" and not s2_view.empty:
        if "user" in s2_view.columns:
            s2_view = s2_view[
                s2_view["user"] == selected_user]

    failures   = len(df_view[
        df_view['login_status'] == 'failure'])
    successes  = len(df_view[
        df_view['login_status'] == 'success'])
    crit_count = (0 if s2_view.empty else
                  len(s2_view[
                      s2_view.get("alert_level", "") ==
                      "CRITICAL"]) if "alert_level"
                  in s2_view.columns else 0)

    c1.metric("📋 Login Events",  len(df_view))
    c2.metric("✅ Successes",      successes)
    c3.metric("❌ Failures",       failures)
    c4.metric("🟠 S1 Alerts",      len(alerts_df))
    c5.metric("🔴 S2 Anomalies",   len(s2_view))

    st.markdown("---")

    # ── SYSTEM 2: Advanced Behavioral Anomalies ──
    st.header("🔴 System 2 — Behavioral Anomaly Alerts")
    st.caption(
        "Advanced detection: 11 checks including "
        "impossible travel, brute force, unknown device, "
        "account takeover and more."
    )

    if not s2_view.empty:
        def color_row(row):
            colors = {
                "CRITICAL": "background-color: #ff4444;"
                            " color: white",
                "HIGH":     "background-color: #ff8c00;"
                            " color: white",
                "MEDIUM":   "background-color: #ffd700",
                "LOW":      "background-color: #e0e0e0",
            }
            level = row.get("alert_level", "")
            style = colors.get(level, "")
            return [style] * len(row)

        styled = s2_view.style.apply(color_row, axis=1)
        st.dataframe(styled, use_container_width=True,
                     height=300)
    else:
        st.info(
            "ℹ️ No System 2 anomalies detected yet.\n\n"
            "Make sure collector_windows.py is running "
            "in the background.")

    st.markdown("---")

    # ── SYSTEM 1: Risk Scored Alerts ──
    st.header("🟠 System 1 — Risk Scored Alerts")
    st.caption(
        "Behavioral scoring on login_logs.csv using "
        "weighted risk engine.")

    if not alerts_df.empty:
        alerts_df.to_csv("alerts_output.csv", index=False)
        st.dataframe(alerts_df, use_container_width=True,
                     height=250)
    else:
        st.write("No System 1 alerts for selected filter.")

    st.markdown("---")

    # ── Charts Row ──
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📈 Login Attempts Over Time")
        attempts = df_view.groupby(
            df_view['timestamp'].dt.date).size()
        st.line_chart(attempts)

    with col2:
        st.subheader("✅ Login Status Breakdown")
        status_counts = df_view[
            'login_status'].value_counts()
        st.bar_chart(status_counts)

    # ── Risk Score Summary ──
    if not alerts_df.empty:
        st.subheader("⚠️ Risk Score by User")
        risk_summary = alerts_df.groupby(
            "user_hash")["risk_score"].max()
        st.bar_chart(risk_summary)

    st.markdown("---")

    # ── System 2 Anomaly Breakdown ──
    if not s2_view.empty and "alert_level" in s2_view.columns:
        st.subheader("📊 System 2 Anomaly Breakdown")
        col3, col4 = st.columns(2)
        with col3:
            level_counts = s2_view[
                "alert_level"].value_counts()
            st.bar_chart(level_counts)
        with col4:
            if "anomaly_type" in s2_view.columns:
                type_counts = s2_view[
                    "anomaly_type"].value_counts()
                st.bar_chart(type_counts)

    # ── Recent Behavioral Data ──
    if not behavioral.empty:
        with st.expander(
                "📋 Recent Behavioral Data (System 2)"):
            st.dataframe(
                behavioral.head(50),
                use_container_width=True)

    # ── Raw Login Logs ──
    with st.expander("📁 Raw Login Logs (last 100)"):
        st.dataframe(
            df_view.tail(100),
            use_container_width=True)

if __name__ == "__main__":
    main()