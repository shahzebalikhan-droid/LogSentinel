
import streamlit as st
import pandas as pd

from datetime import datetime, timedelta
from log_detector import detect_anomalies


# Page setup
st.set_page_config(
    page_title="LogSentinel",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ LogSentinel")
st.caption("Automated Log Parser & Anomaly Detection Dashboard")

st.info(
    "Demo mode: All events are simulated. "
    "No real authentication data is collected."
)


# Store demo events during the current session
if "events" not in st.session_state:
    st.session_state.events = []

if "next_id" not in st.session_state:
    st.session_state.next_id = 1


def add_event(ip, username, event_type, timestamp=None):
    """Add one simulated security event."""
    if timestamp is None:
        timestamp = datetime.now()

    event = {
        "id": st.session_state.next_id,
        "timestamp": timestamp,
        "ip": ip,
        "username": username,
        "event": event_type
    }

    st.session_state.events.append(event)
    st.session_state.next_id += 1


# Sidebar controls
st.sidebar.header("Simulation Controls")

if st.sidebar.button("Generate normal activity", use_container_width=True):
    now = datetime.now()

    add_event(
        "192.168.1.10", "alex", "LOGIN_SUCCESS", now
    )
    add_event(
        "192.168.1.10", "alex", "LOGOUT",
        now + timedelta(seconds=30)
    )

    st.rerun()


if st.sidebar.button("Simulate brute-force attack", use_container_width=True):
    now = datetime.now()

    # Six failed logins from the same IP within five minutes
    for minute in range(5):
        add_event(
            "203.0.113.50",
            "admin",
            "LOGIN_FAILED",
            now - timedelta(minutes=4 - minute)
        )

    add_event(
        "203.0.113.50",
        "admin",
        "LOGIN_FAILED",
        now
    )

    st.rerun()


if st.sidebar.button("Simulate unusual-hours login", use_container_width=True):
    now = datetime.now()

    unusual_time = now.replace(
        hour=2,
        minute=30,
        second=0,
        microsecond=0
    )

    add_event(
        "198.51.100.25",
        "shah",
        "LOGIN_SUCCESS",
        unusual_time
    )

    st.rerun()


if st.sidebar.button("Clear demo events", use_container_width=True):
    st.session_state.events = []
    st.rerun()


# Run the existing detection engine
events = st.session_state.events
alerts = detect_anomalies(events)


# Summary cards
total_events = len(events)
failed_logins = sum(
    event["event"] == "LOGIN_FAILED" for event in events
)
high_alerts = sum(
    alert["severity"] == "HIGH" for alert in alerts
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Failed Logins", failed_logins)
col3.metric("Security Alerts", len(alerts))
col4.metric("High-Severity Alerts", high_alerts)


# Events table
st.subheader("Security Events")

if events:
    event_rows = []

    for event in events:
        row = event.copy()
        row["timestamp"] = row["timestamp"].strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        event_rows.append(row)

    st.dataframe(
        pd.DataFrame(event_rows).drop(columns=["id"]),
        use_container_width=True,
        hide_index=True
    )
else:
    st.write("No events yet. Generate a scenario using the sidebar.")


# Alerts section
st.subheader("🚨 Detected Anomalies")

if alerts:
    for alert in alerts:
        with st.container(border=True):
            st.write(
                f"**{alert['severity']} — {alert['type']}**"
            )
            st.write(alert["message"])
            st.caption(
                f"Detection timestamp: {alert['timestamp']}"
            )
else:
    st.success("No anomalies detected.")


# Download the alert report
if alerts:
    st.download_button(
        "Download alerts as JSON",
        data=pd.Series(alerts).to_json(indent=4),
        file_name="logsentinel_alerts.json",
        mime="application/json"
    )
