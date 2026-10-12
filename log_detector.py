
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import json
import sys


# Convert one raw log line into a structured event.
def parse_log_line(line):
    parts = line.strip().split("|")

    if len(parts) != 4:
        return None

    timestamp_text, ip, username, event_type = parts

    try:
        timestamp = datetime.fromisoformat(timestamp_text)
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": ip,
        "username": username,
        "event": event_type
    }


# Find suspicious activity in the parsed events.
def detect_anomalies(events):
    alerts = []
    failed_by_ip = defaultdict(list)

    # Group failed login events by IP address.
    for event in events:
        if event["event"] == "LOGIN_FAILED":
            failed_by_ip[event["ip"]].append(event)

    # Rule 1: Five failed logins in any five-minute window.
    threshold = 5
    window = timedelta(minutes=5)

    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda item: item["timestamp"])

        for start in range(len(failures)):
            first_time = failures[start]["timestamp"]
            end = start

            while (
                end < len(failures)
                and failures[end]["timestamp"] - first_time <= window
            ):
                end += 1

            count = end - start

            if count >= threshold:
                alerts.append({
                    "type": "BRUTE_FORCE_SUSPECTED",
                    "severity": "HIGH",
                    "ip": ip,
                    "count": count,
                    "timestamp": first_time.isoformat(),
                    "message": (
                        f"{count} failed logins from {ip} "
                        "within five minutes"
                    )
                })

                # One alert per IP for this rule.
                break

    # Rule 2: Successful logins between midnight and 4:59 a.m.
    for event in events:
        hour = event["timestamp"].hour

        if event["event"] == "LOGIN_SUCCESS" and 0 <= hour < 5:
            alerts.append({
                "type": "UNUSUAL_LOGIN_HOUR",
                "severity": "MEDIUM",
                "ip": event["ip"],
                "username": event["username"],
                "timestamp": event["timestamp"].isoformat(),
                "message": (
                    f"Login for {event['username']} "
                    f"at {event['timestamp'].strftime('%H:%M')}"
                )
            })

    return alerts


# Read the file, run detection, and generate a report.
def main():
    if len(sys.argv) > 1:
        log_path = Path(sys.argv[1])
    else:
        log_path = Path(__file__).parent / "sample_logs.txt"

    if not log_path.is_file():
        print(f"Error: Log file not found: {log_path}")
        sys.exit(1)

    events = []
    malformed_lines = 0

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            event = parse_log_line(line)

            if event is None:
                malformed_lines += 1
            else:
                events.append(event)

    alerts = detect_anomalies(events)

    print("\n=== LOGSENTINEL REPORT ===")
    print(f"Input file: {log_path.name}")
    print(f"Valid events: {len(events)}")
    print(f"Malformed lines: {malformed_lines}")
    print(f"Alerts generated: {len(alerts)}")

    if alerts:
        print("\n=== SECURITY ALERTS ===")

        for alert in alerts:
            print(
                f"[{alert['severity']}] "
                f"{alert['type']}: {alert['message']}"
            )
    else:
        print("\nNo alerts detected.")

    report_path = Path(__file__).parent / "alerts.json"

    report_path.write_text(
        json.dumps(alerts, indent=4),
        encoding="utf-8"
    )

    print(f"\nJSON report saved to: {report_path}")


if __name__ == "__main__":
    main()
