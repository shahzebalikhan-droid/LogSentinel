
# LogSentinel

An automated Python log parser and anomaly detector.

## Features:

- Parses structured authentication logs
- Detects repeated failed login attempts
- Flags successful logins during configured unusual hours
- Generates JSON security reports
- Includes automated unit tests

## Requirements:

- Python 3.10 or later

## Run the project

Run the detector:

    python log_detector.py

Run the tests:

    python -m unittest -v

## Sample data

The project includes synthetic log data for safe testing.

## Limitations

This is an educational prototype. Alerts indicate potentially
suspicious activity and do not prove an attack occurred.
