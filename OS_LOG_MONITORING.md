# OS Log Monitoring Enhancements 🖥️

To satisfy the requirement that the system "catch[s] OS logs" alongside IDS/IPS and browser monitoring, the activity logger now includes an **operating system log watcher**.

## What Changed

- **ActivityLogger** accepts an optional `os_log_file` parameter and will autodetect a suitable log path (e.g. `/var/log/syslog`, `/var/log/messages`, `/var/log/system.log`).
- The SQLite schema includes a new `os_logs` table storing each line read from the system log.
- A new `_monitor_os_logs()` helper reads appended lines from the log file on each loop iteration (every 10 seconds) and:
  - writes the entry to the database
  - emits a callback event of type `os_log`
  - logs the line at `DEBUG` level for debugging purposes
- A simple test script `test_os_log_monitoring.py` verifies the feature using a temporary file.
- The server launcher now configures persistent logging to `logs/protection.log` (rotating) so that both IDS/IPS output and any OS log read events are saved to disk.

## Usage Notes

- When running with sufficient privileges the system log watcher can follow real files in `/var/log`.
- On systems where `journalctl` is preferred a future extension could spawn `journalctl -f` and pipe its output into the same callback mechanism.
- The `os_logs` table and callback allow downstream components (e.g. threat rules) to inspect OS-level events alongside browser and network activity.

## Testing

Run the quick test: `python3 test_os_log_monitoring.py`.

This enhancement makes the protection system more "proper" by auditing not only user-driven activity but also core OS messages, closing gaps that could hide persistence or intrusion indicators.
