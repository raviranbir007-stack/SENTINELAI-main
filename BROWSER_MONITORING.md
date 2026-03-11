# Browser Monitoring Improvements 📡

During testing the activity monitor was sometimes silent even when browsing sites. This usually happened when the server was started with `sudo` (required for full IDS/IPS functionality). Under a `sudo` session `Path.home()` returns `/root`, so the monitor looked in the wrong user profile and never saw any history entries.

## What’s new

- The monitor now detects the real user’s home directory by checking `SUDO_USER` when running as root.
- All browser path templates (Firefox, Chrome, Brave, Edge, Opera, Vivaldi, etc.) use `self.user_home` instead of `Path.home()`.
- The active home directory is logged at startup: `ActivityMonitor will use home directory: /home/kali`.
- Network connection fallback runs on every cycle (not only when history yields nothing) so even private‑mode or ephemeral browsers are captured.
- Each detection is logged with `logger.info` as well as printed to the console, ensuring the information appears in `logs/protection.log` and server output.
- Sample visits and analysis are both printed and logged (see the demo in earlier tests).

## How to verify

1. Start the server normally (using `sudo python3 server/run_server.py`).
2. Open any website in your regular user browser (e.g. Chrome, Firefox).
3. Watch the server terminal or check `logs/protection.log` for lines like:
   ```
   INFO:ActivityMonitor:Website visit detected: https://example.com (domain: example.com) from Chrome
   ```
4. You can also run the provided demo:
   ```bash
   cd server && python3 - <<'PYCODE'
   import asyncio
   from app.activity_monitor import ActivityMonitor
   asyncio.run(ActivityMonitor()._process_website({
       'url':'https://www.google.com','title':'Google','browser':'Chrome','time':'now'
   }))
   PYCODE
   ```

## Notes

- The monitor still respects a one‑hour cache to avoid re‑scanning the same URL repeatedly.
- To force re‑analysis of a URL, delete it from `self.last_websites` in the running process or restart the server.
- If you prefer not to run the server as root, start it as your normal user; monitoring will still work but some IDS/IPS features will be limited.
