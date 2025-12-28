# SENTINEL-AI Dashboard Quick Reference

## 🚀 Quick Start

### Start the Server
```bash
cd /home/kali/Documents/SENTINELAI-main/server
python run_server.py
```

### Access Dashboard
Open browser: `http://localhost:8000`

---

## ✨ New Features

### 1. Report Generation (20/day limit)
- **How it works**: Automatically generates AI-powered reports for each scan
- **Daily limit**: 20 reports with full AI analysis
- **After limit**: Basic analysis reports (still functional)
- **Reset**: Automatic at midnight

### 2. Real-time Dashboard Stats
- **Critical Threats**: Red counter (malicious/critical scans)
- **Medium Threats**: Yellow counter (suspicious/high/medium scans)
- **Low Threats**: Green counter (safe/clean/low scans)
- **Files Scanned**: Total scan count
- **Updates**: Automatically after each scan

### 3. Notification Panel
- **Access**: Click 🔔 bell icon (top-right)
- **Shows**: Last 10 scans with details
- **Click scan**: Opens report (if available)
- **Badge**: Shows unread count
- **Clear**: Button to remove all history

### 4. Time Range Filters
- **24h**: Last 24 hours
- **7 days**: Last week
- **30 days**: Last month
- **Custom**: Custom date range
- **Effect**: Filters dashboard stats

---

## 🎯 Common Tasks

### Scan an IP Address
1. Click "IP Scanner" tab
2. Enter IP address (e.g., 8.8.8.8)
3. Click "Scan IP"
4. View results below
5. Stats update automatically

### Scan a URL
1. Click "URL Scanner" tab
2. Enter URL (e.g., https://example.com)
3. Click "Scan URL"
4. View results below
5. Stats update automatically

### Scan a File
1. Click "File Scanner" tab
2. Click upload area or drag & drop file
3. Click "Scan File"
4. View results below
5. Stats update automatically

### View Recent Scans
1. Click notification bell (🔔)
2. Browse recent scans
3. Click any scan to open report
4. Click "Clear All" to remove history

### Filter by Time
1. Scroll to Reports section
2. Click desired time range button
3. Dashboard stats update instantly
4. Selection saved for next visit

---

## 🎨 UI Elements

### Status Indicators
- 🔴 **Malicious/Critical**: Immediate action required
- 🟡 **Suspicious/Medium**: Review recommended
- 🟢 **Safe/Clean**: No threats detected

### Toast Notifications
- Appear bottom-right corner
- Auto-dismiss after 3 seconds
- Types: Info (blue), Success (green), Warning (yellow), Error (red)

### Loading States
- Spinner appears during operations
- Shows current operation message
- Automatically dismisses when complete

---

## 💾 Data Storage

### What's Stored (localStorage)
- Last 100 scans (type, target, threat level, timestamp, report URL)
- Selected time range preference
- No sensitive data or file contents

### Clear Storage
```javascript
// Open browser console (F12)
localStorage.clear()
location.reload()
```

---

## 🐛 Troubleshooting

### Stats Not Updating
- Hard refresh: Ctrl+Shift+R (Cmd+Shift+R on Mac)
- Check console for errors (F12)
- Clear localStorage and reload

### Reports Saying "Limit Reached"
- Daily limit of 20 AI reports reached
- Reports still generated with basic analysis
- Resets automatically at midnight
- Check server console for exact count

### Notification Badge Not Showing
- Perform at least one scan
- Badge appears automatically with count
- Click bell to view details

### Time Filter Not Working
- Check if scans exist in selected range
- Try different time ranges
- Check browser console for errors

### Loading Stuck
- Hard refresh browser (Ctrl+Shift+R)
- Check if backend server is running
- Check server logs for errors

---

## 🔧 Configuration

### Adjust Report Limit
Edit `server/app/core/report_generator.py`:
```python
# Line ~172
if len(self._daily_reports) >= 20:  # Change 20 to desired limit
```

### Adjust Token Limit
Edit `server/app/core/report_generator.py`:
```python
# Line ~177
max_output_tokens=150  # Increase for longer reports (uses more quota)
```

### Adjust Scan History Size
Edit `server/app/static/js/dashboard.js`:
```javascript
// Line ~467
if (scans.length > 100) scans.pop();  // Change 100 to desired limit
```

---

## 📊 API Endpoints

### Health Check
```bash
curl http://localhost:8000/health
```

### Scan IP
```bash
curl -X POST http://localhost:8000/api/v1/scan/ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

### Scan URL
```bash
curl -X POST http://localhost:8000/api/v1/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Get Dashboard Summary
```bash
curl http://localhost:8000/api/v1/dashboard/summary
```

---

## 🎓 Tips & Tricks

### Keyboard Shortcuts (future enhancement idea)
- Press `N` to open notifications
- Press `Esc` to close panels
- Press `/` to focus search

### Best Practices
1. Regularly check notification panel for scan history
2. Use time filters to focus on recent threats
3. Monitor daily report count (visible in server logs)
4. Clear old scans periodically for performance
5. Download important reports immediately

### Performance Tips
- Keep scan history under 100 items
- Use time filters to reduce data display
- Clear localStorage if dashboard feels slow
- Restart server daily to reset report counter

---

## 📱 Browser Support

### Fully Supported
- Chrome/Chromium 90+
- Firefox 88+
- Edge 90+
- Safari 14+

### Features Used
- LocalStorage API (for scan persistence)
- Fetch API (for backend communication)
- ES6+ JavaScript (arrow functions, async/await)
- CSS Animations (for smooth transitions)

---

## 🔐 Security Notes

### Data Privacy
- Scans stored locally in browser only
- No data sent to third parties
- Clear localStorage to remove all history
- Reports stored on server (can be deleted)

### API Keys
- Gemini API key required for AI reports
- Set in server environment: `GEMINI_API_KEY`
- Keep API key secret (never commit to git)
- Use separate keys for dev/prod

---

## 📈 Monitoring

### Server Logs
```bash
# Watch server logs
tail -f server.log

# Check report generation count
grep "Daily Gemini report limit" server.log

# View API requests
grep "POST /api/v1/scan" server.log
```

### Browser Console
```javascript
// View stored scans
JSON.parse(localStorage.getItem('recentScans'))

// View scan count
JSON.parse(localStorage.getItem('recentScans')).length

// View selected time range
localStorage.getItem('selectedTimeRange')
```

---

## 🎉 Success Metrics

### Fully Functional ✅
- [x] Real-time dashboard statistics
- [x] 20 AI reports per day
- [x] Persistent scan history
- [x] Interactive notifications
- [x] Time range filtering
- [x] Toast notifications
- [x] Smooth animations
- [x] Professional UI/UX
- [x] Error handling
- [x] Loading states

---

## 📞 Support

### Get Help
1. Check [FIXES_APPLIED.md](FIXES_APPLIED.md) for detailed changes
2. Review server logs for errors
3. Check browser console (F12) for client errors
4. Clear localStorage and try again
5. Restart server and browser

### Report Issues
Include:
- Browser version
- Server logs
- Browser console errors
- Steps to reproduce
- Expected vs actual behavior

---

**Last Updated**: 2024
**Version**: 1.0.0
**Status**: ✅ Production Ready
