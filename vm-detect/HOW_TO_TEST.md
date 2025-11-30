# How to Test if the System is Running

## Quick Verification Steps

### 1. Test Basic Detection (Fastest)
```bash
python detector.py
```
**Expected Output:**
```
============================================================
VM & Remote Access Detection Report
============================================================

[OK] No VM detected (confidence: X.XX%)
[OK] No remote access detected (confidence: 0.00%)
[OK] No screen sharing detected (confidence: 0.00%)
============================================================
```

✅ **If you see this** → System is working!

---

### 2. Test Data Collection
```bash
python collector.py
```
**Expected Output:**
- JSON output with system data
- Should show processes, MAC addresses, BIOS info, etc.

✅ **If you see JSON data** → Data collection is working!

---

### 3. Test Main Runner
```bash
python main.py --once
```
**Expected Output:**
- Same as `detector.py` but with proper CLI formatting

✅ **If you see a report** → Main system is working!

---

### 4. Test Continuous Monitoring
```bash
python main.py --monitor --interval 5
```
**Expected Output:**
```
Starting continuous monitoring...
Scan interval: 5 seconds
Press Ctrl+C to stop

[2024-XX-XX XX:XX:XX] ✓ No threats detected
[2024-XX-XX XX:XX:XX] ✓ No threats detected
...
```

✅ **If you see continuous updates** → Monitoring is working!

**To stop:** Press `Ctrl+C`

---

### 5. Test Behavioral Analyzer
```bash
python behavioral_analyzer.py
```
**Expected Output:**
```
{
  "sufficient_data": true/false,
  "total_detections": X,
  ...
}
Statistics:
{...}
```

✅ **If you see JSON output** → Behavioral analysis is working!

---

### 6. Test Manual VM Check
```bash
python check_vm.py
```
**Expected Output:**
- Detailed breakdown of system checks
- Shows what's detected

✅ **If you see checks running** → Verification tool is working!

---

## What Each Test Tells You

| Command | What It Tests | Time |
|---------|---------------|------|
| `python detector.py` | Core detection engine | ~2 seconds |
| `python collector.py` | Data collection | ~1 second |
| `python main.py --once` | Full CLI interface | ~2 seconds |
| `python main.py --monitor` | Real-time monitoring | Continuous |
| `python behavioral_analyzer.py` | Pattern analysis | ~2 seconds |
| `python check_vm.py` | Manual verification | ~3 seconds |

---

## Troubleshooting

### ❌ Error: "ModuleNotFoundError: No module named 'psutil'"
**Fix:**
```bash
pip install psutil
```

### ❌ Error: "ModuleNotFoundError: No module named 'flask'"
**Fix (only needed for dashboard):**
```bash
pip install flask
```

### ❌ No output or hangs
**Check:**
1. Are you in the `vm-detect` directory?
2. Do you have Python 3.8+ installed?
3. Are dependencies installed? (`pip install -r requirements.txt`)

---

## Quick Health Check Script

Run this to test everything at once:

```bash
echo "Testing detection..." && python detector.py && echo "✅ Detector working"
echo "Testing collector..." && python collector.py > /dev/null 2>&1 && echo "✅ Collector working"
echo "Testing main..." && python main.py --once > /dev/null 2>&1 && echo "✅ Main working"
echo "All systems operational!"
```

---

## Real-World Testing

### Test VM Detection (if you have a VM):
1. Install VirtualBox or VMware
2. Run `python detector.py` inside the VM
3. Should detect VM indicators

### Test Remote Access Detection:
1. Install TeamViewer or AnyDesk
2. Run `python detector.py`
3. Should detect remote access process

### Test Screen Sharing Detection:
1. Open Zoom or OBS
2. Run `python detector.py`
3. Should detect screen sharing process

---

## Performance Check

If detection takes longer than 5 seconds:
- Normal: System has many processes
- Slow: Might indicate performance issues

Typical detection time: 1-3 seconds on most systems.

