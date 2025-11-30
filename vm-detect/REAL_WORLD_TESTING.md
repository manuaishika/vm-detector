# Real-World Testing Guide

How to verify the system works beyond your current machine.

## 🎯 Testing Scenarios

### Test 1: VM Detection ✅

**Goal:** Verify it detects when running inside a Virtual Machine

#### Option A: Test on VirtualBox VM
1. **Install VirtualBox** (if not installed)
   - Download: https://www.virtualbox.org/
   - Install normally

2. **Create a VM**
   - Create new VM (Windows or Linux)
   - Install OS
   - Install VirtualBox Guest Additions (important!)

3. **Install detection system in VM**
   ```bash
   # In the VM, copy your vm-detect folder or clone repo
   cd vm-detect
   pip install psutil
   ```

4. **Run detection**
   ```bash
   python detector.py
   ```

5. **Expected Results:**
   ```
   [ALERT] Virtual Machine Detected!
   Confidence: XX.XX%
   Evidence:
     - MAC: 08:00:27:xx:xx:xx matches VM vendor 08:00:27
     - Process: VBoxService.exe is running
     - BIOS: VirtualBox found in manufacturer/product
   ```

#### Option B: Test on VMware VM
Same process but with VMware instead of VirtualBox.

**What to look for:**
- MAC address starting with `00:05:69`, `00:0c:29`, `00:50:56`
- Processes: `vmtoolsd.exe`, `vmwaretray.exe`
- BIOS strings containing "VMware"

---

### Test 2: Remote Access Detection ✅

**Goal:** Verify it detects remote access tools when they're active

#### Test with TeamViewer
1. **Install TeamViewer**
   - Download: https://www.teamviewer.com/
   - Install (don't need to connect, just have it installed)

2. **Start TeamViewer**
   - Launch TeamViewer application
   - Keep it running (even if not connected)

3. **Run detection**
   ```bash
   python detector.py
   ```

4. **Expected Results:**
   ```
   [ALERT] Remote Access Detected!
   Confidence: XX.XX%
   Evidence:
     - Process: TeamViewer.exe is running
   ```

#### Test with AnyDesk
1. Install AnyDesk
2. Start AnyDesk
3. Run detection - should detect `anydesk.exe`

#### Test with RDP (Remote Desktop)
**On Windows:**
1. Enable Remote Desktop:
   - Settings → System → Remote Desktop → Enable
2. Connect from another machine (optional, just having it enabled is enough)
3. Run detection:
   ```bash
   python detector.py
   ```
4. Should detect:
   - Port 3389 listening
   - Session name changes to "RDP-Tcp#X"
   - `mstsc.exe` process if actively connected

#### Test with VNC
1. Install TightVNC or UltraVNC
2. Start VNC server
3. Run detection - should detect:
   - VNC processes
   - Port 5900 or 5901 listening

---

### Test 3: Screen Sharing Detection ✅

**Goal:** Verify it detects screen sharing applications

#### Test with Zoom
1. **Install Zoom**
   - Download: https://zoom.us/download
   - Install Zoom client

2. **Start Zoom**
   - Launch Zoom application
   - Join a meeting or just have it open

3. **Run detection**
   ```bash
   python detector.py
   ```

4. **Expected Results:**
   ```
   [ALERT] Screen Sharing Detected!
   Confidence: XX.XX%
   Evidence:
     - Process: Zoom.exe is running
   ```

#### Test with OBS Studio
1. Install OBS Studio
2. Start OBS (even if not streaming)
3. Run detection - should detect `obs64.exe` or `obs32.exe`

#### Test with Discord
1. Install Discord
2. Start Discord
3. Start a screen share (even just the feature available)
4. Run detection - should detect `discord.exe`

#### Test with Microsoft Teams
1. Install Teams
2. Start Teams
3. Run detection - should detect `teams.exe`

---

## 🔬 Comprehensive Testing Checklist

### Pre-Test Setup
- [ ] System works on clean machine (your current test)
- [ ] All dependencies installed (`pip install psutil`)
- [ ] Test script works (`python test_system.py`)

### VM Testing
- [ ] Create VirtualBox VM
- [ ] Install detection system in VM
- [ ] Run `python detector.py` in VM
- [ ] Verify VM is detected (high confidence)
- [ ] Check evidence (MAC address, processes, BIOS)
- [ ] Try with VMware (optional)

### Remote Access Testing
- [ ] Test with TeamViewer installed and running
- [ ] Test with AnyDesk installed and running
- [ ] Test with RDP enabled
- [ ] Test with VNC server running
- [ ] Verify each is detected with correct evidence

### Screen Sharing Testing
- [ ] Test with Zoom running
- [ ] Test with OBS running
- [ ] Test with Discord screen sharing
- [ ] Test with Teams screen sharing
- [ ] Verify each is detected

### Edge Cases
- [ ] Test with multiple tools running simultaneously
- [ ] Test detection accuracy (no false positives)
- [ ] Test with tools renamed (evasion test)
- [ ] Test continuous monitoring during tool startup

---

## 📊 Expected Detection Rates

| Scenario | Expected Detection | Confidence Range |
|----------|-------------------|------------------|
| VirtualBox VM | ✅ Should detect | 60-90% |
| VMware VM | ✅ Should detect | 60-90% |
| TeamViewer active | ✅ Should detect | 30-40% |
| RDP enabled | ✅ Should detect | 30-50% |
| Zoom running | ✅ Should detect | 30-40% |
| OBS running | ✅ Should detect | 30% |
| Clean machine | ✅ No alerts | 0-10% |

---

## 🛠️ Troubleshooting

### VM not detected?
**Check:**
1. Are Guest Additions installed? (VirtualBox) or VMware Tools?
2. Is the VM actually running (not just created)?
3. Check MAC address: `python check_vm.py`
4. Check processes: Look for `vboxservice.exe` or `vmtoolsd.exe`

### Remote access not detected?
**Check:**
1. Is the tool actually running? (Check Task Manager)
2. Is the process name correct? (Check what's actually running)
3. For RDP: Is port 3389 listening? Check with: `netstat -an | findstr 3389`

### Screen sharing not detected?
**Check:**
1. Is the application actually running? (Check Task Manager)
2. Is the process name exactly matching? (case-sensitive)
3. Check if process is running: `tasklist | findstr zoom` (Windows)

---

## 🎓 Advanced Testing

### Test Evasion Resistance
1. **Rename process** (e.g., rename `teamviewer.exe` to `svchost.exe`)
   - Detection should still catch it via other methods (ports, behavior)
   
2. **Hide VM processes**
   - Try to stop VM services
   - Detection should still catch via MAC address or BIOS

### Test False Positives
- Run on clean machine for extended period
- Should not trigger false alerts
- Monitor `behavior_history.json` for patterns

### Test Performance
- Monitor detection time: Should be < 5 seconds
- Monitor continuous mode: Should handle long-running sessions
- Check memory usage: Should be reasonable

---

## 📝 Test Report Template

```markdown
## Test Report - [Date]

### VM Detection Test
- [ ] VirtualBox: Detected / Not Detected
- Confidence: XX%
- Evidence: [list]

### Remote Access Test
- [ ] TeamViewer: Detected / Not Detected
- [ ] RDP: Detected / Not Detected
- Evidence: [list]

### Screen Sharing Test
- [ ] Zoom: Detected / Not Detected
- [ ] OBS: Detected / Not Detected
- Evidence: [list]

### Issues Found
- [List any false positives/negatives]

### Performance
- Detection time: X seconds
- Memory usage: X MB
```

---

## ✅ Quick Verification Commands

**On any system, verify detection is working:**
```bash
# Check what processes are running
# Windows:
tasklist | findstr /i "teamviewer zoom obs vbox"

# Check listening ports
netstat -an | findstr "3389 5900 5938"

# Run detection
python detector.py

# Get detailed system info
python check_vm.py
```

---

## 🎯 Success Criteria

Your system is working correctly if:
- ✅ Detects VMs when running inside one
- ✅ Detects remote access tools when active
- ✅ Detects screen sharing apps when running
- ✅ No false positives on clean physical machine
- ✅ Continuous monitoring works reliably
- ✅ All evidence matches actual system state

