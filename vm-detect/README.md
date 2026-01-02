# VM & Remote Access Detection System

A real-time detection system for identifying virtual machines, remote access software, and screen sharing applications. Designed for online exam proctoring, security auditing, and compliance checking scenarios.

## Overview

This system detects three main categories of unauthorized access methods:

1. **Virtual Machines**: VMware, VirtualBox, Hyper-V, QEMU, KVM, Parallels
2. **Remote Access Tools**: TeamViewer, AnyDesk, RDP, VNC, Chrome Remote Desktop
3. **Screen Sharing Applications**: Zoom, OBS, Discord, Teams, Skype, WebEx

The system uses a multi-vector detection approach with weighted scoring to achieve high accuracy while minimizing false positives.

## Features

- Multi-vector detection using 5+ methods per category
- Weighted confidence scoring with configurable thresholds
- Real-time continuous monitoring
- Behavioral pattern analysis over time
- Cross-platform support (Windows, Linux, macOS)
- Evidence collection with detailed reporting
- Performance optimized (sub-second detection time)

## Requirements

- Python 3.8 or higher
- psutil library

Optional dependencies:
- Flask (for web dashboard)

## Installation

1. Install Python 3.8+ if not already installed

2. Install dependencies:
```bash
pip install psutil
```

3. For web dashboard (optional):
```bash
pip install flask
```

## Quick Start

### Run Detection Once

```bash
python detector.py
```

Or using the main script:
```bash
python main.py --once
```

### Continuous Monitoring

Monitor system continuously with 5-second intervals:
```bash
python main.py --monitor --interval 5
```

Monitor and log to file:
```bash
python main.py --monitor --interval 5 --log alerts.log
```

Quiet mode (only show alerts):
```bash
python main.py --monitor --interval 5 --quiet
```

### Manual Verification

Check if system is running in a VM:
```bash
python check_vm.py
```

## Architecture

The system consists of three main layers:

### Collection Layer (collector.py)

Gathers system fingerprints:
- BIOS/vendor information (manufacturer, product names)
- Running processes (optimized to check only suspicious ones)
- Network interfaces and MAC addresses
- Listening ports (optimized to check only suspicious ports)
- Session information (RDP, SSH indicators)
- CPU timing characteristics
- GPU artifacts
- System metrics

### Detection Layer (detector.py)

Analyzes collected data:
- Loads detection signatures from JSON configuration
- Matches indicators using weighted scoring algorithm
- Calculates confidence scores for each category
- Applies configurable thresholds
- Generates evidence reports

### Monitoring Layer (main.py)

Provides interfaces:
- Command-line interface for one-time or continuous monitoring
- Real-time alerting when threats detected
- Logging capabilities for audit trails
- Multiple output formats (text, JSON)

## Detection Methods

### Virtual Machine Detection

1. **BIOS String Detection**: Checks system manufacturer and product names for VM keywords (VMware, VirtualBox, QEMU, etc.). High reliability (95%), difficult to evade.

2. **MAC Address Validation**: Validates MAC addresses against known VM vendor prefixes. High reliability (90%), requires MAC spoofing to evade.

3. **Process Monitoring**: Scans for VM-related processes (vboxservice.exe, vmtoolsd.exe). Medium reliability (75%), can be evaded by renaming processes.

4. **CPU Timing Analysis**: Measures timing variance which is typically higher in VMs due to hypervisor scheduling. Medium reliability (65%), affected by system load.

5. **GPU Artifact Detection**: Detects virtual GPUs and missing real GPU drivers. Lower reliability (55%), can have false positives.

6. **CPU Information**: Checks for hypervisor flags and unusual CPU configurations. Medium reliability.

### Remote Access Detection

1. **Process Detection**: Monitors for remote access processes (teamviewer.exe, anydesk.exe, mstsc.exe, vncserver.exe). High reliability (85%).

2. **Port Scanning**: Checks for listening ports associated with remote access (3389 RDP, 5900 VNC, 5938 TeamViewer). Medium reliability (70%).

3. **Session Indicators**: Detects RDP sessions via environment variables (SESSIONNAME="RDP-Tcp") and SSH connections. High reliability (90%).

### Screen Sharing Detection

1. **Process Detection**: Monitors for screen sharing applications (zoom.exe, obs64.exe, discord.exe, teams.exe). High reliability (85%).

## Detection Algorithm

The system uses a weighted scoring algorithm:

```
Total_Score = Σ(Indicator_Weight × Match_Value)

where:
  Indicator_Weight = predefined importance (from signatures.json)
  Match_Value = 1 if indicator detected, 0 otherwise

Detection = (Total_Score >= Threshold)
```

### Current Weights

- BIOS match: 0.4 (high reliability)
- MAC match: 0.3 (high reliability)
- Process match: 0.25 (medium reliability)
- Port match: 0.15 (medium reliability)
- Session match: 0.3 (high reliability)
- GPU match: 0.15 (lower reliability)
- Timing match: 0.15 (lower reliability)

### Thresholds

- VM confidence: 0.6 (60%)
- Remote access confidence: 0.4 (40%)
- Screen share confidence: 0.3 (30%)

These can be adjusted in `signatures.json`.

## Configuration

Detection behavior is configured in `signatures.json`:

- **Indicators**: Lists of processes, ports, keywords to check
- **Weights**: Importance of each detection method
- **Thresholds**: Confidence levels required for alerts

To customize detection:
1. Edit `signatures.json`
2. Add new indicators to appropriate lists
3. Adjust weights to change method importance
4. Modify thresholds to change sensitivity

Example: To add a new VM process indicator, add it to `vm_indicators.processes` array.

## Project Structure

```
vm-detect/
├── collector.py              # Data collection layer
├── detector.py               # Detection engine
├── main.py                   # CLI interface and monitoring
├── behavioral_analyzer.py    # Pattern analysis over time
├── check_vm.py               # Manual VM verification tool
├── dashboard.py              # Optional web dashboard
├── signatures.json           # Detection configuration
└── requirements.txt          # Python dependencies
```

## Components

### collector.py

System data collection module. Functions:
- `get_bios_info()`: Collects BIOS/vendor strings
- `get_processes()`: Enumerates running processes (optimized)
- `get_network_info()`: Gets MAC addresses and listening ports (optimized)
- `get_session_info()`: Checks session indicators
- `get_gpu_info()`: Detects GPU artifacts
- `get_timing_info()`: Analyzes CPU timing (optimized to 25 iterations)
- `get_system_metrics()`: Collects system resource metrics
- `collect_all()`: Main function that gathers all data

### detector.py

Detection engine module. Classes:
- `VMRemoteDetector`: Main detection class
  - `detect_vm()`: Virtual machine detection
  - `detect_remote_access()`: Remote access detection
  - `detect_screen_share()`: Screen sharing detection
  - `analyze()`: Performs full system analysis
  - `format_report()`: Generates human-readable report

### main.py

Command-line interface and monitoring system. Functions:
- `monitor_continuous()`: Continuous monitoring loop
- `run_once()`: One-time detection
- `main()`: CLI argument parsing

### behavioral_analyzer.py

Pattern analysis module. Classes:
- `BehavioralAnalyzer`: Tracks detection history and identifies anomalies
  - `add_detection()`: Records detection result
  - `analyze_patterns()`: Identifies patterns and anomalies
  - `get_statistics()`: Returns detection statistics

### check_vm.py

Manual verification tool that performs comprehensive system checks to verify VM status.

## Performance

- Detection time: ~1 second per scan (optimized from ~2.5 seconds)
- Memory usage: 50-100 MB
- CPU usage: <5% during scan
- Throughput: 60+ scans per minute

### Optimizations

- Selective process checking: Only examines ~30 suspicious processes instead of all 500+
- Selective port scanning: Only checks 8 suspicious ports instead of all connections
- Reduced timing iterations: 25 iterations instead of 100 (4x faster)
- Efficient data structures: Sets for O(1) lookup operations

## Usage Examples

### Basic Detection

```bash
python detector.py
```

Output shows detection report with confidence scores for each category.

### Continuous Monitoring

```bash
python main.py --monitor --interval 5
```

Continuously scans every 5 seconds and alerts when threats are detected.

### JSON Output

```bash
python main.py --once --format json --output result.json
```

Saves detection results in JSON format for programmatic processing.

### Logging

```bash
python main.py --monitor --interval 10 --log detection.log
```

Monitors continuously and logs all detections to file.

## Detection Capabilities

### Virtual Machines

Detects: VMware, VirtualBox, Hyper-V, QEMU, KVM, Parallels, Xen

Indicators: BIOS strings, MAC vendor prefixes, VM processes, CPU timing anomalies, GPU artifacts

### Remote Access Tools

Detects: TeamViewer, AnyDesk, Windows RDP, VNC (multiple variants), Chrome Remote Desktop, LogMeIn, Splashtop

Indicators: Processes, listening ports, session information

### Screen Sharing

Detects: Zoom, OBS Studio, Discord, Microsoft Teams, Skype, WebEx, GoToMeeting, screen recording tools

Indicators: Application processes

## Limitations

### Detection Limitations

- Cannot detect browser-based screen sharing (Chrome tab sharing) without active network connections
- Cannot detect VPN-encrypted remote access (tunneled connections)
- Cannot detect kernel-level process hiding
- Cannot detect custom VMs with all artifacts removed
- GPU detection can have false positives on systems without dedicated GPU
- Timing analysis can be affected by high system load and background processes (mitigated: timing checks only run when other VM indicators are present)

### Evasion Resistance

The system is resistant to basic evasion:
- Process renaming: Still detected via other indicators (BIOS, MAC)
- MAC spoofing: BIOS strings still reveal VM
- Port hiding: Process detection still works
- Stopping VM services: BIOS and MAC still detect

However, advanced evasion techniques can bypass detection:
- Custom VM configurations with all artifacts removed
- Kernel-level process hiding
- Encrypted tunnels
- Hardware passthrough

## Technical Details

### Platform Support

**Windows**:
- Full feature set
- Registry access for BIOS information
- WMI for GPU detection (optional)
- Environment variables for RDP detection

**Linux**:
- Core features available
- Requires dmidecode for BIOS information (install: `apt install dmidecode`)
- Environment variables for SSH detection
- Process and network detection fully functional

**macOS**:
- Basic detection available
- Limited VM detection capabilities
- Process and network detection functional

### Dependencies

**Required**:
- psutil: System and process information

**Optional**:
- Flask: Web dashboard interface
- WMI (Python): Windows GPU detection (auto-installed if available)

### Performance Characteristics

The system is optimized for real-time monitoring:
- Sub-second detection time allows for frequent scans
- Low resource usage enables background operation
- Selective checking reduces overhead on large systems

## Testing

To verify the system is working:

```bash
python detector.py
```

This should complete in under 1 second and show detection results. On a physical machine, you should see low confidence scores (below thresholds).

To test on a VM:
1. Install VirtualBox or VMware
2. Copy this project into the VM
3. Run detection inside the VM
4. Should detect VM with high confidence

To test remote access detection:
1. Install TeamViewer or AnyDesk
2. Start the application
3. Run detection
4. Should detect remote access process

## Configuration Reference

### signatures.json Structure

```json
{
  "vm_indicators": {
    "bios_keywords": [...],      // Keywords to search in BIOS strings
    "mac_vendors": [...],        // MAC address vendor prefixes
    "processes": [...],          // VM-related process names
    "cpu_keywords": [...]        // Keywords in CPU info
  },
  "remote_indicators": {
    "processes": [...],          // Remote access process names
    "ports": [...],              // Suspicious listening ports
    "session_keywords": [...]    // Session indicator keywords
  },
  "screen_share_indicators": {
    "processes": [...]           // Screen sharing process names
  },
  "weights": {
    // Weight for each detection method (0.0 to 1.0)
  },
  "thresholds": {
    // Confidence thresholds for alerts (0.0 to 1.0)
  }
}
```

## Extending the System

### Adding New Indicators

Edit `signatures.json` and add to appropriate arrays:
- VM processes: Add to `vm_indicators.processes`
- Remote access ports: Add to `remote_indicators.ports`
- Screen sharing apps: Add to `screen_share_indicators.processes`

### Adding New Detection Methods

1. Add data collection function to `collector.py`
2. Add detection logic to `detector.py`
3. Add weight to `signatures.json`
4. Integrate into detection flow

### Modifying Weights and Thresholds

Edit `signatures.json`:
- Increase weight for more reliable indicators
- Decrease weight for less reliable indicators
- Adjust thresholds based on false positive/negative rates

## Future Improvements

The following enhancements are planned for future versions:

1. **Enhanced Timing Detection**:
   - Multiple measurement samples with statistical analysis
   - Pattern detection (consistent anomalies vs. random variance)
   - Baseline comparison against known-good measurements
   - CPU feature detection (RDTSC behavior, hypervisor bit, etc.)
   - Machine learning to distinguish VM timing patterns from physical machine noise

2. **Network Traffic Analysis**:
   - Deep packet inspection for encrypted meeting protocols
   - Traffic pattern analysis (packet sizes, timing patterns)
   - DNS query monitoring for meeting domain lookups

3. **Advanced Process Detection**:
   - Window title analysis for browser-based meetings
   - Process tree analysis (parent-child relationships)
   - Memory scanning for known signatures

4. **Hardware Fingerprinting**:
   - More sophisticated BIOS/UEFI analysis
   - Hardware component enumeration
   - CPUID instruction analysis

5. **Machine Learning**:
   - Train models on known VM vs. physical machine datasets
   - Behavioral analysis over time
   - Adaptive threshold adjustment

## License

This project is for research and educational purposes.
