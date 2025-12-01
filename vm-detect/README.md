# VM & Remote Access Detection System

A detection system that identifies virtual machines, remote access software, and screen sharing applications in real-time.

## Features

- **VM Detection**: Detects VMware, VirtualBox, Hyper-V, QEMU, KVM, and other virtual machines
- **Remote Access Detection**: Identifies TeamViewer, AnyDesk, RDP, VNC, and similar tools
- **Screen Sharing Detection**: Detects Zoom, OBS, Discord, Teams, and other screen sharing applications
- **Real-time Monitoring**: Continuous monitoring with configurable intervals
- **Behavioral Analysis**: Tracks patterns over time to detect anomalies

## Requirements

- Python 3.8 or higher
- psutil library

## Installation

1. Install dependencies:
```bash
pip install psutil
```


## Usage

### Basic Detection

Run a single detection:
```bash
python detector.py
```

Or use the main script:
```bash
python main.py --once
```

### Continuous Monitoring

Monitor system continuously (primary use case for exam proctoring):
```bash
python main.py --monitor --interval 5
```

This will scan every 5 seconds and alert if threats are detected. Press Ctrl+C to stop.

To log results to a file for later analysis:
```bash
python main.py --monitor --interval 5 --log alerts.log
```

Quiet mode (only shows alerts):
```bash
python main.py --monitor --interval 5 --quiet
```

### Check System Status

Verify if you're running in a VM:
```bash
python check_vm.py
```

## Configuration

Detection thresholds and indicators can be configured in `signatures.json`. Edit this file to:
- Adjust confidence thresholds
- Add new detection indicators
- Modify detection weights

## Files

- `collector.py` - System data collection
- `detector.py` - Detection engine
- `main.py` - Command-line interface
- `behavioral_analyzer.py` - Pattern analysis over time
- `dashboard.py` - Optional web dashboard (requires Flask)
- `check_vm.py` - Manual VM verification tool
- `signatures.json` - Detection indicators and configuration

## Testing

Run system health check:
```bash
python test_system.py
```

Check what tools are currently running:
```bash
python test_remote_access.py
```



