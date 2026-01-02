import platform
import json
import subprocess
import psutil
import socket
import os
import sys
import time
import struct

# Windows-specific imports (will be ignored on other OS)
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

def get_bios_info():
    """Get BIOS/vendor strings that often reveal VMs."""
    bios = {}
    system = platform.system().lower()
    
    if system == 'windows' and HAS_WINREG:
        # Windows: Check registry for system manufacturer/product
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System")
            bios['manufacturer'] = winreg.QueryValueEx(key, "SystemManufacturer")[0]
            bios['product'] = winreg.QueryValueEx(key, "SystemProductName")[0]
            winreg.CloseKey(key)
        except Exception:
            bios['manufacturer'] = 'Unknown'
            bios['product'] = 'Unknown'
    else:
        # Linux: Use dmidecode (install if needed: apt install dmidecode)
        try:
            output = subprocess.check_output(['dmidecode', '-s', 'system-manufacturer'], stderr=subprocess.DEVNULL)
            bios['manufacturer'] = output.decode().strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            bios['manufacturer'] = 'Unknown'
        try:
            output = subprocess.check_output(['dmidecode', '-s', 'system-product-name'], stderr=subprocess.DEVNULL)
            bios['product'] = output.decode().strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            bios['product'] = 'Unknown'
    
    # Cross-platform: CPU info for hypervisor flags
    bios['cpu_info'] = platform.processor()
    return bios

def get_processes():
    """List running processes (look for VM/remote tools) - optimized to only check suspicious ones."""
    # Get list of suspicious processes from signatures (if available)
    suspicious_processes = set()
    browser_processes = set()
    browser_keywords = []
    try:
        import json
        with open('signatures.json', 'r') as f:
            sigs = json.load(f)
            # Collect all suspicious process names
            suspicious_processes.update(sigs.get('vm_indicators', {}).get('processes', []))
            suspicious_processes.update(sigs.get('remote_indicators', {}).get('processes', []))
            suspicious_processes.update(sigs.get('screen_share_indicators', {}).get('processes', []))
            suspicious_processes = {p.lower() for p in suspicious_processes}
            # Also collect browser processes for screen sharing detection
            browser_processes.update(sigs.get('screen_share_indicators', {}).get('browser_processes', []))
            browser_processes = {p.lower() for p in browser_processes}
            browser_keywords = sigs.get('screen_share_indicators', {}).get('browser_keywords', [])
    except:
        pass
    
    # Only check for suspicious processes (much faster)
    found_processes = []
    if suspicious_processes or browser_processes:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in suspicious_processes:
                    found_processes.append(proc_name)
                elif proc_name in browser_processes:
                    # Check if browser command line contains screen sharing keywords
                    cmdline = ' '.join(proc.info.get('cmdline', [])).lower()
                    if any(keyword.lower() in cmdline for keyword in browser_keywords):
                        found_processes.append(f"{proc_name}_screenshare")
                    else:
                        # Browser running but not necessarily screen sharing - note it anyway
                        found_processes.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return found_processes
    
    # Fallback: get all processes if signatures not available
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info['name'].lower())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_network_info():
    """Get MAC addresses and open connections (VMs have specific MAC vendors) - optimized."""
    net = {}
    macs = []
    
    # Use psutil to get network interfaces and MAC addresses (cached in practice)
    try:
        if_addrs = psutil.net_if_addrs()
        for iface_name, addrs in if_addrs.items():
            for addr in addrs:
                if addr.family == -1 or addr.family == psutil.AF_LINK:
                    mac = addr.address.upper().replace('-', ':')
                    if mac and mac != '00:00:00:00:00:00' and len(mac) == 17 and mac.count(':') == 5:
                        macs.append(mac)
        net['mac_addresses'] = list(set(macs))
    except Exception:
        net['mac_addresses'] = []
    
    # Only check suspicious ports (much faster)
    suspicious_ports = set()
    try:
        import json
        with open('signatures.json', 'r') as f:
            sigs = json.load(f)
            suspicious_ports = set(sigs.get('remote_indicators', {}).get('ports', []))
    except:
        suspicious_ports = {3389, 5900, 5938, 7070}  # Fallback common ports
    
    listening_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr[1]
                if port in suspicious_ports:  # Only check suspicious ports
                    listening_ports.append(port)
        net['listening_ports'] = listening_ports
    except (psutil.AccessDenied, AttributeError):
        net['listening_ports'] = []
    
    return net

def get_browser_connections():
    """Check if browsers are actively connected to meeting domains (Google Meet, Zoom, Teams, etc.)."""
    meeting_domains = []
    browser_processes = set()
    
    try:
        import json
        with open('signatures.json', 'r') as f:
            sigs = json.load(f)
            browser_keywords = sigs.get('screen_share_indicators', {}).get('browser_keywords', [])
            # Extract domains from keywords
            for keyword in browser_keywords:
                if 'google.com' in keyword.lower():
                    meeting_domains.extend(['meet.google.com', 'google.com', 'googleapis.com', 'gstatic.com'])
                elif 'zoom.us' in keyword.lower():
                    meeting_domains.extend(['zoom.us', 'zoom.com', 'zoomgov.com'])
                elif 'teams.microsoft.com' in keyword.lower():
                    meeting_domains.extend(['teams.microsoft.com', 'microsoft.com', 'office.com'])
                elif 'webex.com' in keyword.lower():
                    meeting_domains.extend(['webex.com', 'cisco.com'])
            
            browser_processes.update(sigs.get('screen_share_indicators', {}).get('browser_processes', []))
            browser_processes = {p.lower() for p in browser_processes}
    except:
        meeting_domains = ['meet.google.com', 'zoom.us', 'teams.microsoft.com', 'webex.com']
        browser_processes = {'chrome.exe', 'msedge.exe', 'firefox.exe'}
    
    active_meetings = set()
    
    try:
        # Get all network connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV'] and conn.raddr:
                try:
                    # Try to get process info for this connection
                    if hasattr(conn, 'pid') and conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name().lower()
                        
                        if proc_name in browser_processes:
                            # Check if connected to meeting domain
                            # Note: raddr is usually IP, we'd need reverse DNS, but we check process
                            # For now, if browser is making connections, it might be in a meeting
                            # We'll use a more reliable method: check if browser has many active connections
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    pass
    except (psutil.AccessDenied, AttributeError):
        pass
    
    # Alternative approach: Check if browsers have active network activity
    # Count active connections per browser process
    browser_connection_counts = {}
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                if proc_name in browser_processes:
                    try:
                        conns = proc.connections(kind='inet')
                        active_conns = [c for c in conns if c.status in ['ESTABLISHED', 'SYN_SENT']]
                        if active_conns:
                            browser_connection_counts[proc_name] = browser_connection_counts.get(proc_name, 0) + len(active_conns)
                    except (psutil.AccessDenied, AttributeError):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except:
        pass
    
    # If browsers have many active connections, might be in a meeting
    # BUT: Chrome can have 10-20+ connections from normal browsing (tabs, extensions, sync)
    # Meetings typically have 15-30+ connections (audio, video, signaling, data channels)
    # Use a higher threshold to reduce false positives
    meeting_browsers = set()
    for browser, conn_count in browser_connection_counts.items():
        # Require significantly more connections than normal browsing
        # Normal browsing: 5-15 connections
        # Active meeting: 20-50+ connections
        if conn_count >= 20:  # Much higher threshold to avoid false positives
            meeting_browsers.add(browser)
            # Note: We can't reliably identify which meeting service without DNS lookup
            # So we just note that browser has high connection count
            active_meetings.add("high_connection_count")
    
    return {
        'active_meeting_browsers': list(meeting_browsers),
        'detected_meeting_domains': list(active_meetings) if active_meetings else [],
        'browser_connection_counts': browser_connection_counts
    }

def get_session_info():
    """Check for remote sessions (e.g., RDP env vars)."""
    session = {}
    session['hostname'] = platform.node()
    session['user'] = os.getenv('USERNAME') or os.getenv('USER', 'Unknown')
    
    # Windows RDP check
    if platform.system().lower() == 'windows':
        session['session_name'] = os.getenv('SESSIONNAME', 'Unknown')
    else:
        # Linux SSH check
        session['ssh_connection'] = bool(os.getenv('SSH_CONNECTION'))
    
    return session

def get_gpu_info():
    """Get GPU information (can reveal VM artifacts)."""
    gpu = {}
    gpu['devices'] = []
    gpu['count'] = 0
    
    try:
        # Try to detect GPUs using various methods
        # Method 1: Windows WMI (if available)
        if platform.system().lower() == 'windows':
            try:
                import wmi
                c = wmi.WMI()
                for video_controller in c.Win32_VideoController():
                    gpu['devices'].append({
                        'name': video_controller.Name or 'Unknown',
                        'driver': video_controller.DriverVersion or 'Unknown',
                        'adapter_ram': video_controller.AdapterRAM or 0
                    })
                gpu['count'] = len(gpu['devices'])
            except ImportError:
                # WMI not available, try alternative methods
                pass
            except Exception:
                pass
        
        # Method 2: Check for common GPU processes
        gpu_processes = ['nvidia-smi.exe', 'nvxdsync.exe', 'nvcontainer.exe', 
                        'amdkmdap.exe', 'atieclxx.exe', 'igfxext.exe']
        running_gpu_processes = []
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                if any(gpu_proc.lower() in proc_name for gpu_proc in gpu_processes):
                    running_gpu_processes.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        gpu['processes'] = running_gpu_processes
        
        # Method 3: Check for GPU-related registry keys (Windows)
        if platform.system().lower() == 'windows' and HAS_WINREG:
            try:
                # Check for NVIDIA
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\nvlddmkm")
                    gpu['nvidia_driver'] = True
                    winreg.CloseKey(key)
                except Exception:
                    gpu['nvidia_driver'] = False
                
                # Check for AMD
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\amdkmdap")
                    gpu['amd_driver'] = True
                    winreg.CloseKey(key)
                except Exception:
                    gpu['amd_driver'] = False
                
                # Check for Intel
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\igfx")
                    gpu['intel_driver'] = True
                    winreg.CloseKey(key)
                except Exception:
                    gpu['intel_driver'] = False
            except Exception:
                pass
        
        # Method 4: Linux lspci (if available)
        if platform.system().lower() == 'linux':
            try:
                output = subprocess.check_output(['lspci'], stderr=subprocess.DEVNULL)
                gpu_lines = [line for line in output.decode().split('\n') if 'VGA' in line or '3D' in line or 'Display' in line]
                gpu['count'] = len(gpu_lines)
                gpu['devices'] = gpu_lines
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
    except Exception:
        pass
    
    return gpu

def get_timing_info():
    """Get CPU timing information (can detect hypervisors through timing anomalies) - optimized."""
    timing = {}
    
    try:
        # Optimized: Use fewer iterations (25 instead of 100) for faster detection
        # Still accurate enough for VM detection
        iterations = 25  # Reduced from 100 to 25 (4x faster)
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            _ = sum(range(100))
            end = time.perf_counter()
            times.append((end - start) * 1e6)
        
        timing['min_time'] = min(times)
        timing['max_time'] = max(times)
        timing['avg_time'] = sum(times) / len(times)
        timing['std_dev'] = (sum((x - timing['avg_time'])**2 for x in times) / len(times)) ** 0.5
        timing['variance'] = timing['std_dev'] / timing['avg_time'] if timing['avg_time'] > 0 else 0
        
        # Method 2: CPU frequency detection
        try:
            freq = psutil.cpu_freq()
            if freq:
                timing['cpu_freq_current'] = freq.current
                timing['cpu_freq_min'] = freq.min
                timing['cpu_freq_max'] = freq.max
        except Exception:
            pass
        
        # Method 3: CPU count and architecture
        timing['cpu_count'] = psutil.cpu_count(logical=False)  # Physical cores
        timing['cpu_count_logical'] = psutil.cpu_count(logical=True)  # Logical cores
        
        # VMs often have unusual CPU counts
        if timing['cpu_count'] and timing['cpu_count'] % 2 != 0 and timing['cpu_count'] > 1:
            timing['odd_cpu_count'] = True
        else:
            timing['odd_cpu_count'] = False
        
    except Exception:
        pass
    
    return timing

def get_system_metrics():
    """Get additional system metrics for behavioral analysis."""
    metrics = {}
    
    try:
        # CPU metrics
        metrics['cpu_percent'] = psutil.cpu_percent(interval=0.1)
        metrics['cpu_count'] = psutil.cpu_count()
        
        # Memory metrics
        mem = psutil.virtual_memory()
        metrics['memory_total'] = mem.total
        metrics['memory_available'] = mem.available
        metrics['memory_percent'] = mem.percent
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        metrics['disk_total'] = disk.total
        metrics['disk_free'] = disk.free
        metrics['disk_percent'] = disk.percent
        
        # Network metrics
        net_io = psutil.net_io_counters()
        metrics['bytes_sent'] = net_io.bytes_sent
        metrics['bytes_recv'] = net_io.bytes_recv
        
        # Process count
        metrics['process_count'] = len(psutil.pids())
        
        # Boot time
        metrics['boot_time'] = psutil.boot_time()
        
        # System uptime
        metrics['uptime'] = time.time() - metrics['boot_time']
        
    except Exception:
        pass
    
    return metrics

def collect_all():
    """Main function: Gather everything into a dict."""
    data = {
        'timestamp': platform.node() + ' - ' + str(platform.platform()),
        'bios': get_bios_info(),
        'processes': get_processes(),
        'network': get_network_info(),
        'session': get_session_info(),
        'gpu': get_gpu_info(),
        'timing': get_timing_info(),
        'metrics': get_system_metrics(),
        'browser_connections': get_browser_connections(),
    }
    return data

if __name__ == "__main__":
    print(json.dumps(collect_all(), indent=2))