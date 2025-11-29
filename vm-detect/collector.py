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
    """List running processes (look for VM/remote tools)."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info['name'].lower())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_network_info():
    """Get MAC addresses and open connections (VMs have specific MAC vendors)."""
    net = {}
    macs = []
    
    # Use psutil to get network interfaces and MAC addresses
    try:
        if_addrs = psutil.net_if_addrs()
        for iface_name, addrs in if_addrs.items():
            for addr in addrs:
                # psutil uses AF_LINK (-1 on Windows, 17 on Linux) for MAC addresses
                # Check for AF_LINK family (MAC addresses)
                if addr.family == -1 or addr.family == psutil.AF_LINK or (hasattr(psutil, 'AF_LINK') and addr.family == getattr(psutil, 'AF_LINK')):
                    mac = addr.address.upper()
                    # Skip invalid MACs
                    if mac and mac != '00:00:00:00:00:00' and mac != '00-00-00-00-00-00':
                        # Normalize MAC address format (replace hyphens with colons)
                        mac = mac.replace('-', ':')
                        # Validate MAC format (should be XX:XX:XX:XX:XX:XX)
                        if len(mac) == 17 and mac.count(':') == 5:
                            macs.append(mac)
        net['mac_addresses'] = list(set(macs))  # Remove duplicates
    except Exception:
        net['mac_addresses'] = []
    
    # Open connections (e.g., RDP port 3389)
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                connections.append({'local': conn.laddr, 'remote': conn.raddr, 'pid': conn.pid})
        net['listening_ports'] = [c['local'][1] for c in connections if c['local']]
    except (psutil.AccessDenied, AttributeError):
        # On some systems, net_connections() requires elevated privileges
        net['listening_ports'] = []
    
    return net

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
    """Get CPU timing information (can detect hypervisors through timing anomalies)."""
    timing = {}
    
    try:
        # Method 1: RDTSC (Read Time-Stamp Counter) timing test
        # VMs often have inconsistent timing
        iterations = 100
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            # Do a small computation
            _ = sum(range(100))
            end = time.perf_counter()
            times.append((end - start) * 1e6)  # Convert to microseconds
        
        timing['min_time'] = min(times)
        timing['max_time'] = max(times)
        timing['avg_time'] = sum(times) / len(times)
        timing['std_dev'] = (sum((x - timing['avg_time'])**2 for x in times) / len(times)) ** 0.5
        
        # VMs often have higher variance in timing
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
    }
    return data

if __name__ == "__main__":
    print(json.dumps(collect_all(), indent=2))