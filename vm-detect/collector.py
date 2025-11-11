import platform
import json
import subprocess
import psutil
import socket
import netifaces
import os
import sys

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
    try:
        addrs = netifaces.interfaces()
        macs = []
        for iface in addrs:
            if netifaces.AF_LINK in netifaces.ifaddresses(iface):
                mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
                if mac != '00:00:00:00:00:00':  # Skip invalid
                    macs.append(mac)
        net['mac_addresses'] = macs
    except Exception:
        net['mac_addresses'] = []
    
    # Open connections (e.g., RDP port 3389)
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            connections.append({'local': conn.laddr, 'remote': conn.raddr, 'pid': conn.pid})
    net['listening_ports'] = [c['local'][1] for c in connections if c['local']]
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

def collect_all():
    """Main function: Gather everything into a dict."""
    data = {
        'timestamp': platform.node() + ' - ' + str(platform.platform()),
        'bios': get_bios_info(),
        'processes': get_processes(),
        'network': get_network_info(),
        'session': get_session_info(),
    }
    return data

if __name__ == "__main__":
    print(json.dumps(collect_all(), indent=2))