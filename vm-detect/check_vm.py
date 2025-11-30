#!/usr/bin/env python3
"""
Manual VM Check Utility - Helps verify if system is actually running in a VM.
Provides multiple checks to help determine VM status.
"""

import platform
import subprocess
import psutil
import os

# Windows-specific imports
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

def check_bios_registry():
    """Check Windows registry for BIOS/System info."""
    print("\n" + "="*60)
    print("BIOS / System Information Check")
    print("="*60)
    
    if platform.system().lower() != 'windows' or not HAS_WINREG:
        print("⚠️  Windows registry check not available on this system")
        return
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System")
        manufacturer = winreg.QueryValueEx(key, "SystemManufacturer")[0]
        product = winreg.QueryValueEx(key, "SystemProductName")[0]
        winreg.CloseKey(key)
        
        print(f"Manufacturer: {manufacturer}")
        print(f"Product Name: {product}")
        
        # Check for VM indicators
        vm_keywords = ["vmware", "virtualbox", "qemu", "kvm", "virtual", "microsoft corporation", "innotek", "xen"]
        manufacturer_lower = manufacturer.lower()
        product_lower = product.lower()
        
        found_vm = False
        for keyword in vm_keywords:
            if keyword in manufacturer_lower or keyword in product_lower:
                print(f"⚠️  VM INDICATOR FOUND: '{keyword}' in manufacturer/product")
                found_vm = True
        
        if not found_vm:
            print("✅ No obvious VM indicators in BIOS info")
    except Exception as e:
        print(f"❌ Could not read registry: {e}")

def check_mac_addresses():
    """Check MAC addresses for VM vendor prefixes."""
    print("\n" + "="*60)
    print("MAC Address Check")
    print("="*60)
    
    try:
        if_addrs = psutil.net_if_addrs()
        vm_mac_prefixes = {
            "08:00:27": "VirtualBox",
            "00:05:69": "VMware",
            "00:0c:29": "VMware",
            "00:1c:14": "VMware",
            "00:50:56": "VMware",
            "00:16:3e": "Xen",
            "00:1b:21": "Parallels"
        }
        
        found_vm_mac = False
        for iface_name, addrs in if_addrs.items():
            for addr in addrs:
                if addr.family == -1 or addr.family == psutil.AF_LINK:
                    mac = addr.address.upper().replace('-', ':')
                    # Check first 3 octets (OUI)
                    oui = ':'.join(mac.split(':')[:3])
                    if oui in vm_mac_prefixes:
                        print(f"⚠️  VM MAC DETECTED: {mac}")
                        print(f"   Vendor: {vm_mac_prefixes[oui]}")
                        found_vm_mac = True
                    elif not found_vm_mac:
                        print(f"   {iface_name}: {mac}")
        
        if not found_vm_mac:
            print("✅ No VM MAC address prefixes found")
    except Exception as e:
        print(f"❌ Error checking MAC addresses: {e}")

def check_vm_processes():
    """Check for VM-related processes."""
    print("\n" + "="*60)
    print("VM Process Check")
    print("="*60)
    
    vm_processes = [
        "vboxservice.exe", "vmtoolsd.exe", "vmwaretray.exe", 
        "vboxtray.exe", "hypervvmservice.exe", "vmwareuser.exe",
        "vboxguest.exe", "qemu-ga.exe", "vmware.exe"
    ]
    
    running_processes = []
    for proc in psutil.process_iter(['name']):
        try:
            proc_name = proc.info['name'].lower()
            if proc_name in [p.lower() for p in vm_processes]:
                running_processes.append(proc_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if running_processes:
        print("⚠️  VM PROCESSES DETECTED:")
        for proc in running_processes:
            print(f"   - {proc}")
    else:
        print("✅ No VM processes found")

def check_cpu_info():
    """Check CPU information for VM indicators."""
    print("\n" + "="*60)
    print("CPU Information Check")
    print("="*60)
    
    print(f"CPU Count (physical): {psutil.cpu_count(logical=False)}")
    print(f"CPU Count (logical): {psutil.cpu_count(logical=True)}")
    print(f"Processor: {platform.processor()}")
    
    # Check for hypervisor flag in CPU
    cpu_info_lower = platform.processor().lower()
    vm_keywords = ["virtual", "qemu", "vmware", "kvm"]
    found_vm_cpu = False
    for keyword in vm_keywords:
        if keyword in cpu_info_lower:
            print(f"⚠️  VM INDICATOR: '{keyword}' found in CPU info")
            found_vm_cpu = True
    
    if not found_vm_cpu:
        print("✅ No VM indicators in CPU info")

def check_session_info():
    """Check session information."""
    print("\n" + "="*60)
    print("Session Information")
    print("="*60)
    
    if platform.system().lower() == 'windows':
        session_name = os.getenv('SESSIONNAME', 'Unknown')
        print(f"Session Name: {session_name}")
        if 'rdp' in session_name.lower():
            print("⚠️  Remote Desktop Session detected")
        else:
            print("✅ Local session (not RDP)")
    else:
        ssh_conn = os.getenv('SSH_CONNECTION')
        if ssh_conn:
            print(f"⚠️  SSH Connection detected: {ssh_conn}")
        else:
            print("✅ No SSH connection detected")

def check_wmic_system_info():
    """Use WMIC to get system info (Windows only)."""
    if platform.system().lower() != 'windows':
        return
    
    print("\n" + "="*60)
    print("WMIC System Information")
    print("="*60)
    
    try:
        result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer,model'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip() and 'Manufacturer' not in line and 'Model' not in line:
                    print(f"System Info: {line.strip()}")
    except Exception as e:
        print(f"⚠️  WMIC check failed: {e}")

def main():
    """Run all VM checks."""
    print("="*60)
    print("Manual VM Detection Check")
    print("="*60)
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Hostname: {platform.node()}")
    
    check_bios_registry()
    check_mac_addresses()
    check_vm_processes()
    check_cpu_info()
    check_session_info()
    check_wmic_system_info()
    
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    print("If you see multiple ⚠️ warnings above, you're likely in a VM.")
    print("If you only see ✅ marks, you're likely on a physical machine.")
    print("\nNote: Some indicators (like GPU detection) can give false positives.")
    print("The most reliable indicators are:")
    print("  - BIOS Manufacturer/Product with VM keywords")
    print("  - VM MAC address prefixes")
    print("  - VM processes running")

if __name__ == "__main__":
    main()

