#!/usr/bin/env python3
"""
Test script to check if remote access tools are installed/running.
Useful for verifying detection without manually installing tools.
"""

import psutil
import platform

def check_processes(process_names):
    """Check if any of the processes are running."""
    running_processes = []
    all_processes = []
    
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            proc_name = proc.info['name'].lower()
            all_processes.append(proc_name)
            for target_name in process_names:
                if target_name.lower() in proc_name:
                    running_processes.append({
                        'name': proc.info['name'],
                        'pid': proc.info['pid']
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return running_processes, all_processes

def test_remote_access_detection():
    """Test if remote access tools are detected."""
    print("="*60)
    print("Remote Access Tool Detection Test")
    print("="*60)
    
    remote_tools = [
        'teamviewer', 'anydesk', 'mstsc', 'vnc', 'ultravnc',
        'tightvnc', 'logmein', 'splashtop', 'chrome_remote',
        'remotedesktop'
    ]
    
    found, all_procs = check_processes(remote_tools)
    
    if found:
        print("\n✅ Remote Access Tools Found:")
        for tool in found:
            print(f"   - {tool['name']} (PID: {tool['pid']})")
        print("\n⚠️  If you see this, your detector should catch it!")
    else:
        print("\n❌ No Remote Access Tools Running")
        print("\nTo test detection:")
        print("  1. Install TeamViewer or AnyDesk")
        print("  2. Start the application")
        print("  3. Run: python detector.py")

def test_screen_sharing_detection():
    """Test if screen sharing tools are detected."""
    print("\n" + "="*60)
    print("Screen Sharing Tool Detection Test")
    print("="*60)
    
    screen_tools = [
        'zoom', 'obs', 'discord', 'teams', 'skype',
        'webex', 'gotomeeting', 'camtasia', 'fraps',
        'xsplit', 'screenflow'
    ]
    
    found, all_procs = check_processes(screen_tools)
    
    if found:
        print("\n✅ Screen Sharing Tools Found:")
        for tool in found:
            print(f"   - {tool['name']} (PID: {tool['pid']})")
        print("\n⚠️  If you see this, your detector should catch it!")
    else:
        print("\n❌ No Screen Sharing Tools Running")
        print("\nTo test detection:")
        print("  1. Install Zoom, OBS, or Discord")
        print("  2. Start the application")
        print("  3. Run: python detector.py")

def test_vm_processes():
    """Test if VM-related processes are running."""
    print("\n" + "="*60)
    print("VM Process Detection Test")
    print("="*60)
    
    vm_processes = [
        'vboxservice', 'vmtoolsd', 'vmwaretray', 'vboxtray',
        'hyperv', 'qemu', 'vmware'
    ]
    
    found, all_procs = check_processes(vm_processes)
    
    if found:
        print("\n⚠️  VM Processes Found:")
        for tool in found:
            print(f"   - {tool['name']} (PID: {tool['pid']})")
        print("\n⚠️  You might be running in a VM!")
    else:
        print("\n✅ No VM Processes Found")
        print("   (You're likely on a physical machine)")

def check_listening_ports():
    """Check for remote access ports."""
    print("\n" + "="*60)
    print("Remote Access Port Check")
    print("="*60)
    
    remote_ports = {
        3389: 'RDP',
        5900: 'VNC',
        5901: 'VNC',
        5902: 'VNC',
        5938: 'TeamViewer',
        7070: 'TeamViewer',
        4000: 'AnyDesk',
        5500: 'VNC'
    }
    
    listening_ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr[1]
                if port in remote_ports:
                    listening_ports.append((port, remote_ports[port]))
    except (psutil.AccessDenied, AttributeError):
        print("⚠️  Cannot check ports (requires admin privileges)")
        return
    
    if listening_ports:
        print("\n⚠️  Remote Access Ports Listening:")
        for port, service in listening_ports:
            print(f"   - Port {port}: {service}")
    else:
        print("\n✅ No Remote Access Ports Listening")

def main():
    """Run all tests."""
    print("="*60)
    print("Detection System - Real-World Test")
    print("="*60)
    print(f"System: {platform.system()} {platform.release()}")
    
    test_remote_access_detection()
    test_screen_sharing_detection()
    test_vm_processes()
    check_listening_ports()
    
    print("\n" + "="*60)
    print("Test Complete")
    print("="*60)
    print("\nNext steps:")
    print("  1. Install tools listed above if needed")
    print("  2. Start the tools")
    print("  3. Run: python detector.py")
    print("  4. Verify detection matches what you see here")

if __name__ == "__main__":
    main()

