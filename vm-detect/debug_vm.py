from collector import collect_all
from detector import VMRemoteDetector
import json

data = collect_all()
det = VMRemoteDetector()
result = det.analyze(data)

print("="*60)
print("VM Detection Debug")
print("="*60)

# Get VM detection directly
vm_score, vm_matches = det.detect_vm(data)
print(f"\nVM Score: {vm_score:.2%}")
print(f"VM Detected: {vm_score >= det.thresholds.get('vm_confidence', 0.6)}")
print(f"\nMatches ({len(vm_matches)}):")
for match in vm_matches:
    print(f"  - {match}")

# Check individual components
print("\n" + "="*60)
print("Individual Component Scores:")
print("="*60)

# Check BIOS
bios_score, bios_matches = det._check_bios_keywords(data.get("bios", {}))
print(f"\nBIOS: {bios_score:.2%}")
if bios_matches:
    for m in bios_matches:
        print(f"  - {m}")

# Check MAC
mac_score, mac_matches = det._check_mac_addresses(data.get("network", {}).get("mac_addresses", []))
print(f"\nMAC: {mac_score:.2%}")
if mac_matches:
    for m in mac_matches:
        print(f"  - {m}")

# Check Processes
vm_procs = det.signatures.get("vm_indicators", {}).get("processes", [])
proc_score, proc_matches = det._check_processes(vm_procs, data.get("processes", []))
print(f"\nProcesses: {proc_score:.2%}")
if proc_matches:
    for m in proc_matches:
        print(f"  - {m}")

# Check GPU
gpu_score, gpu_matches = det._check_gpu_artifacts(data.get("gpu", {}))
print(f"\nGPU: {gpu_score:.2%}")
if gpu_matches:
    for m in gpu_matches:
        print(f"  - {m}")

# Check Timing
timing_score, timing_matches = det._check_timing_anomalies(data.get("timing", {}))
print(f"\nTiming: {timing_score:.2%}")
if timing_matches:
    for m in timing_matches:
        print(f"  - {m}")

print(f"\n{'='*60}")
print(f"Total: {bios_score + mac_score + proc_score + gpu_score + timing_score:.2%}")
print(f"{'='*60}")

