import json
import os
import platform
from typing import Dict, List, Tuple
from collector import collect_all

class VMRemoteDetector:
    """Detects virtual machines, remote access, and screen sharing."""
    
    def __init__(self, signatures_file: str = "signatures.json"):
        """Initialize detector with signatures."""
        self.signatures = self._load_signatures(signatures_file)
        self.weights = self.signatures.get("weights", {})
        self.thresholds = self.signatures.get("thresholds", {})
    
    def _load_signatures(self, filepath: str) -> Dict:
        """Load detection signatures from JSON file."""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: {filepath} not found. Using default signatures.")
            return self._get_default_signatures()
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {filepath}")
            return self._get_default_signatures()
    
    def _get_default_signatures(self) -> Dict:
        """Return default signatures if file is missing."""
        return {
            "vm_indicators": {"bios_keywords": [], "processes": []},
            "remote_indicators": {"processes": [], "ports": []},
            "screen_share_indicators": {"processes": []},
            "weights": {},
            "thresholds": {}
        }
    
    def _check_bios_keywords(self, bios_data: Dict) -> Tuple[float, List[str]]:
        """Check BIOS/vendor strings for VM indicators."""
        score = 0.0
        matches = []
        keywords = self.signatures.get("vm_indicators", {}).get("bios_keywords", [])
        
        manufacturer = str(bios_data.get("manufacturer", "")).lower()
        product = str(bios_data.get("product", "")).lower()
        cpu_info = str(bios_data.get("cpu_info", "")).lower()
        
        for keyword in keywords:
            if keyword in manufacturer or keyword in product:
                score += self.weights.get("bios_match", 0.4)
                matches.append(f"BIOS: {keyword} found in manufacturer/product")
            if keyword in cpu_info:
                score += self.weights.get("cpu_match", 0.2)
                matches.append(f"CPU: {keyword} found in CPU info")
        
        return min(score, 1.0), matches
    
    def _check_mac_addresses(self, mac_addresses: List[str]) -> Tuple[float, List[str]]:
        """Check MAC addresses for VM vendor prefixes."""
        score = 0.0
        matches = []
        vm_mac_vendors = self.signatures.get("vm_indicators", {}).get("mac_vendors", [])
        
        for mac in mac_addresses:
            mac_lower = mac.lower().replace(":", "-")
            for vendor in vm_mac_vendors:
                vendor_normalized = vendor.lower().replace(":", "-")
                if mac_lower.startswith(vendor_normalized):
                    score += self.weights.get("mac_match", 0.3)
                    matches.append(f"MAC: {mac} matches VM vendor {vendor}")
        
        return min(score, 1.0), matches
    
    def _check_processes(self, processes: List[str], process_list: List[str]) -> Tuple[float, List[str]]:
        """Check running processes against suspicious process list."""
        score = 0.0
        matches = []
        
        process_set = set(process_list)
        for proc in processes:
            if proc in process_set:
                score += self.weights.get("process_match", 0.25)
                matches.append(f"Process: {proc} is running")
        
        return min(score, 1.0), matches
    
    def _check_ports(self, listening_ports: List[int]) -> Tuple[float, List[str]]:
        """Check listening ports for remote access ports."""
        score = 0.0
        matches = []
        remote_ports = self.signatures.get("remote_indicators", {}).get("ports", [])
        
        port_set = set(listening_ports)
        for port in remote_ports:
            if port in port_set:
                score += self.weights.get("port_match", 0.15)
                matches.append(f"Port: {port} is listening (remote access port)")
        
        return min(score, 1.0), matches
    
    def _check_session(self, session_data: Dict) -> Tuple[float, List[str]]:
        """Check session info for remote access indicators."""
        score = 0.0
        matches = []
        session_keywords = self.signatures.get("remote_indicators", {}).get("session_keywords", [])
        
        session_name = str(session_data.get("session_name", "")).lower()
        ssh_connection = session_data.get("ssh_connection", False)
        
        for keyword in session_keywords:
            if keyword in session_name:
                score += self.weights.get("session_match", 0.3)
                matches.append(f"Session: {session_name} matches remote session pattern")
        
        if ssh_connection:
            score += self.weights.get("session_match", 0.3)
            matches.append("Session: SSH connection detected")
        
        return min(score, 1.0), matches
    
    def _check_gpu_artifacts(self, gpu_data: Dict) -> Tuple[float, List[str]]:
        """Check GPU information for VM artifacts."""
        score = 0.0
        matches = []
        
        # VMs often have virtual GPUs or missing GPU drivers
        gpu_count = gpu_data.get("count", 0)
        gpu_devices = gpu_data.get("devices", [])
        
        # Check for virtual GPU names (strong indicator)
        vm_gpu_keywords = ["vmware", "virtualbox", "virtual", "qxl", "vbox", "cirrus"]
        for device in gpu_devices:
            device_name = str(device).lower()
            if isinstance(device, dict):
                device_name = str(device.get("name", "")).lower()
            for keyword in vm_gpu_keywords:
                if keyword in device_name:
                    score += self.weights.get("gpu_match", 0.15)
                    matches.append(f"GPU: {keyword} found in GPU name")
        
        # Only flag missing GPU drivers if we have NO GPU info at all (weaker indicator)
        # Don't flag if we just couldn't detect drivers - that's unreliable
        if platform.system().lower() == 'windows':
            nvidia_driver = gpu_data.get("nvidia_driver", False)
            amd_driver = gpu_data.get("amd_driver", False)
            intel_driver = gpu_data.get("intel_driver", False)
            gpu_processes = gpu_data.get("processes", [])
            # Only flag if absolutely no GPU indicators AND we have GPU process checking enabled
            # Make this even weaker - only flag if we're certain it's suspicious
            # Many physical machines don't expose GPU info properly
            if (not nvidia_driver and not amd_driver and not intel_driver and 
                gpu_count == 0 and len(gpu_processes) == 0 and len(gpu_devices) == 0):
                # Very weak indicator - reduce weight significantly (don't flag on physical machines)
                score += self.weights.get("gpu_match", 0.15) * 0.2  # Only 20% of weight (was 50%)
                matches.append("GPU: No GPU indicators detected (weak VM indicator)")
        
        return min(score, 1.0), matches
    
    def _check_timing_anomalies(self, timing_data: Dict) -> Tuple[float, List[str]]:
        """
        Check CPU timing for hypervisor artifacts.
        
        NOTE: Timing-based detection is unreliable on physical machines due to:
        - Background processes affecting CPU timing
        - Power management/throttling
        - OS scheduler interference
        - Measurement noise
        
        This method uses very conservative thresholds to minimize false positives.
        For production use, timing should only be used as a secondary confirmation
        when other indicators are already present.
        
        FUTURE IMPROVEMENTS:
        - Multiple measurement samples with statistical analysis
        - Pattern detection (consistent timing anomalies vs. random variance)
        - Comparison against baseline measurements
        - More sophisticated CPU feature detection (RDTSC, hypervisor bit, etc.)
        """
        score = 0.0
        matches = []
        
        # VMs often have higher timing variance, but this is a weak indicator
        variance = timing_data.get("variance", 0)
        std_dev = timing_data.get("std_dev", 0)
        avg_time = timing_data.get("avg_time", 0)
        min_time = timing_data.get("min_time", 0)
        max_time = timing_data.get("max_time", 0)
        
        # VERY conservative threshold - only flag extreme, consistent anomalies
        # Physical machines can show 200-300%+ variance due to background processes
        # Only flag if variance is extremely high AND we see consistent patterns
        if variance > 3.0 and avg_time > 0:  # Threshold: 300% variance (very conservative)
            # Additional check: verify it's not just measurement noise
            if min_time > 0 and max_time > 0:
                # Check if variance is consistent (not just a single outlier)
                time_range_ratio = (max_time - min_time) / avg_time if avg_time > 0 else 0
                if time_range_ratio > 2.5:  # Consistent high variance
                    score += self.weights.get("timing_match", 0.15) * 0.6  # Reduced weight
                    matches.append(f"Timing: Extremely high variance detected ({variance:.2%}) - possible VM")
        
        # Check for odd CPU counts (VMs often have unusual configurations)
        # This is more reliable than variance
        odd_cpu_count = timing_data.get("odd_cpu_count", False)
        cpu_count = timing_data.get("cpu_count", 0)
        if odd_cpu_count and cpu_count > 1:
            # Only flag if it's truly unusual (e.g., prime numbers > 1, or very small counts)
            # Skip common physical configurations like 1, 2, 4, 8 cores
            if cpu_count not in [1, 2, 4, 6, 8, 12, 16, 24, 32]:
                score += self.weights.get("timing_match", 0.15) * 0.5  # Reduced weight
                matches.append(f"Timing: Unusual CPU count detected ({cpu_count} cores) - possible VM")
        
        # Check CPU frequency (VMs often report fixed or unusual frequencies)
        # This is more reliable than variance
        cpu_freq = timing_data.get("cpu_freq_current", 0)
        cpu_freq_min = timing_data.get("cpu_freq_min", 0)
        cpu_freq_max = timing_data.get("cpu_freq_max", 0)
        if cpu_freq > 0 and cpu_freq_min > 0 and cpu_freq_max > 0:
            # If frequency range is very small, might be a VM
            freq_range = cpu_freq_max - cpu_freq_min
            if freq_range < 10:  # Less than 10 MHz range (very strict - VMs often fixed)
                score += self.weights.get("timing_match", 0.15) * 0.5  # Reduced weight
                matches.append(f"Timing: Fixed CPU frequency detected ({cpu_freq:.0f} MHz, range: {freq_range:.1f} MHz) - possible VM")
        
        return min(score, 1.0), matches
    
    def detect_vm(self, system_data: Dict) -> Tuple[float, List[str]]:
        """Detect if system is running in a virtual machine."""
        total_score = 0.0
        all_matches = []
        
        # Check BIOS keywords
        bios_score, bios_matches = self._check_bios_keywords(system_data.get("bios", {}))
        total_score += bios_score
        all_matches.extend(bios_matches)
        
        # Check MAC addresses
        mac_score, mac_matches = self._check_mac_addresses(
            system_data.get("network", {}).get("mac_addresses", [])
        )
        total_score += mac_score
        all_matches.extend(mac_matches)
        
        # Check VM processes
        vm_processes = self.signatures.get("vm_indicators", {}).get("processes", [])
        proc_score, proc_matches = self._check_processes(
            vm_processes,
            system_data.get("processes", [])
        )
        total_score += proc_score
        all_matches.extend(proc_matches)
        
        # Check GPU artifacts
        gpu_score, gpu_matches = self._check_gpu_artifacts(system_data.get("gpu", {}))
        total_score += gpu_score
        all_matches.extend(gpu_matches)
        
        # Check timing anomalies (only if other indicators suggest VM to reduce false positives)
        # Timing is unreliable alone, but can confirm other indicators
        if total_score > 0.2:  # Only check timing if we already have some VM indicators
            timing_score, timing_matches = self._check_timing_anomalies(system_data.get("timing", {}))
            total_score += timing_score
            all_matches.extend(timing_matches)
        # If no other indicators, skip timing check to avoid false positives
        
        return min(total_score, 1.0), all_matches
    
    def detect_remote_access(self, system_data: Dict) -> Tuple[float, List[str]]:
        """Detect if remote access software is active."""
        total_score = 0.0
        all_matches = []
        
        # Check remote access processes
        remote_processes = self.signatures.get("remote_indicators", {}).get("processes", [])
        proc_score, proc_matches = self._check_processes(
            remote_processes,
            system_data.get("processes", [])
        )
        total_score += proc_score
        all_matches.extend(proc_matches)
        
        # Check listening ports
        ports = system_data.get("network", {}).get("listening_ports", [])
        port_score, port_matches = self._check_ports(ports)
        total_score += port_score
        all_matches.extend(port_matches)
        
        # Check session info
        session_score, session_matches = self._check_session(system_data.get("session", {}))
        total_score += session_score
        all_matches.extend(session_matches)
        
        return min(total_score, 1.0), all_matches
    
    def detect_screen_share(self, system_data: Dict) -> Tuple[float, List[str]]:
        """Detect if screen sharing software is active."""
        screen_share_sigs = self.signatures.get("screen_share_indicators", {})
        screen_processes = screen_share_sigs.get("processes", [])
        
        # Check for dedicated screen sharing apps
        score, matches = self._check_processes(
            screen_processes,
            system_data.get("processes", [])
        )
        
        # Check for browsers (might be doing screen sharing)
        browser_processes = screen_share_sigs.get("browser_processes", [])
        found_browsers = set()  # Use set to deduplicate
        found_browser_screenshare = set()
        for process_name in system_data.get("processes", []):
            for browser in browser_processes:
                if browser.lower() == process_name:
                    found_browsers.add(browser.lower())
                elif f"{browser.lower()}_screenshare" == process_name:
                    found_browser_screenshare.add(browser.lower())
        
        # Check for active meeting connections (high connection count)
        browser_conns = system_data.get("browser_connections", {})
        active_meeting_browsers = browser_conns.get("active_meeting_browsers", [])
        detected_domains = browser_conns.get("detected_meeting_domains", [])
        connection_counts = browser_conns.get("browser_connection_counts", {})
        
        if active_meeting_browsers:
            # Medium confidence - browsers have high connection counts (could be meeting or heavy browsing)
            # Reduce weight since this can have false positives
            meeting_score = 0.25  # Reduced from 0.4 to account for false positives
            score += meeting_score
            for browser in active_meeting_browsers:
                conn_count = connection_counts.get(browser, 0)
                if detected_domains and "high_connection_count" in detected_domains:
                    matches.append(f"High connection count in {browser} ({conn_count} connections - possible meeting)")
                else:
                    matches.append(f"High connection count in {browser} ({conn_count} connections - possible meeting)")
        elif found_browser_screenshare:
            # Medium confidence - browser command line suggests meeting
            browser_score = 0.25 * len(found_browser_screenshare)
            score += min(browser_score, 0.35)
            for browser in found_browser_screenshare:
                matches.append(f"Browser meeting detected: {browser} (Google Meet/Zoom/etc)")
        elif found_browsers:
            # Lower confidence - browsers running but not confirmed meeting
            browser_score = 0.1 * len(found_browsers)  # Lower weight
            score += min(browser_score, 0.2)  # Cap at 0.2
            for browser in found_browsers:
                matches.append(f"Browser detected: {browser} (may indicate meeting/screen sharing)")
        
        return min(score, 1.0), matches
    
    def analyze(self, system_data: Dict = None) -> Dict:
        """Perform full analysis of system data."""
        if system_data is None:
            system_data = collect_all()
        
        vm_score, vm_matches = self.detect_vm(system_data)
        remote_score, remote_matches = self.detect_remote_access(system_data)
        screen_score, screen_matches = self.detect_screen_share(system_data)
        
        vm_threshold = self.thresholds.get("vm_confidence", 0.5)
        remote_threshold = self.thresholds.get("remote_confidence", 0.4)
        screen_threshold = self.thresholds.get("screen_share_confidence", 0.3)
        
        result = {
            "vm_detected": vm_score >= vm_threshold,
            "vm_confidence": vm_score,
            "vm_matches": vm_matches,
            "remote_access_detected": remote_score >= remote_threshold,
            "remote_access_confidence": remote_score,
            "remote_access_matches": remote_matches,
            "screen_share_detected": screen_score >= screen_threshold,
            "screen_share_confidence": screen_score,
            "screen_share_matches": screen_matches,
            "system_data": system_data
        }
        
        return result
    
    def format_report(self, result: Dict) -> str:
        """Format detection result as human-readable report."""
        lines = []
        lines.append("=" * 60)
        lines.append("VM & Remote Access Detection Report")
        lines.append("=" * 60)
        
        if result["vm_detected"]:
            lines.append(f"\n[ALERT] Virtual Machine Detected!")
            lines.append(f"Confidence: {result['vm_confidence']:.2%}")
            lines.append("Evidence:")
            for match in result["vm_matches"]:
                lines.append(f"  - {match}")
        else:
            lines.append(f"\n[OK] No VM detected (confidence: {result['vm_confidence']:.2%})")
        
        if result["remote_access_detected"]:
            lines.append(f"\n[ALERT] Remote Access Detected!")
            lines.append(f"Confidence: {result['remote_access_confidence']:.2%}")
            lines.append("Evidence:")
            for match in result["remote_access_matches"]:
                lines.append(f"  - {match}")
        else:
            lines.append(f"\n[OK] No remote access detected (confidence: {result['remote_access_confidence']:.2%})")
        
        if result["screen_share_detected"]:
            lines.append(f"\n[ALERT] Screen Sharing Detected!")
            lines.append(f"Confidence: {result['screen_share_confidence']:.2%}")
            lines.append("Evidence:")
            for match in result["screen_share_matches"]:
                lines.append(f"  - {match}")
        else:
            lines.append(f"\n[OK] No screen sharing detected (confidence: {result['screen_share_confidence']:.2%})")
        
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

if __name__ == "__main__":
    detector = VMRemoteDetector()
    result = detector.analyze()
    print(detector.format_report(result))

