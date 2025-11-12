import json
import os
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
        screen_processes = self.signatures.get("screen_share_indicators", {}).get("processes", [])
        score, matches = self._check_processes(
            screen_processes,
            system_data.get("processes", [])
        )
        return score, matches
    
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

