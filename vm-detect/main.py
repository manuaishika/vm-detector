#!/usr/bin/env python3
"""
Main runner for VM & Remote Access Detection System.
Performs real-time monitoring and alerts on detection.
"""

import time
import json
import argparse
from datetime import datetime
from detector import VMRemoteDetector
from collector import collect_all

def monitor_continuous(interval: int = 5, output_file: str = None, quiet: bool = False):
    """Continuously monitor system and alert on detection."""
    detector = VMRemoteDetector()
    log_file = None
    
    if output_file:
        log_file = open(output_file, 'a')
        print(f"Logging to: {output_file}")
    
    print("Starting continuous monitoring...")
    print(f"Scan interval: {interval} seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Collect and analyze
            result = detector.analyze()
            
            # Check for alerts
            alerts = []
            if result["vm_detected"]:
                alerts.append(f"VM DETECTED (confidence: {result['vm_confidence']:.2%})")
            if result["remote_access_detected"]:
                alerts.append(f"REMOTE ACCESS DETECTED (confidence: {result['remote_access_confidence']:.2%})")
            if result["screen_share_detected"]:
                alerts.append(f"SCREEN SHARE DETECTED (confidence: {result['screen_share_confidence']:.2%})")
            if result.get("proxy_firewall_detected"):
                alerts.append(f"PROXY/FIREWALL/VPN DETECTED (confidence: {result.get('proxy_firewall_confidence', 0):.2%})")
            
            # Print alerts
            if alerts:
                print(f"\n[{timestamp}] ⚠️  ALERTS:")
                for alert in alerts:
                    print(f"  - {alert}")
                if not quiet:
                    print("\nDetails:")
                    if result["vm_matches"]:
                        print("  VM Evidence:")
                        for match in result["vm_matches"]:
                            print(f"    - {match}")
                    if result["remote_access_matches"]:
                        print("  Remote Access Evidence:")
                        for match in result["remote_access_matches"]:
                            print(f"    - {match}")
                    if result["screen_share_matches"]:
                        print("  Screen Share Evidence:")
                        for match in result["screen_share_matches"]:
                            print(f"    - {match}")
                    if result.get("proxy_firewall_matches"):
                        print("  Proxy/Firewall/VPN Evidence:")
                        for match in result.get("proxy_firewall_matches", []):
                            print(f"    - {match}")
                    print()  # Add blank line after details
            elif not quiet:
                print(f"[{timestamp}] ✓ No threats detected")
            
            # Log to file
            if log_file:
                log_entry = {
                    "timestamp": timestamp,
                    "vm_detected": result["vm_detected"],
                    "vm_confidence": result["vm_confidence"],
                    "remote_access_detected": result["remote_access_detected"],
                    "remote_access_confidence": result["remote_access_confidence"],
                    "screen_share_detected": result["screen_share_detected"],
                    "screen_share_confidence": result["screen_share_confidence"],
                    "proxy_firewall_detected": result.get("proxy_firewall_detected", False),
                    "proxy_firewall_confidence": result.get("proxy_firewall_confidence", 0),
                    "matches": {
                        "vm": result["vm_matches"],
                        "remote": result["remote_access_matches"],
                        "screen_share": result["screen_share_matches"],
                        "proxy_firewall": result.get("proxy_firewall_matches", [])
                    }
                }
                log_file.write(json.dumps(log_entry) + "\n")
                log_file.flush()
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n\nStopping monitoring...")
    finally:
        if log_file:
            log_file.close()
        print("Monitoring stopped.")

def run_once(output_format: str = "text", output_file: str = None):
    """Run detection once and output results."""
    detector = VMRemoteDetector()
    result = detector.analyze()
    
    if output_format == "json":
        output = json.dumps(result, indent=2, default=str)
    else:
        output = detector.format_report(result)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
        print(f"Results saved to: {output_file}")
    else:
        print(output)
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="VM & Remote Access Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run once and print report
  python main.py

  # Run once and save JSON
  python main.py --once --format json --output result.json

  # Monitor continuously every 5 seconds
  python main.py --monitor --interval 5

  # Monitor and log to file
  python main.py --monitor --interval 10 --log detection.log
        """
    )
    
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run detection once and exit"
    )
    
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Monitor continuously"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Monitoring interval in seconds (default: 5)"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="Output file path"
    )
    
    parser.add_argument(
        "--log",
        type=str,
        help="Log file for continuous monitoring"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Quiet mode (only show alerts)"
    )
    
    args = parser.parse_args()
    
    if args.monitor:
        monitor_continuous(
            interval=args.interval,
            output_file=args.log,
            quiet=args.quiet
        )
    else:
        run_once(
            output_format=args.format,
            output_file=args.output
        )

if __name__ == "__main__":
    main()

