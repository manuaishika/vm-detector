import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque
from detector import VMRemoteDetector
from collector import collect_all

class BehavioralAnalyzer:
    """Analyzes system behavior over time to detect anomalies."""
    
    def __init__(self, history_file: str = "behavior_history.json", max_history: int = 100):
        """Initialize behavioral analyzer with history file."""
        self.history_file = history_file
        self.max_history = max_history
        self.history = self._load_history()
        self.detector = VMRemoteDetector()
    
    def _load_history(self) -> List[Dict]:
        """Load detection history from file."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data[-self.max_history:]  # Keep only recent history
                    return []
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def _save_history(self):
        """Save detection history to file."""
        try:
            # Keep only recent history
            self.history = self.history[-self.max_history:]
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2, default=str)
        except IOError:
            pass
    
    def add_detection(self, detection_result: Dict):
        """Add a detection result to history."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'vm_detected': detection_result.get('vm_detected', False),
            'vm_confidence': detection_result.get('vm_confidence', 0.0),
            'remote_access_detected': detection_result.get('remote_access_detected', False),
            'remote_access_confidence': detection_result.get('remote_access_confidence', 0.0),
            'screen_share_detected': detection_result.get('screen_share_detected', False),
            'screen_share_confidence': detection_result.get('screen_share_confidence', 0.0),
            'metrics': detection_result.get('system_data', {}).get('metrics', {})
        }
        self.history.append(entry)
        self._save_history()
    
    def analyze_patterns(self) -> Dict:
        """Analyze patterns in detection history."""
        if len(self.history) < 2:
            return {
                'sufficient_data': False,
                'message': 'Not enough history data for pattern analysis'
            }
        
        analysis = {
            'sufficient_data': True,
            'total_detections': len(self.history),
            'vm_detections': sum(1 for h in self.history if h.get('vm_detected', False)),
            'remote_detections': sum(1 for h in self.history if h.get('remote_access_detected', False)),
            'screen_share_detections': sum(1 for h in self.history if h.get('screen_share_detected', False)),
            'anomalies': []
        }
        
        # Calculate average confidence scores
        vm_confidences = [h.get('vm_confidence', 0.0) for h in self.history]
        remote_confidences = [h.get('remote_access_confidence', 0.0) for h in self.history]
        screen_confidences = [h.get('screen_share_confidence', 0.0) for h in self.history]
        
        analysis['avg_vm_confidence'] = sum(vm_confidences) / len(vm_confidences) if vm_confidences else 0.0
        analysis['avg_remote_confidence'] = sum(remote_confidences) / len(remote_confidences) if remote_confidences else 0.0
        analysis['avg_screen_share_confidence'] = sum(screen_confidences) / len(screen_confidences) if screen_confidences else 0.0
        
        # Detect anomalies
        # 1. Sudden changes in detection
        if len(self.history) >= 2:
            recent = self.history[-1]
            previous = self.history[-2]
            
            # Check for sudden VM detection
            if not previous.get('vm_detected', False) and recent.get('vm_detected', False):
                analysis['anomalies'].append({
                    'type': 'sudden_vm_detection',
                    'timestamp': recent.get('timestamp'),
                    'confidence': recent.get('vm_confidence', 0.0),
                    'message': 'VM suddenly detected after being clean'
                })
            
            # Check for sudden remote access
            if not previous.get('remote_access_detected', False) and recent.get('remote_access_detected', False):
                analysis['anomalies'].append({
                    'type': 'sudden_remote_access',
                    'timestamp': recent.get('timestamp'),
                    'confidence': recent.get('remote_access_confidence', 0.0),
                    'message': 'Remote access suddenly detected'
                })
            
            # Check for sudden screen sharing
            if not previous.get('screen_share_detected', False) and recent.get('screen_share_detected', False):
                analysis['anomalies'].append({
                    'type': 'sudden_screen_share',
                    'timestamp': recent.get('timestamp'),
                    'confidence': recent.get('screen_share_confidence', 0.0),
                    'message': 'Screen sharing suddenly detected'
                })
        
        # 2. Check for consistent high confidence
        high_vm_confidence_count = sum(1 for c in vm_confidences if c > 0.7)
        if high_vm_confidence_count > len(self.history) * 0.8:  # 80% of detections
            analysis['anomalies'].append({
                'type': 'consistent_vm_high_confidence',
                'count': high_vm_confidence_count,
                'percentage': (high_vm_confidence_count / len(self.history)) * 100,
                'message': f'Consistent high VM confidence ({high_vm_confidence_count}/{len(self.history)} detections)'
            })
        
        # 3. Check for metric anomalies
        if len(self.history) >= 5:
            recent_metrics = [h.get('metrics', {}) for h in self.history[-5:]]
            cpu_percentages = [m.get('cpu_percent', 0) for m in recent_metrics if m.get('cpu_percent')]
            memory_percentages = [m.get('memory_percent', 0) for m in recent_metrics if m.get('memory_percent')]
            
            if cpu_percentages:
                avg_cpu = sum(cpu_percentages) / len(cpu_percentages)
                if avg_cpu > 90:  # High CPU usage
                    analysis['anomalies'].append({
                        'type': 'high_cpu_usage',
                        'average': avg_cpu,
                        'message': f'High average CPU usage: {avg_cpu:.1f}%'
                    })
            
            if memory_percentages:
                avg_memory = sum(memory_percentages) / len(memory_percentages)
                if avg_memory > 90:  # High memory usage
                    analysis['anomalies'].append({
                        'type': 'high_memory_usage',
                        'average': avg_memory,
                        'message': f'High average memory usage: {avg_memory:.1f}%'
                    })
        
        return analysis
    
    def get_statistics(self) -> Dict:
        """Get statistics from detection history."""
        if not self.history:
            return {
                'total_detections': 0,
                'message': 'No history data available'
            }
        
        stats = {
            'total_detections': len(self.history),
            'vm_detections': sum(1 for h in self.history if h.get('vm_detected', False)),
            'remote_detections': sum(1 for h in self.history if h.get('remote_access_detected', False)),
            'screen_share_detections': sum(1 for h in self.history if h.get('screen_share_detected', False)),
            'vm_detection_rate': (sum(1 for h in self.history if h.get('vm_detected', False)) / len(self.history)) * 100,
            'remote_detection_rate': (sum(1 for h in self.history if h.get('remote_access_detected', False)) / len(self.history)) * 100,
            'screen_share_detection_rate': (sum(1 for h in self.history if h.get('screen_share_detected', False)) / len(self.history)) * 100,
        }
        
        # Get time range
        if self.history:
            stats['first_detection'] = self.history[0].get('timestamp')
            stats['last_detection'] = self.history[-1].get('timestamp')
        
        return stats
    
    def clear_history(self):
        """Clear detection history."""
        self.history = []
        self._save_history()

if __name__ == "__main__":
    analyzer = BehavioralAnalyzer()
    
    # Run detection
    result = analyzer.detector.analyze()
    analyzer.add_detection(result)
    
    # Analyze patterns
    patterns = analyzer.analyze_patterns()
    print(json.dumps(patterns, indent=2))
    
    # Get statistics
    stats = analyzer.get_statistics()
    print("\nStatistics:")
    print(json.dumps(stats, indent=2))


