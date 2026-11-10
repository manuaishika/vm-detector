#!/usr/bin/env python3
"""
Web Dashboard for VM & Remote Access Detection System.
Real-time visualization and monitoring.
"""

from flask import Flask, render_template_string, jsonify
from detector import VMRemoteDetector
from behavioral_analyzer import BehavioralAnalyzer
from collector import collect_all
import json
import threading
import time

app = Flask(__name__)
detector = VMRemoteDetector()
behavioral_analyzer = BehavioralAnalyzer()

# Store latest detection results
latest_result = None
latest_result_lock = threading.Lock()

def update_detection():
    """Continuously update detection results."""
    global latest_result
    while True:
        try:
            result = detector.analyze()
            behavioral_analyzer.add_detection(result)
            
            with latest_result_lock:
                latest_result = result
            
            time.sleep(5)  # Update every 5 seconds
        except Exception as e:
            print(f"Error in update_detection: {e}")
            time.sleep(5)

# Start background thread for continuous detection
detection_thread = threading.Thread(target=update_detection, daemon=True)
detection_thread.start()

# HTML template for dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VM & Remote Access Detection Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 30px;
        }
        
        h1 {
            color: #667eea;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .status-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #667eea;
        }
        
        .status-card.alert {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .status-card.ok {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        
        .status-card h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 18px;
        }
        
        .status-card .confidence {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        
        .status-card.alert .confidence {
            color: #dc3545;
        }
        
        .status-card.ok .confidence {
            color: #28a745;
        }
        
        .status-card .status {
            margin-top: 10px;
            font-size: 14px;
            color: #666;
        }
        
        .evidence {
            margin-top: 20px;
        }
        
        .evidence h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .evidence ul {
            list-style: none;
            padding: 0;
        }
        
        .evidence li {
            background: #f8f9fa;
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }
        
        .evidence li.alert {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .stats {
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .stats h3 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .stat-item {
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        
        .stat-item .label {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .stat-item .value {
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
        }
        
        .refresh-info {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 VM & Remote Access Detection Dashboard</h1>
        
        <div id="dashboard-content">
            <div class="loading">Loading detection results...</div>
        </div>
    </div>
    
    <script>
        function updateDashboard() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const content = document.getElementById('dashboard-content');
                    let html = '<div class="status-grid">';
                    
                    // VM Detection
                    html += `<div class="status-card ${data.vm_detected ? 'alert' : 'ok'}">
                        <h3>Virtual Machine Detection</h3>
                        <div class="confidence">${(data.vm_confidence * 100).toFixed(1)}%</div>
                        <div class="status">${data.vm_detected ? '⚠️ VM Detected' : '✅ No VM Detected'}</div>
                    </div>`;
                    
                    // Remote Access Detection
                    html += `<div class="status-card ${data.remote_access_detected ? 'alert' : 'ok'}">
                        <h3>Remote Access Detection</h3>
                        <div class="confidence">${(data.remote_access_confidence * 100).toFixed(1)}%</div>
                        <div class="status">${data.remote_access_detected ? '⚠️ Remote Access Detected' : '✅ No Remote Access'}</div>
                    </div>`;
                    
                    // Screen Share Detection
                    html += `<div class="status-card ${data.screen_share_detected ? 'alert' : 'ok'}">
                        <h3>Screen Share Detection</h3>
                        <div class="confidence">${(data.screen_share_confidence * 100).toFixed(1)}%</div>
                        <div class="status">${data.screen_share_detected ? '⚠️ Screen Sharing Detected' : '✅ No Screen Sharing'}</div>
                    </div>`;
                    
                    html += '</div>';
                    
                    // Evidence
                    if (data.vm_matches.length > 0 || data.remote_access_matches.length > 0 || data.screen_share_matches.length > 0) {
                        html += '<div class="evidence">';
                        html += '<h3>Evidence</h3>';
                        html += '<ul>';
                        
                        if (data.vm_matches.length > 0) {
                            data.vm_matches.forEach(match => {
                                html += `<li class="alert">🔴 ${match}</li>`;
                            });
                        }
                        
                        if (data.remote_access_matches.length > 0) {
                            data.remote_access_matches.forEach(match => {
                                html += `<li class="alert">🔴 ${match}</li>`;
                            });
                        }
                        
                        if (data.screen_share_matches.length > 0) {
                            data.screen_share_matches.forEach(match => {
                                html += `<li class="alert">🔴 ${match}</li>`;
                            });
                        }
                        
                        html += '</ul>';
                        html += '</div>';
                    }
                    
                    // Statistics
                    if (data.stats) {
                        html += '<div class="stats">';
                        html += '<h3>Detection Statistics</h3>';
                        html += '<div class="stats-grid">';
                        html += `<div class="stat-item">
                            <div class="label">Total Detections</div>
                            <div class="value">${data.stats.total_detections}</div>
                        </div>`;
                        html += `<div class="stat-item">
                            <div class="label">VM Detections</div>
                            <div class="value">${data.stats.vm_detections}</div>
                        </div>`;
                        html += `<div class="stat-item">
                            <div class="label">Remote Access</div>
                            <div class="value">${data.stats.remote_detections}</div>
                        </div>`;
                        html += `<div class="stat-item">
                            <div class="label">Screen Sharing</div>
                            <div class="value">${data.screen_share_detections}</div>
                        </div>`;
                        html += '</div>';
                        html += '</div>';
                    }
                    
                    html += '<div class="refresh-info">🔄 Auto-refreshing every 5 seconds</div>';
                    
                    content.innerHTML = html;
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('dashboard-content').innerHTML = 
                        '<div class="loading">Error loading detection results. Please refresh.</div>';
                });
        }
        
        // Update dashboard immediately and then every 5 seconds
        updateDashboard();
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/status')
def api_status():
    """API endpoint for detection status."""
    with latest_result_lock:
        if latest_result is None:
            # Return initial result if available
            result = detector.analyze()
            behavioral_analyzer.add_detection(result)
            latest_result = result
        
        # Get statistics
        stats = behavioral_analyzer.get_statistics()
        
        return jsonify({
            'vm_detected': latest_result.get('vm_detected', False),
            'vm_confidence': latest_result.get('vm_confidence', 0.0),
            'vm_matches': latest_result.get('vm_matches', []),
            'remote_access_detected': latest_result.get('remote_access_detected', False),
            'remote_access_confidence': latest_result.get('remote_access_confidence', 0.0),
            'remote_access_matches': latest_result.get('remote_access_matches', []),
            'screen_share_detected': latest_result.get('screen_share_detected', False),
            'screen_share_confidence': latest_result.get('screen_share_confidence', 0.0),
            'screen_share_matches': latest_result.get('screen_share_matches', []),
            'stats': stats
        })

@app.route('/api/analyze')
def api_analyze():
    """API endpoint for manual analysis."""
    result = detector.analyze()
    behavioral_analyzer.add_detection(result)
    return jsonify(result)

@app.route('/api/behavioral')
def api_behavioral():
    """API endpoint for behavioral analysis."""
    patterns = behavioral_analyzer.analyze_patterns()
    stats = behavioral_analyzer.get_statistics()
    return jsonify({
        'patterns': patterns,
        'stats': stats
    })

if __name__ == '__main__':
    print("Starting VM & Remote Access Detection Dashboard...")
    print("Dashboard available at: http://localhost:5000")
    print("API endpoints:")
    print("  - GET /api/status - Get current detection status")
    print("  - GET /api/analyze - Run manual analysis")
    print("  - GET /api/behavioral - Get behavioral analysis")
    app.run(debug=True, host='0.0.0.0', port=5000)



