#!/usr/bin/env python3
"""
Quick system test - verifies all components are working.
"""

import sys
import traceback

def test_imports():
    """Test if all modules can be imported."""
    print("="*60)
    print("Testing Module Imports...")
    print("="*60)
    
    modules = ['collector', 'detector', 'behavioral_analyzer']
    failed = []
    
    for module in modules:
        try:
            __import__(module)
            print(f"✅ {module}.py - OK")
        except Exception as e:
            print(f"❌ {module}.py - FAILED: {e}")
            failed.append(module)
    
    return len(failed) == 0

def test_collector():
    """Test data collection."""
    print("\n" + "="*60)
    print("Testing Data Collection...")
    print("="*60)
    
    try:
        from collector import collect_all
        data = collect_all()
        
        checks = {
            'processes': len(data.get('processes', [])) > 0,
            'network': 'network' in data,
            'session': 'session' in data,
            'bios': 'bios' in data,
            'gpu': 'gpu' in data,
            'timing': 'timing' in data,
            'metrics': 'metrics' in data
        }
        
        for check, passed in checks.items():
            status = "✅" if passed else "⚠️"
            print(f"{status} {check.capitalize()} data collection")
        
        return all(checks.values())
    except Exception as e:
        print(f"❌ Data collection failed: {e}")
        traceback.print_exc()
        return False

def test_detector():
    """Test detection engine."""
    print("\n" + "="*60)
    print("Testing Detection Engine...")
    print("="*60)
    
    try:
        from detector import VMRemoteDetector
        detector = VMRemoteDetector()
        result = detector.analyze()
        
        required_keys = [
            'vm_detected', 'vm_confidence', 'vm_matches',
            'remote_access_detected', 'remote_access_confidence',
            'screen_share_detected', 'screen_share_confidence'
        ]
        
        all_present = all(key in result for key in required_keys)
        
        if all_present:
            print("✅ Detection engine working")
            print(f"   VM confidence: {result['vm_confidence']:.2%}")
            print(f"   Remote confidence: {result['remote_access_confidence']:.2%}")
            print(f"   Screen share confidence: {result['screen_share_confidence']:.2%}")
            return True
        else:
            print("❌ Missing required keys in result")
            return False
    except Exception as e:
        print(f"❌ Detection engine failed: {e}")
        traceback.print_exc()
        return False

def test_behavioral_analyzer():
    """Test behavioral analysis."""
    print("\n" + "="*60)
    print("Testing Behavioral Analyzer...")
    print("="*60)
    
    try:
        from behavioral_analyzer import BehavioralAnalyzer
        analyzer = BehavioralAnalyzer()
        stats = analyzer.get_statistics()
        
        if 'total_detections' in stats:
            print("✅ Behavioral analyzer working")
            print(f"   Total detections: {stats['total_detections']}")
            return True
        else:
            print("❌ Behavioral analyzer failed")
            return False
    except Exception as e:
        print(f"❌ Behavioral analyzer failed: {e}")
        return False

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("VM & Remote Access Detection System - Health Check")
    print("="*60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Collector", test_collector()))
    results.append(("Detector", test_detector()))
    results.append(("Behavioral Analyzer", test_behavioral_analyzer()))
    
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 ALL TESTS PASSED - System is operational!")
        print("="*60)
        return 0
    else:
        print("⚠️  SOME TESTS FAILED - Check errors above")
        print("="*60)
        return 1

if __name__ == "__main__":
    sys.exit(main())

