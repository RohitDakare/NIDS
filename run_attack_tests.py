#!/usr/bin/env python3
"""
Run attack tests against the NIDS system
"""

import sys
import os
import time
import subprocess
import threading
from datetime import datetime

def run_nids_system():
    """Start the NIDS system"""
    print("Starting NIDS system...")
    try:
        # Start NIDS system in background
        process = subprocess.Popen([
            sys.executable, "-m", "app.main"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a bit for system to start
        time.sleep(10)
        
        return process
    except Exception as e:
        print(f"Error starting NIDS system: {e}")
        return None

def run_attack_generator(attack_type, duration):
    """Run attack generator"""
    print(f"Starting {attack_type} attack for {duration} seconds...")
    try:
        # Run attack generator
        result = subprocess.run([
            sys.executable, "generate_attack_traffic.py"
        ], input=f"{attack_type}\n{duration}\n", text=True, capture_output=True)
        
        print(f"Attack generator output: {result.stdout}")
        if result.stderr:
            print(f"Attack generator errors: {result.stderr}")
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error running attack generator: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints to check system status"""
    import requests
    
    try:
        # Test health endpoint
        response = requests.get("http://localhost:8000/api/v1/health")
        if response.status_code == 200:
            health_data = response.json()
            print(f"System health: {health_data.get('status')}")
            print(f"System running: {health_data.get('system_running')}")
            return True
        else:
            print(f"Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error testing API: {e}")
        return False

def main():
    """Main function to run attack tests"""
    print("NIDS Attack Testing")
    print("=" * 40)
    
    # Start NIDS system
    nids_process = run_nids_system()
    if not nids_process:
        print("Failed to start NIDS system")
        return
    
    try:
        # Test API connectivity
        if not test_api_endpoints():
            print("API not accessible, waiting...")
            time.sleep(5)
            if not test_api_endpoints():
                print("API still not accessible")
                return
        
        # Run attack tests
        attack_types = ["ddos", "port_scan", "brute_force", "syn_flood", "icmp_flood"]
        
        for attack_type in attack_types:
            print(f"\n{'='*50}")
            print(f"Testing {attack_type} attack")
            print(f"{'='*50}")
            
            # Run attack
            success = run_attack_generator(attack_type, 30)
            
            if success:
                print(f"{attack_type} attack completed successfully")
            else:
                print(f"{attack_type} attack failed")
            
            # Wait between attacks
            time.sleep(5)
        
        print(f"\n{'='*50}")
        print("All attack tests completed!")
        print(f"{'='*50}")
        
    except KeyboardInterrupt:
        print("\nTesting interrupted by user")
    except Exception as e:
        print(f"Error during testing: {e}")
    finally:
        # Cleanup
        if nids_process:
            print("Stopping NIDS system...")
            nids_process.terminate()
            nids_process.wait()

if __name__ == "__main__":
    main()
