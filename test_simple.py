#!/usr/bin/env python3
"""
Simple test for NIDS packet sniffer start/stop functionality
"""

import requests
import json
import time
import sys

# API base URL
BASE_URL = "http://localhost:8000/api/v1"

def test_health():
    """Test health check"""
    print("Testing health check...")
    
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            result = response.json()
            print(f"Status: {result.get('status')}")
            print(f"System Running: {result.get('system_running')}")
            return True
        else:
            print(f"Error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"Request failed: {e}")
        return False

def test_start_system():
    """Test starting the NIDS system"""
    print("Testing start system...")
    
    # Try to start with a simple config
    config = {
        "interface": "Wi-Fi",
        "packet_count": 20,
        "timeout": 30
    }
    
    data = {"config": config}
    
    try:
        # Try without authentication first
        response = requests.post(f"{BASE_URL}/start-sniffer", json=data)
        print(f"Response status: {response.status_code}")
        print(f"Response text: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Status: {result.get('status')}")
            print(f"Message: {result.get('message')}")
            return True
        elif response.status_code == 401:
            print("Authentication required. Trying with default API key...")
            # Try with default API key
            headers = {"Authorization": "Bearer change-me"}
            response = requests.post(f"{BASE_URL}/start-sniffer", json=data, headers=headers)
            print(f"Response status: {response.status_code}")
            print(f"Response text: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Status: {result.get('status')}")
                print(f"Message: {result.get('message')}")
                return True
        
        return False
    except Exception as e:
        print(f"Request failed: {e}")
        return False

def test_status():
    """Test getting system status"""
    print("Testing system status...")
    
    try:
        response = requests.get(f"{BASE_URL}/status")
        if response.status_code == 200:
            result = response.json()
            print(f"Running: {result.get('is_running')}")
            print(f"Packets Captured: {result.get('packets_captured')}")
            print(f"Uptime: {result.get('uptime', 0):.2f} seconds")
            return True
        else:
            print(f"Error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"Request failed: {e}")
        return False

def test_stop_system():
    """Test stopping the NIDS system"""
    print("Testing stop system...")
    
    try:
        # Try without authentication first
        response = requests.post(f"{BASE_URL}/stop-sniffer", json={})
        print(f"Response status: {response.status_code}")
        print(f"Response text: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Status: {result.get('status')}")
            print(f"Message: {result.get('message')}")
            return True
        elif response.status_code == 401:
            print("Authentication required. Trying with default API key...")
            # Try with default API key
            headers = {"Authorization": "Bearer change-me"}
            response = requests.post(f"{BASE_URL}/stop-sniffer", json={}, headers=headers)
            print(f"Response status: {response.status_code}")
            print(f"Response text: {response.text}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"Status: {result.get('status')}")
                print(f"Message: {result.get('message')}")
                return True
        
        return False
    except Exception as e:
        print(f"Request failed: {e}")
        return False

def main():
    """Main test function"""
    print("NIDS Simple Test")
    print("=" * 50)
    
    # Test health first
    if not test_health():
        print("API is not accessible. Please start the NIDS application first.")
        return False
    
    print("\n" + "=" * 50)
    
    # Test start system
    if test_start_system():
        print("Start system test: PASSED")
    else:
        print("Start system test: FAILED")
        return False
    
    print("\n" + "=" * 50)
    
    # Wait a bit for packets to be captured
    print("Waiting for packets to be captured...")
    time.sleep(5)
    
    # Test status
    if test_status():
        print("Status test: PASSED")
    else:
        print("Status test: FAILED")
    
    print("\n" + "=" * 50)
    
    # Test stop system
    if test_stop_system():
        print("Stop system test: PASSED")
    else:
        print("Stop system test: FAILED")
        return False
    
    print("\n" + "=" * 50)
    print("All tests completed!")
    return True

if __name__ == "__main__":
    success = main()
    if success:
        print("SUCCESS: All tests passed!")
        sys.exit(0)
    else:
        print("FAILURE: Some tests failed!")
        sys.exit(1)
