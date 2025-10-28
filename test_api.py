#!/usr/bin/env python3
"""
Simple test script for NIDS API functionality
"""

import requests
import json
import time
import sys
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY", "change-me")  # Use default API key for testing
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

# API base URL
BASE_URL = "http://localhost:8000/api/v1"

def make_request(method, endpoint, data=None, params=None):
    url = f"{BASE_URL}{endpoint}"
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params, headers=HEADERS)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=HEADERS)
        else:
            print(f"Unsupported method: {method}")
            return None
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error {response.status_code}: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print(f"Cannot connect to NIDS API at {url}")
        return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def test_health_no_auth():
    """Test health check without authentication"""
    print("Testing health check (no auth)...")
    
    url = f"{BASE_URL}/health"
    try:
        response = requests.get(url)
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

def test_start_sniffer():
    """Test starting the packet sniffer"""
    print("Testing start sniffer...")
    
    config = {
        "interface": "Wi-Fi",
        "packet_count": 50,
        "timeout": 30
    }
    
    data = {"config": config}
    result = make_request("POST", "/start-sniffer", data=data)
    
    if result:
        print(f"Status: {result.get('status')}")
        print(f"Message: {result.get('message')}")
        return True
    else:
        print("Failed to start sniffer")
        return False

def test_stop_sniffer():
    """Test stopping the packet sniffer"""
    print("Testing stop sniffer...")
    
    result = make_request("POST", "/stop-sniffer", data={})
    
    if result:
        print(f"Status: {result.get('status')}")
        print(f"Message: {result.get('message')}")
        return True
    else:
        print("Failed to stop sniffer")
        return False

def test_status():
    """Test getting system status"""
    print("Testing system status...")
    
    result = make_request("GET", "/status")
    
    if result:
        print(f"Running: {result.get('is_running')}")
        print(f"Packets Captured: {result.get('packets_captured')}")
        print(f"Uptime: {result.get('uptime', 0):.2f} seconds")
        return True
    else:
        print("Failed to get status")
        return False

def test_health():
    """Test health check"""
    print("Testing health check...")
    
    result = make_request("GET", "/health")
    
    if result:
        print(f"Status: {result.get('status')}")
        print(f"System Running: {result.get('system_running')}")
        return True
    else:
        print("Failed to get health status")
        return False

def main():
    """Main test function"""
    print("NIDS API Test")
    print("=" * 40)
    
    # Test health first (no auth required)
    if not test_health_no_auth():
        print("API is not accessible. Please start the NIDS application first.")
        return False
    
    print("\n" + "=" * 40)
    
    # Test start sniffer
    if test_start_sniffer():
        print("Start sniffer test: PASSED")
    else:
        print("Start sniffer test: FAILED")
        return False
    
    print("\n" + "=" * 40)
    
    # Wait a bit for packets to be captured
    print("Waiting for packets to be captured...")
    time.sleep(5)
    
    # Test status
    if test_status():
        print("Status test: PASSED")
    else:
        print("Status test: FAILED")
    
    print("\n" + "=" * 40)
    
    # Test stop sniffer
    if test_stop_sniffer():
        print("Stop sniffer test: PASSED")
    else:
        print("Stop sniffer test: FAILED")
        return False
    
    print("\n" + "=" * 40)
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
