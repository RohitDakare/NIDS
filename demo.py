#!/usr/bin/env python3
"""
NIDS Demo Script

This script demonstrates the capabilities of the AI-based NIDS system
by making API calls and showing various features.
"""

import requests
import json
import time
import sys
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("API_KEY")
HEADERS = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else {}

# API base URL
BASE_URL = "http://localhost:8000/api/v1"

def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_section(title):
    """Print a formatted section"""
    print(f"\n{'-'*40}")
    print(f"  {title}")
    print(f"{'-'*40}")

def make_request(method, endpoint, data=None, params=None, base_url=None):
    if base_url is None:
        base_url = BASE_URL
    url = f"{base_url}{endpoint}"
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params, headers=HEADERS)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=HEADERS)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=HEADERS)
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
        print("Make sure the NIDS application is running on localhost:8000")
        return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def demo_system_info():
    """Demo system information endpoints"""
    print_header("SYSTEM INFORMATION")
    
    # Get root info
    print_section("Root Endpoint")
    result = make_request("GET", "/", base_url="http://localhost:8000")
    if result:
        print(f"System: {result.get('message')}")
        print(f"Version: {result.get('version')}")
        print(f"Status: {result.get('status')}")
    
    # Get system info
    print_section("System Info")
    result = make_request("GET", "/info", base_url="http://localhost:8000")
    if result:
        print(f"System: {result.get('system')}")
        print(f"Description: {result.get('description')}")
        print(f"Features: {', '.join(result.get('features', []))}")

def demo_health_check():
    """Demo health check endpoint"""
    print_header("HEALTH CHECK")
    
    result = make_request("GET", "/health")
    if result:
        status = result.get('status', 'unknown')
        system_running = result.get('system_running', False)
        component_health = result.get('component_health', {})
        
        print(f"Overall Status: {status}")
        print(f"System Running: {system_running}")
        print("Component Health:")
        for component, healthy in component_health.items():
            status_icon = "OK" if healthy else "FAIL"
            print(f"   {status_icon} {component}: {'Healthy' if healthy else 'Unhealthy'}")

def demo_system_status():
    """Demo system status endpoint"""
    print_header("SYSTEM STATUS")
    
    result = make_request("GET", "/status")
    if result:
        print(f"Running: {result.get('is_running')}")
        print(f"Uptime: {result.get('uptime', 0):.2f} seconds")
        print(f"Packets Captured: {result.get('packets_captured', 0)}")
        print(f"Alerts Generated: {result.get('alerts_generated', 0)}")
        print(f"ML Predictions: {result.get('ml_predictions', 0)}")
        print(f"Signature Matches: {result.get('signature_matches', 0)}")
        print(f"Memory Usage: {result.get('memory_usage', 0):.1f}%")
        print(f"CPU Usage: {result.get('cpu_usage', 0):.1f}%")

def demo_start_sniffer():
    """Demo starting the packet sniffer"""
    print_header("STARTING PACKET SNIFFER")
    
    # Configuration for demo
    config = {
        "interface": "Wi-Fi",  # Use loopback for demo
        "packet_count": 100,
        "timeout": 30
    }
    
    data = {"config": config}
    
    result = make_request("POST", "/start-sniffer", data=data)
    if result:
        print(f"Status: {result.get('status')}")
        print(f"Message: {result.get('message')}")
        
        system_status = result.get('system_status', {})
        if system_status:
            print(f"System Running: {system_status.get('is_running')}")
            print(f"Packets Captured: {system_status.get('packets_captured')}")
    else:
        print("Failed to start sniffer")

def demo_get_packets():
    """Demo getting captured packets"""
    print_header("CAPTURED PACKETS")
    
    result = make_request("GET", "/packets", params={"limit": 10})
    if result:
        packets = result.get('packets', [])
        total_count = result.get('total_count', 0)
        
        print(f"Total Packets: {total_count}")
        print(f"Showing: {len(packets)} packets")
        
        for i, packet in enumerate(packets[:5], 1):  # Show first 5 packets
            print(f"\nPacket {i}:")
            print(f"   Source: {packet.get('source_ip')}:{packet.get('source_port', 'N/A')}")
            print(f"   Destination: {packet.get('dest_ip')}:{packet.get('dest_port', 'N/A')}")
            print(f"   Protocol: {packet.get('protocol')}")
            print(f"   Length: {packet.get('packet_length')} bytes")
            print(f"   Timestamp: {packet.get('timestamp')}")

def demo_get_alerts():
    """Demo getting alerts"""
    print_header("SYSTEM ALERTS")
    
    result = make_request("GET", "/alerts", params={"limit": 10})
    if result:
        alerts = result.get('alerts', [])
        total_count = result.get('total_count', 0)
        
        print(f"Total Alerts: {total_count}")
        print(f"Showing: {len(alerts)} alerts")
        
        for i, alert in enumerate(alerts[:3], 1):  # Show first 3 alerts
            print(f"\nAlert {i}:")
            print(f"   ID: {alert.get('id')}")
            print(f"   Severity: {alert.get('severity')}")
            print(f"   Type: {alert.get('detection_type')}")
            print(f"   Description: {alert.get('description')}")
            print(f"   Source: {alert.get('source_ip')}")
            print(f"   Destination: {alert.get('dest_ip')}")
            print(f"   Confidence: {alert.get('confidence_score', 'N/A')}")
            print(f"   Resolved: {alert.get('is_resolved')}")

def demo_get_stats():
    """Demo getting detailed statistics"""
    print_header("DETAILED STATISTICS")
    
    result = make_request("GET", "/stats")
    if result:
        system_status = result.get('system_status', {})
        ml_stats = result.get('ml_stats', {})
        signature_stats = result.get('signature_stats', {})
        alert_stats = result.get('alert_stats', {})
        detection_rates = result.get('detection_rates', {})
        
        print("System Status:")
        print(f"   Running: {system_status.get('is_running')}")
        print(f"   Uptime: {system_status.get('uptime', 0):.2f} seconds")
        
        print("\nML Statistics:")
        print(f"   Model Loaded: {ml_stats.get('is_loaded')}")
        print(f"   Model Type: {ml_stats.get('model_type')}")
        print(f"   Predictions: {ml_stats.get('predictions_count', 0)}")
        print(f"   Anomalies Detected: {ml_stats.get('anomalies_detected', 0)}")
        print(f"   Detection Rate: {ml_stats.get('detection_rate', 0):.2%}")
        
        print("\nSignature Statistics:")
        print(f"   Total Rules: {signature_stats.get('total_rules', 0)}")
        print(f"   Enabled Rules: {signature_stats.get('enabled_rules', 0)}")
        print(f"   Matches: {signature_stats.get('matches_count', 0)}")
        
        print("\nDetection Rates:")
        print(f"   ML Detection Rate: {detection_rates.get('ml_detection_rate', 0):.2%}")
        print(f"   Signature Detection Rate: {detection_rates.get('signature_detection_rate', 0):.2%}")
        print(f"   Overall Detection Rate: {detection_rates.get('overall_detection_rate', 0):.2%}")

def demo_signature_rules():
    """Demo signature rules management"""
    print_header("SIGNATURE RULES")
    
    result = make_request("GET", "/signature-rules")
    if result:
        print(f"Total Rules: {len(result)}")
        
        for rule in result[:5]:  # Show first 5 rules
            print(f"\nRule: {rule.get('id')}")
            print(f"   Name: {rule.get('name')}")
            print(f"   Enabled: {rule.get('enabled')}")
            print(f"   Severity: {rule.get('severity')}")
            print(f"   Matches: {rule.get('matches_count', 0)}")
            print(f"   Last Match: {rule.get('last_match', 'Never')}")

def demo_correlation_analysis():
    """Demo correlation analysis"""
    print_header("CORRELATION ANALYSIS")
    
    result = make_request("GET", "/correlation")
    if result:
        total_correlations = result.get('total_correlations', 0)
        correlations = result.get('correlations', [])
        
        print(f"Total Correlations: {total_correlations}")
        
        for correlation in correlations[:3]:  # Show first 3 correlations
            print(f"\nCorrelation for {correlation.get('source_ip')}:")
            print(f"   Alert Count: {correlation.get('alert_count')}")
            print(f"   Time Span: {correlation.get('time_span_minutes', 0):.1f} minutes")
            print(f"   First Seen: {correlation.get('first_seen')}")
            print(f"   Last Seen: {correlation.get('last_seen')}")

def demo_stop_sniffer():
    """Demo stopping the packet sniffer"""
    print_header("STOPPING PACKET SNIFFER")
    
    result = make_request("POST", "/stop-sniffer", data={})
    if result:
        print(f"Status: {result.get('status')}")
        print(f"Message: {result.get('message')}")
        
        system_status = result.get('system_status', {})
        if system_status:
            print(f"System Running: {system_status.get('is_running')}")
    else:
        print("Failed to stop sniffer")

def demo_export_alerts():
    """Demo exporting alerts"""
    print_header("EXPORTING ALERTS")
    
    # Export as JSON
    result = make_request("GET", "/export/alerts", params={"format": "json"})
    if result:
        print(f"Format: {result.get('format')}")
        print(f"Message: {result.get('message')}")
        
        # Show a sample of exported data
        data = result.get('data', '')
        if data:
            try:
                alerts_data = json.loads(data)
                print(f"Exported {len(alerts_data)} alerts")
                if alerts_data:
                    print(f"Sample alert ID: {alerts_data[0].get('id', 'N/A')}")
            except json.JSONDecodeError:
                print("Data exported (JSON format)")

def main():
    """Main demo function"""
    print("NIDS Demo - AI-Based Network Intrusion Detection System")
    print("=" * 70)
    print("This demo showcases the capabilities of the NIDS system")
    print("Make sure the NIDS application is running on localhost:8000")
    print("=" * 70)
    
    # Check if API is accessible
    print("\nChecking API connectivity...")
    health_result = make_request("GET", "/health")
    if not health_result:
        print("Cannot connect to NIDS API. Please start the application first.")
        print("Run: python run.py")
        sys.exit(1)
    
    print("API is accessible!")
    
    # Run demos
    try:
        demo_system_info()
        demo_health_check()
        demo_system_status()
        
        # Start sniffer and capture some traffic
        demo_start_sniffer()
        
        print("\nWaiting for packets to be captured...")
        time.sleep(5)  # Wait for some packets to be captured
        
        demo_get_packets()
        demo_get_alerts()
        demo_get_stats()
        demo_signature_rules()
        demo_correlation_analysis()
        demo_export_alerts()
        
        # Stop sniffer
        demo_stop_sniffer()
        
        print_header("DEMO COMPLETED")
        print("All demos completed successfully!")
        print("\nNext steps:")
        print("   - Explore the API documentation at http://localhost:8000/docs")
        print("   - Try different network interfaces")
        print("   - Configure ML models and signature rules")
        print("   - Monitor real network traffic")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        demo_stop_sniffer()
    except Exception as e:
        print(f"\nDemo failed: {e}")
        demo_stop_sniffer()

if __name__ == "__main__":
    main() 