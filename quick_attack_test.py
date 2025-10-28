#!/usr/bin/env python3
"""
Quick attack test for NIDS system
"""

import sys
import os
import time
import json
from datetime import datetime

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.nids_orchestrator import NIDSOrchestrator
from app.models.schemas import SnifferConfig, MLModelConfig

def quick_test():
    """Run a quick attack test"""
    print("Quick NIDS Attack Test")
    print("=" * 40)
    
    # Create configurations
    sniffer_config = SnifferConfig(
        interface="Wi-Fi",
        packet_count=1000,
        timeout=60
    )
    
    ml_config = MLModelConfig(
        model_path="app/ml_models/nids_model.joblib",
        confidence_threshold=0.7
    )
    
    # Create orchestrator
    orchestrator = NIDSOrchestrator(
        sniffer_config=sniffer_config,
        ml_config=ml_config
    )
    
    print("Starting NIDS system...")
    success = orchestrator.start()
    
    if not success:
        print("Failed to start NIDS system!")
        return False
    
    print("NIDS system started successfully!")
    
    # Load attack patterns
    try:
        with open("test_attacks.json", "r") as f:
            attack_data = json.load(f)
        print(f"Loaded {len(attack_data)} attack patterns")
    except FileNotFoundError:
        print("No attack patterns found. Run create_test_attacks.py first.")
        return False
    
    # Simulate processing attack packets
    print("Processing attack packets...")
    
    # Get initial stats
    initial_stats = orchestrator.get_system_status()
    initial_packets = initial_stats.packets_captured
    initial_alerts = initial_stats.alerts_generated
    
    print(f"Initial packets: {initial_packets}")
    print(f"Initial alerts: {initial_alerts}")
    
    # Process some attack packets
    processed_count = 0
    for i, attack_packet in enumerate(attack_data[:1000]):  # Process first 1000 packets
        # Simulate packet processing
        from app.models.schemas import PacketInfo
        packet = PacketInfo(
            timestamp=datetime.fromisoformat(attack_packet["timestamp"]),
            source_ip=attack_packet["source_ip"],
            dest_ip=attack_packet["dest_ip"],
            protocol=attack_packet["protocol"],
            source_port=attack_packet.get("source_port"),
            dest_port=attack_packet.get("dest_port"),
            packet_length=attack_packet["packet_length"],
            tcp_flags=attack_packet.get("tcp_flags"),
            payload_size=attack_packet.get("payload_size", 0)
        )
        
        # Process packet through NIDS
        orchestrator._process_packet(packet)
        processed_count += 1
        
        if i % 100 == 0:
            print(f"Processed {i} packets...")
    
    # Get final stats
    final_stats = orchestrator.get_system_status()
    final_packets = final_stats.packets_captured
    final_alerts = final_stats.alerts_generated
    
    print(f"\nTest Results:")
    print(f"Packets processed: {processed_count}")
    print(f"Total packets captured: {final_packets}")
    print(f"Total alerts generated: {final_alerts}")
    print(f"New alerts: {final_alerts - initial_alerts}")
    
    # Get recent alerts
    recent_alerts = orchestrator.get_alerts(limit=10)
    if recent_alerts:
        print(f"\nRecent alerts:")
        for i, alert in enumerate(recent_alerts[:5], 1):
            print(f"  {i}. {alert.detection_type} - {alert.severity} - {alert.description}")
    
    # Stop NIDS system
    print("\nStopping NIDS system...")
    orchestrator.stop()
    
    print("Test completed!")
    return True

if __name__ == "__main__":
    try:
        success = quick_test()
        if success:
            print("\nSUCCESS: Quick test completed!")
        else:
            print("\nFAILURE: Quick test failed!")
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Error during test: {e}")
