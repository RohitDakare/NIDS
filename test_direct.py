#!/usr/bin/env python3
"""
Direct test of NIDS functionality without API
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.nids_orchestrator import NIDSOrchestrator
from app.models.schemas import SnifferConfig, MLModelConfig

def test_direct():
    """Test NIDS functionality directly"""
    print("Direct NIDS Test")
    print("=" * 50)
    
    # Create configurations
    sniffer_config = SnifferConfig(
        interface="Wi-Fi",
        packet_count=10,
        timeout=30
    )
    
    ml_config = MLModelConfig(
        model_path="app/ml_models/nids_model.joblib",
        confidence_threshold=0.8
    )
    
    # Create orchestrator
    orchestrator = NIDSOrchestrator(
        sniffer_config=sniffer_config,
        ml_config=ml_config
    )
    
    print("Starting NIDS system...")
    success = orchestrator.start()
    
    if success:
        print("NIDS system started successfully!")
        
        # Get status
        status = orchestrator.get_system_status()
        print(f"System running: {status.is_running}")
        print(f"Packets captured: {status.packets_captured}")
        print(f"Uptime: {status.uptime:.2f} seconds")
        
        # Wait a bit for packets
        import time
        print("Waiting for packets...")
        time.sleep(5)
        
        # Get updated status
        status = orchestrator.get_system_status()
        print(f"Packets captured: {status.packets_captured}")
        
        # Get recent packets
        packets = orchestrator.get_recent_packets(5)
        print(f"Recent packets: {len(packets)}")
        for i, packet in enumerate(packets[:3], 1):
            print(f"  {i}. {packet.source_ip} -> {packet.dest_ip} ({packet.protocol})")
        
        # Stop system
        print("Stopping NIDS system...")
        success = orchestrator.stop()
        
        if success:
            print("NIDS system stopped successfully!")
        else:
            print("Failed to stop NIDS system")
    else:
        print("Failed to start NIDS system")
    
    return success

if __name__ == "__main__":
    success = test_direct()
    if success:
        print("\nSUCCESS: Direct test passed!")
        sys.exit(0)
    else:
        print("\nFAILURE: Direct test failed!")
        sys.exit(1)
