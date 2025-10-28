#!/usr/bin/env python3
"""
Test script for packet sniffer functionality
"""

import os
import sys
import time
import logging
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.packet_sniffer import PacketSniffer
from app.models.schemas import SnifferConfig

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def test_sniffer():
    """Test the packet sniffer functionality"""
    print("Testing NIDS Packet Sniffer")
    print("=" * 50)
    
    # Get interface from environment or use default
    interface = os.getenv("INTERFACE", "Wi-Fi")
    print(f"Using interface: {interface}")
    
    # Create sniffer configuration
    config = SnifferConfig(
        interface=interface,
        packet_count=10,  # Capture only 10 packets for testing
        timeout=10        # 10 second timeout
    )
    
    # Create packet sniffer
    sniffer = PacketSniffer(config)
    
    # Test packet processing callback
    def packet_callback(packet_info):
        print(f"Captured packet: {packet_info.source_ip} -> {packet_info.dest_ip} "
              f"({packet_info.protocol}) - {packet_info.packet_length} bytes")
    
    try:
        print("\nStarting packet sniffer...")
        success = sniffer.start(callback=packet_callback)
        
        if not success:
            print("Failed to start packet sniffer")
            return False
        
        print("Packet sniffer started successfully")
        print("Capturing packets for 10 seconds...")
        
        # Wait for packets to be captured
        time.sleep(10)
        
        # Get statistics
        stats = sniffer.get_stats()
        print(f"\nSniffer Statistics:")
        print(f"   Running: {stats['is_running']}")
        print(f"   Packets Captured: {stats['packets_captured']}")
        print(f"   Uptime: {stats['uptime']:.2f} seconds")
        print(f"   Interface: {stats['interface']}")
        
        # Get recent packets
        recent_packets = sniffer.get_recent_packets(5)
        print(f"\nRecent Packets ({len(recent_packets)}):")
        for i, packet in enumerate(recent_packets, 1):
            print(f"   {i}. {packet.source_ip}:{packet.source_port or 'N/A'} -> "
                  f"{packet.dest_ip}:{packet.dest_port or 'N/A'} "
                  f"({packet.protocol}) - {packet.packet_length} bytes")
        
        print("\nStopping packet sniffer...")
        success = sniffer.stop()
        
        if success:
            print("Packet sniffer stopped successfully")
        else:
            print("Failed to stop packet sniffer")
        
        return success
        
    except Exception as e:
        print(f"Error during testing: {e}")
        logger.error(f"Test error: {e}")
        return False

if __name__ == "__main__":
    success = test_sniffer()
    if success:
        print("\nTest completed successfully!")
        sys.exit(0)
    else:
        print("\nTest failed!")
        sys.exit(1)
