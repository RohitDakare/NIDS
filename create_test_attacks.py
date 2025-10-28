#!/usr/bin/env python3
"""
Create test attack patterns for NIDS testing
This script generates various attack patterns and saves them for testing
"""

import json
import random
import time
from datetime import datetime, timedelta
import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.models.schemas import PacketInfo

class TestAttackCreator:
    """Create test attack patterns for NIDS testing"""
    
    def __init__(self):
        self.attacks = []
    
    def create_ddos_pattern(self, target_ip="192.168.1.100", duration_minutes=5):
        """Create DDoS attack pattern"""
        print("Creating DDoS attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Generate high-frequency requests from multiple sources
        while start_time < end_time:
            # Create burst of requests
            for _ in range(50):
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=80,
                    packet_length=random.randint(64, 1500),
                    tcp_flags="SYN,ACK",
                    payload_size=random.randint(0, 1000)
                )
                self.attacks.append(packet)
            
            start_time += timedelta(seconds=0.1)  # 10 requests per second
    
    def create_port_scan_pattern(self, target_ip="192.168.1.100", duration_minutes=3):
        """Create port scan attack pattern"""
        print("Creating port scan attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995, 1433, 3389, 5432, 5900]
        
        while start_time < end_time:
            for port in ports_to_scan:
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=port,
                    packet_length=64,
                    tcp_flags="SYN",
                    payload_size=0
                )
                self.attacks.append(packet)
                start_time += timedelta(milliseconds=100)  # 100ms between port attempts
            
            start_time += timedelta(seconds=2)  # 2 second pause between scan rounds
    
    def create_brute_force_pattern(self, target_ip="192.168.1.100", duration_minutes=4):
        """Create brute force attack pattern"""
        print("Creating brute force attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        common_passwords = [
            "admin", "password", "123456", "root", "test", "guest", "user", "login",
            "admin123", "password123", "qwerty", "abc123", "letmein", "welcome"
        ]
        
        while start_time < end_time:
            for password in common_passwords:
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=22,  # SSH port
                    packet_length=len(password) + 50,
                    tcp_flags="PSH,ACK",
                    payload_size=len(password)
                )
                self.attacks.append(packet)
                start_time += timedelta(milliseconds=500)  # 500ms between attempts
            
            start_time += timedelta(seconds=5)  # 5 second pause between rounds
    
    def create_syn_flood_pattern(self, target_ip="192.168.1.100", duration_minutes=2):
        """Create SYN flood attack pattern"""
        print("Creating SYN flood attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        while start_time < end_time:
            # Generate burst of SYN packets
            for _ in range(100):
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=80,
                    packet_length=64,
                    tcp_flags="SYN",
                    payload_size=0
                )
                self.attacks.append(packet)
            
            start_time += timedelta(milliseconds=50)  # Very fast rate
    
    def create_icmp_flood_pattern(self, target_ip="192.168.1.100", duration_minutes=2):
        """Create ICMP flood attack pattern"""
        print("Creating ICMP flood attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        while start_time < end_time:
            packet = PacketInfo(
                timestamp=start_time,
                source_ip=f"192.168.1.{random.randint(100, 200)}",
                dest_ip=target_ip,
                protocol="ICMP",
                packet_length=64,
                payload_size=32
            )
            self.attacks.append(packet)
            start_time += timedelta(milliseconds=10)  # 100 packets per second
    
    def create_slowloris_pattern(self, target_ip="192.168.1.100", duration_minutes=3):
        """Create Slowloris attack pattern"""
        print("Creating Slowloris attack pattern...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        while start_time < end_time:
            # Slow HTTP requests
            packet = PacketInfo(
                timestamp=start_time,
                source_ip=f"192.168.1.{random.randint(100, 200)}",
                dest_ip=target_ip,
                protocol="TCP",
                source_port=random.randint(1024, 65535),
                dest_port=80,
                packet_length=100,
                tcp_flags="PSH,ACK",
                payload_size=50
            )
            self.attacks.append(packet)
            start_time += timedelta(seconds=2)  # Slow requests
    
    def create_anomalous_traffic(self, target_ip="192.168.1.100", duration_minutes=5):
        """Create various anomalous traffic patterns"""
        print("Creating anomalous traffic patterns...")
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        while start_time < end_time:
            # Random anomalous patterns
            pattern_type = random.choice([
                "unusual_port", "large_payload", "rapid_connections", 
                "suspicious_protocol", "odd_timing"
            ])
            
            if pattern_type == "unusual_port":
                # Traffic to unusual ports
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice([666, 1337, 31337, 12345, 54321]),
                    packet_length=64,
                    tcp_flags="SYN",
                    payload_size=0
                )
            elif pattern_type == "large_payload":
                # Large payload packets
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=80,
                    packet_length=random.randint(2000, 9000),
                    tcp_flags="PSH,ACK",
                    payload_size=random.randint(1500, 8000)
                )
            elif pattern_type == "rapid_connections":
                # Rapid connection attempts
                for _ in range(10):
                    packet = PacketInfo(
                        timestamp=start_time,
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=target_ip,
                        protocol="TCP",
                        source_port=random.randint(1024, 65535),
                        dest_port=80,
                        packet_length=64,
                        tcp_flags="SYN",
                        payload_size=0
                    )
                    self.attacks.append(packet)
                    start_time += timedelta(milliseconds=10)
                continue
            elif pattern_type == "suspicious_protocol":
                # Suspicious protocol usage
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="OTHER",
                    packet_length=64,
                    payload_size=32
                )
            else:  # odd_timing
                # Odd timing patterns
                packet = PacketInfo(
                    timestamp=start_time,
                    source_ip=f"192.168.1.{random.randint(100, 200)}",
                    dest_ip=target_ip,
                    protocol="TCP",
                    source_port=random.randint(1024, 65535),
                    dest_port=80,
                    packet_length=64,
                    tcp_flags="SYN",
                    payload_size=0
                )
            
            self.attacks.append(packet)
            start_time += timedelta(seconds=random.uniform(0.1, 2.0))
    
    def create_all_patterns(self, target_ip="192.168.1.100"):
        """Create all attack patterns"""
        print("Creating all attack patterns...")
        
        # Create different attack patterns
        self.create_ddos_pattern(target_ip, 5)
        self.create_port_scan_pattern(target_ip, 3)
        self.create_brute_force_pattern(target_ip, 4)
        self.create_syn_flood_pattern(target_ip, 2)
        self.create_icmp_flood_pattern(target_ip, 2)
        self.create_slowloris_pattern(target_ip, 3)
        self.create_anomalous_traffic(target_ip, 5)
        
        print(f"Created {len(self.attacks)} attack packets")
    
    def save_to_file(self, filename="test_attacks.json"):
        """Save attacks to JSON file"""
        attack_data = []
        for packet in self.attacks:
            attack_data.append({
                "timestamp": packet.timestamp.isoformat(),
                "source_ip": packet.source_ip,
                "dest_ip": packet.dest_ip,
                "protocol": packet.protocol,
                "source_port": packet.source_port,
                "dest_port": packet.dest_port,
                "packet_length": packet.packet_length,
                "tcp_flags": packet.tcp_flags,
                "payload_size": packet.payload_size
            })
        
        with open(filename, 'w') as f:
            json.dump(attack_data, f, indent=2)
        
        print(f"Attack patterns saved to {filename}")
    
    def print_summary(self):
        """Print summary of created attacks"""
        if not self.attacks:
            print("No attacks created.")
            return
        
        # Group by protocol
        protocols = {}
        for packet in self.attacks:
            protocol = packet.protocol
            if protocol not in protocols:
                protocols[protocol] = 0
            protocols[protocol] += 1
        
        print(f"\nAttack Summary:")
        print(f"Total packets: {len(self.attacks)}")
        print(f"Time range: {min(p.timestamp for p in self.attacks)} to {max(p.timestamp for p in self.attacks)}")
        print(f"Protocols:")
        for protocol, count in protocols.items():
            print(f"  {protocol}: {count} packets")

def main():
    """Main function"""
    print("Test Attack Pattern Creator")
    print("=" * 40)
    
    # Get target IP
    try:
        target_ip = input("Enter target IP (default: 192.168.1.100): ").strip()
    except EOFError:
        target_ip = ""
    if not target_ip:
        target_ip = "192.168.1.100"
    
    # Create attack creator
    creator = TestAttackCreator()
    
    # Create all patterns
    creator.create_all_patterns(target_ip)
    
    # Print summary
    creator.print_summary()
    
    # Save to file
    try:
        filename = input("\nEnter filename to save (default: test_attacks.json): ").strip()
    except EOFError:
        filename = ""
    if not filename:
        filename = "test_attacks.json"
    
    creator.save_to_file(filename)
    
    print(f"\nTest attack patterns created successfully!")
    print(f"You can now use these patterns to test your NIDS system.")

if __name__ == "__main__":
    main()
