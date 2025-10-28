#!/usr/bin/env python3
"""
Generate various types of attack traffic for testing NIDS anomaly detection
"""

import socket
import time
import random
import threading
import sys
import os
from datetime import datetime
import ipaddress
import struct

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.models.schemas import PacketInfo

class AttackTrafficGenerator:
    """Generate various types of attack traffic for testing"""
    
    def __init__(self, target_ip="192.168.1.100", target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.attacks = []
        
    def start_attack(self, attack_type, duration=30):
        """Start a specific type of attack"""
        if self.running:
            print(f"Attack already running. Stop current attack first.")
            return False
            
        self.running = True
        self.attacks = []
        
        print(f"Starting {attack_type} attack for {duration} seconds...")
        print(f"Target: {self.target_ip}:{self.target_port}")
        
        if attack_type == "ddos":
            self._ddos_attack(duration)
        elif attack_type == "port_scan":
            self._port_scan_attack(duration)
        elif attack_type == "brute_force":
            self._brute_force_attack(duration)
        elif attack_type == "syn_flood":
            self._syn_flood_attack(duration)
        elif attack_type == "icmp_flood":
            self._icmp_flood_attack(duration)
        elif attack_type == "slowloris":
            self._slowloris_attack(duration)
        elif attack_type == "all":
            self._all_attacks(duration)
        else:
            print(f"Unknown attack type: {attack_type}")
            return False
            
        self.running = False
        print(f"Attack completed. Generated {len(self.attacks)} attack packets.")
        return True
    
    def _ddos_attack(self, duration):
        """Generate DDoS attack traffic"""
        print("Generating DDoS attack traffic...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create multiple connections rapidly
                for _ in range(10):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    try:
                        sock.connect((self.target_ip, self.target_port))
                        # Send some data
                        sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                        time.sleep(0.01)
                        sock.close()
                    except:
                        pass
                    
                    # Create attack packet info
                    attack_packet = PacketInfo(
                        timestamp=datetime.now(),
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=self.target_ip,
                        protocol="TCP",
                        source_port=random.randint(1024, 65535),
                        dest_port=self.target_port,
                        packet_length=random.randint(64, 1500),
                        tcp_flags="SYN,ACK",
                        payload_size=random.randint(0, 1000)
                    )
                    self.attacks.append(attack_packet)
                
                time.sleep(0.1)  # Small delay between bursts
                
            except Exception as e:
                print(f"Error in DDoS attack: {e}")
                break
    
    def _port_scan_attack(self, duration):
        """Generate port scanning attack traffic"""
        print("Generating port scan attack traffic...")
        start_time = time.time()
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995, 1433, 3389, 5432, 5900]
        
        while time.time() - start_time < duration and self.running:
            try:
                for port in ports_to_scan:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    try:
                        sock.connect((self.target_ip, port))
                        sock.close()
                        
                        # Create attack packet info
                        attack_packet = PacketInfo(
                            timestamp=datetime.now(),
                            source_ip=f"192.168.1.{random.randint(100, 200)}",
                            dest_ip=self.target_ip,
                            protocol="TCP",
                            source_port=random.randint(1024, 65535),
                            dest_port=port,
                            packet_length=64,
                            tcp_flags="SYN",
                            payload_size=0
                        )
                        self.attacks.append(attack_packet)
                        
                    except:
                        pass
                    
                    time.sleep(0.05)  # Small delay between port attempts
                
                time.sleep(1)  # Wait before next scan round
                
            except Exception as e:
                print(f"Error in port scan attack: {e}")
                break
    
    def _brute_force_attack(self, duration):
        """Generate brute force attack traffic"""
        print("Generating brute force attack traffic...")
        start_time = time.time()
        common_passwords = ["admin", "password", "123456", "root", "test", "guest", "user", "login"]
        
        while time.time() - start_time < duration and self.running:
            try:
                # Simulate SSH brute force
                for password in common_passwords:
                    # Create attack packet info
                    attack_packet = PacketInfo(
                        timestamp=datetime.now(),
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=self.target_ip,
                        protocol="TCP",
                        source_port=random.randint(1024, 65535),
                        dest_port=22,  # SSH port
                        packet_length=len(password) + 50,
                        tcp_flags="PSH,ACK",
                        payload_size=len(password)
                    )
                    self.attacks.append(attack_packet)
                    time.sleep(0.1)
                
                time.sleep(2)  # Wait before next round
                
            except Exception as e:
                print(f"Error in brute force attack: {e}")
                break
    
    def _syn_flood_attack(self, duration):
        """Generate SYN flood attack traffic"""
        print("Generating SYN flood attack traffic...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Generate many SYN packets
                for _ in range(50):
                    attack_packet = PacketInfo(
                        timestamp=datetime.now(),
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=self.target_ip,
                        protocol="TCP",
                        source_port=random.randint(1024, 65535),
                        dest_port=self.target_port,
                        packet_length=64,
                        tcp_flags="SYN",
                        payload_size=0
                    )
                    self.attacks.append(attack_packet)
                
                time.sleep(0.1)  # Small delay between bursts
                
            except Exception as e:
                print(f"Error in SYN flood attack: {e}")
                break
    
    def _icmp_flood_attack(self, duration):
        """Generate ICMP flood attack traffic"""
        print("Generating ICMP flood attack traffic...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Generate many ICMP packets
                for _ in range(20):
                    attack_packet = PacketInfo(
                        timestamp=datetime.now(),
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=self.target_ip,
                        protocol="ICMP",
                        packet_length=64,
                        payload_size=32
                    )
                    self.attacks.append(attack_packet)
                
                time.sleep(0.1)  # Small delay between bursts
                
            except Exception as e:
                print(f"Error in ICMP flood attack: {e}")
                break
    
    def _slowloris_attack(self, duration):
        """Generate Slowloris attack traffic"""
        print("Generating Slowloris attack traffic...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Simulate slow HTTP requests
                for _ in range(5):
                    attack_packet = PacketInfo(
                        timestamp=datetime.now(),
                        source_ip=f"192.168.1.{random.randint(100, 200)}",
                        dest_ip=self.target_ip,
                        protocol="TCP",
                        source_port=random.randint(1024, 65535),
                        dest_port=80,
                        packet_length=100,
                        tcp_flags="PSH,ACK",
                        payload_size=50
                    )
                    self.attacks.append(attack_packet)
                
                time.sleep(2)  # Slow requests
                
            except Exception as e:
                print(f"Error in Slowloris attack: {e}")
                break
    
    def _all_attacks(self, duration):
        """Generate all types of attacks in sequence"""
        print("Generating all attack types...")
        attack_types = ["ddos", "port_scan", "brute_force", "syn_flood", "icmp_flood", "slowloris"]
        duration_per_attack = duration // len(attack_types)
        
        for attack_type in attack_types:
            print(f"\n--- Starting {attack_type} attack ---")
            if attack_type == "ddos":
                self._ddos_attack(duration_per_attack)
            elif attack_type == "port_scan":
                self._port_scan_attack(duration_per_attack)
            elif attack_type == "brute_force":
                self._brute_force_attack(duration_per_attack)
            elif attack_type == "syn_flood":
                self._syn_flood_attack(duration_per_attack)
            elif attack_type == "icmp_flood":
                self._icmp_flood_attack(duration_per_attack)
            elif attack_type == "slowloris":
                self._slowloris_attack(duration_per_attack)
    
    def stop_attack(self):
        """Stop the current attack"""
        self.running = False
        print("Attack stopped.")
    
    def get_attack_packets(self):
        """Get the generated attack packets"""
        return self.attacks
    
    def save_attacks_to_file(self, filename="attack_traffic.json"):
        """Save attack packets to a JSON file"""
        import json
        
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
        
        print(f"Attack traffic saved to {filename}")

def main():
    """Main function to run attack traffic generator"""
    print("NIDS Attack Traffic Generator")
    print("=" * 50)
    
    # Get target IP from user or use default
    target_ip = input("Enter target IP (default: 192.168.1.100): ").strip()
    if not target_ip:
        target_ip = "192.168.1.100"
    
    # Get target port from user or use default
    try:
        target_port = int(input("Enter target port (default: 80): ").strip() or "80")
    except ValueError:
        target_port = 80
    
    # Create attack generator
    generator = AttackTrafficGenerator(target_ip, target_port)
    
    # Show available attack types
    print("\nAvailable attack types:")
    print("1. ddos - Distributed Denial of Service")
    print("2. port_scan - Port scanning")
    print("3. brute_force - Brute force login attempts")
    print("4. syn_flood - SYN flood attack")
    print("5. icmp_flood - ICMP flood attack")
    print("6. slowloris - Slowloris HTTP attack")
    print("7. all - All attack types in sequence")
    
    # Get attack type from user
    attack_type = input("\nEnter attack type (default: all): ").strip().lower()
    if not attack_type:
        attack_type = "all"
    
    # Get duration from user
    try:
        duration = int(input("Enter duration in seconds (default: 30): ").strip() or "30")
    except ValueError:
        duration = 30
    
    # Start the attack
    try:
        success = generator.start_attack(attack_type, duration)
        
        if success:
            print(f"\nAttack completed successfully!")
            print(f"Generated {len(generator.get_attack_packets())} attack packets")
            
            # Ask if user wants to save to file
            save_file = input("\nSave attack packets to file? (y/n): ").strip().lower()
            if save_file == 'y':
                filename = input("Enter filename (default: attack_traffic.json): ").strip()
                if not filename:
                    filename = "attack_traffic.json"
                generator.save_attacks_to_file(filename)
        
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
        generator.stop_attack()
    except Exception as e:
        print(f"Error during attack: {e}")

if __name__ == "__main__":
    main()
