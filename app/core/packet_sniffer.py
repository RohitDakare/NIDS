import asyncio
import threading
import time
from datetime import datetime
from typing import List, Optional, Callable, Dict, Any
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
import logging

from app.models.schemas import PacketInfo, SnifferConfig

logger = logging.getLogger(__name__)

class PacketSniffer:
    """Network packet sniffer using Scapy"""
    
    def __init__(self, config: SnifferConfig):
        self.config = config
        self.is_running = False
        self.sniff_thread = None
        self.packets_captured = 0
        self.start_time = None
        self.packet_callback: Optional[Callable] = None
        self.packets_buffer: List[PacketInfo] = []
        self.max_buffer_size = 10000
        
    def start(self, callback: Optional[Callable] = None) -> bool:
        """Start packet sniffing in a separate thread"""
        if self.is_running:
            logger.warning("Packet sniffer is already running")
            return False
            
        self.packet_callback = callback
        self.is_running = True
        self.start_time = time.time()
        self.packets_captured = 0
        
        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()
        
        logger.info(f"Started packet sniffing on interface {self.config.interface}")
        return True
    
    def stop(self) -> bool:
        """Stop packet sniffing"""
        if not self.is_running:
            logger.warning("Packet sniffer is not running")
            return False
            
        self.is_running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=5)
            
        logger.info("Stopped packet sniffing")
        return True
    
    def _sniff_packets(self):
        """Internal method to sniff packets using Scapy"""
        try:
            # Configure sniffing parameters
            sniff_params = {
                'iface': self.config.interface,
                'prn': self._process_packet,
                'store': False,
                'stop_filter': lambda _: not self.is_running
            }
            
            if self.config.filter:
                sniff_params['filter'] = self.config.filter
                
            if self.config.packet_count > 0:
                sniff_params['count'] = self.config.packet_count
                
            if self.config.timeout > 0:
                sniff_params['timeout'] = self.config.timeout
                
            # Start sniffing
            sniff(**sniff_params)
            
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
            self.is_running = False
    
    def _process_packet(self, packet):
        """Process individual packets and extract relevant information"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packets_captured += 1
                
                # Add to buffer
                self.packets_buffer.append(packet_info)
                if len(self.packets_buffer) > self.max_buffer_size:
                    self.packets_buffer.pop(0)
                
                # Call callback if provided
                if self.packet_callback:
                    self.packet_callback(packet_info)
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from a packet"""
        try:
            # Basic packet info
            timestamp = datetime.now()
            packet_length = len(packet)
            
            # Extract IP layer info
            if IP in packet:
                source_ip = packet[IP].src
                dest_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                # Extract transport layer info
                source_port = None
                dest_port = None
                tcp_flags = None
                payload_size = 0
                
                if TCP in packet:
                    source_port = packet[TCP].sport
                    dest_port = packet[TCP].dport
                    tcp_flags = self._extract_tcp_flags(packet[TCP])
                    payload_size = len(packet[TCP].payload) if packet[TCP].payload else 0
                    protocol_name = "TCP"
                    
                elif UDP in packet:
                    source_port = packet[UDP].sport
                    dest_port = packet[UDP].dport
                    payload_size = len(packet[UDP].payload) if packet[UDP].payload else 0
                    protocol_name = "UDP"
                    
                elif ICMP in packet:
                    protocol_name = "ICMP"
                    
                else:
                    protocol_name = f"IP_{protocol}"
                
                return PacketInfo(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    protocol=protocol_name,
                    source_port=source_port,
                    dest_port=dest_port,
                    packet_length=packet_length,
                    tcp_flags=tcp_flags,
                    payload_size=payload_size
                )
                
            elif ARP in packet:
                # Handle ARP packets
                return PacketInfo(
                    timestamp=timestamp,
                    source_ip=packet[ARP].psrc,
                    dest_ip=packet[ARP].pdst,
                    protocol="ARP",
                    packet_length=packet_length,
                    payload_size=0
                )
                
            else:
                # Other packet types (Ethernet, etc.)
                return PacketInfo(
                    timestamp=timestamp,
                    source_ip="unknown",
                    dest_ip="unknown",
                    protocol="OTHER",
                    packet_length=packet_length,
                    payload_size=0
                )
                
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _extract_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as a string"""
        flags = []
        if tcp_layer.flags & 0x01:  # FIN
            flags.append("FIN")
        if tcp_layer.flags & 0x02:  # SYN
            flags.append("SYN")
        if tcp_layer.flags & 0x04:  # RST
            flags.append("RST")
        if tcp_layer.flags & 0x08:  # PSH
            flags.append("PSH")
        if tcp_layer.flags & 0x10:  # ACK
            flags.append("ACK")
        if tcp_layer.flags & 0x20:  # URG
            flags.append("URG")
        return ",".join(flags) if flags else "NONE"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get sniffer statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        return {
            "is_running": self.is_running,
            "uptime": uptime,
            "packets_captured": self.packets_captured,
            "buffer_size": len(self.packets_buffer),
            "interface": self.config.interface
        }
    
    def get_recent_packets(self, limit: int = 100) -> List[PacketInfo]:
        """Get recent packets from buffer"""
        return self.packets_buffer[-limit:] if self.packets_buffer else []
    
    def clear_buffer(self):
        """Clear the packet buffer"""
        self.packets_buffer.clear()
        logger.info("Packet buffer cleared") 