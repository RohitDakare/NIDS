"""
Mock objects for Scapy packet testing
"""

from unittest.mock import Mock
from datetime import datetime

class MockPacket:
    """Mock packet object for testing"""
    
    def __init__(self, packet_type="TCP", **kwargs):
        self.packet_type = packet_type
        self.length = kwargs.get('length', 64)
        self.timestamp = kwargs.get('timestamp', datetime.now())
        
        # Mock IP layer
        self.ip_layer = Mock()
        self.ip_layer.src = kwargs.get('src_ip', '192.168.1.1')
        self.ip_layer.dst = kwargs.get('dst_ip', '192.168.1.2')
        self.ip_layer.proto = kwargs.get('proto', 6)  # TCP
        
        # Mock transport layer
        if packet_type == "TCP":
            self.tcp_layer = Mock()
            self.tcp_layer.sport = kwargs.get('sport', 12345)
            self.tcp_layer.dport = kwargs.get('dport', 80)
            self.tcp_layer.flags = kwargs.get('flags', 2)  # SYN
            self.tcp_layer.payload = kwargs.get('payload', b"test payload")
        elif packet_type == "UDP":
            self.udp_layer = Mock()
            self.udp_layer.sport = kwargs.get('sport', 53)
            self.udp_layer.dport = kwargs.get('dport', 53)
            self.udp_layer.payload = kwargs.get('payload', b"dns query")
        elif packet_type == "ICMP":
            self.icmp_layer = Mock()
            self.icmp_layer.type = kwargs.get('icmp_type', 8)  # Echo request
        elif packet_type == "ARP":
            self.arp_layer = Mock()
            self.arp_layer.psrc = kwargs.get('psrc', '192.168.1.1')
            self.arp_layer.pdst = kwargs.get('pdst', '192.168.1.2')
    
    def __len__(self):
        return self.length
    
    def __contains__(self, layer):
        if layer.__name__ == "IP":
            return True
        elif layer.__name__ == "TCP" and hasattr(self, 'tcp_layer'):
            return True
        elif layer.__name__ == "UDP" and hasattr(self, 'udp_layer'):
            return True
        elif layer.__name__ == "ICMP" and hasattr(self, 'icmp_layer'):
            return True
        elif layer.__name__ == "ARP" and hasattr(self, 'arp_layer'):
            return True
        return False
    
    def __getitem__(self, layer):
        if layer.__name__ == "IP":
            return self.ip_layer
        elif layer.__name__ == "TCP" and hasattr(self, 'tcp_layer'):
            return self.tcp_layer
        elif layer.__name__ == "UDP" and hasattr(self, 'udp_layer'):
            return self.udp_layer
        elif layer.__name__ == "ICMP" and hasattr(self, 'icmp_layer'):
            return self.icmp_layer
        elif layer.__name__ == "ARP" and hasattr(self, 'arp_layer'):
            return self.arp_layer
        raise KeyError(f"Layer {layer.__name__} not found")

def create_mock_tcp_packet(**kwargs):
    """Create a mock TCP packet"""
    return MockPacket("TCP", **kwargs)

def create_mock_udp_packet(**kwargs):
    """Create a mock UDP packet"""
    return MockPacket("UDP", **kwargs)

def create_mock_icmp_packet(**kwargs):
    """Create a mock ICMP packet"""
    return MockPacket("ICMP", **kwargs)

def create_mock_arp_packet(**kwargs):
    """Create a mock ARP packet"""
    return MockPacket("ARP", **kwargs)

def create_mock_suspicious_packet():
    """Create a mock suspicious packet"""
    return MockPacket(
        "TCP",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.200",
        sport=12345,
        dport=22,
        length=1500,
        flags=18,  # SYN+RST
        payload=b"x" * 1400
    )

def create_mock_attack_packet():
    """Create a mock attack packet"""
    return MockPacket(
        "TCP",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.200",
        sport=12345,
        dport=80,
        length=100,
        flags=2,  # SYN
        payload=b"GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
    )

def get_mock_packets():
    """Get a list of mock packets for testing"""
    return [
        create_mock_tcp_packet(),
        create_mock_udp_packet(),
        create_mock_icmp_packet(),
        create_mock_arp_packet(),
        create_mock_suspicious_packet(),
        create_mock_attack_packet()
    ]
