"""
Test fixtures for packet data
"""

from datetime import datetime
from app.models.schemas import PacketInfo, SnifferConfig, MLModelConfig, Alert, AlertSeverity, DetectionType

def create_tcp_packet():
    """Create a sample TCP packet"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="8.8.8.8",
        protocol="TCP",
        source_port=12345,
        dest_port=80,
        packet_length=64,
        tcp_flags="SYN",
        payload_size=20
    )

def create_udp_packet():
    """Create a sample UDP packet"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        protocol="UDP",
        source_port=53,
        dest_port=53,
        packet_length=32,
        payload_size=12
    )

def create_icmp_packet():
    """Create a sample ICMP packet"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.1",
        dest_ip="192.168.1.254",
        protocol="ICMP",
        packet_length=28,
        payload_size=0
    )

def create_arp_packet():
    """Create a sample ARP packet"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="192.168.1.1",
        protocol="ARP",
        packet_length=42,
        payload_size=0
    )

def create_suspicious_packet():
    """Create a suspicious packet for testing anomaly detection"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="192.168.1.200",
        protocol="TCP",
        source_port=12345,
        dest_port=22,  # SSH port
        packet_length=1500,  # Large packet
        tcp_flags="SYN,RST",  # Suspicious flag combination
        payload_size=1400
    )

def create_attack_packet():
    """Create a packet that should trigger signature detection"""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="192.168.1.200",
        protocol="TCP",
        source_port=12345,
        dest_port=80,
        packet_length=100,
        tcp_flags="SYN",
        payload_size=80
    )

def get_sample_packets():
    """Get a list of sample packets for testing"""
    return [
        create_tcp_packet(),
        create_udp_packet(),
        create_icmp_packet(),
        create_arp_packet(),
        create_suspicious_packet(),
        create_attack_packet()
    ]

def create_sniffer_config():
    """Create a test sniffer configuration"""
    return SnifferConfig(
        interface="lo",
        packet_count=100,
        timeout=30,
        filter="tcp"
    )

def create_ml_config():
    """Create a test ML model configuration"""
    return MLModelConfig(
        model_path="models/test_model.joblib",
        confidence_threshold=0.8,
        feature_columns=[
            'packet_length', 'payload_size', 'source_port', 'dest_port',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp'
        ]
    )

def create_alert():
    """Create a sample alert"""
    return Alert(
        timestamp=datetime.now(),
        severity=AlertSeverity.HIGH,
        detection_type=DetectionType.ML,
        description="Suspicious network activity detected",
        source_ip="192.168.1.100",
        dest_ip="192.168.1.200",
        protocol="TCP",
        confidence_score=0.85,
        is_resolved=False
    )

def create_signature_alert():
    """Create a signature-based alert"""
    return Alert(
        timestamp=datetime.now(),
        severity=AlertSeverity.CRITICAL,
        detection_type=DetectionType.SIGNATURE,
        description="Known attack pattern detected",
        source_ip="192.168.1.100",
        dest_ip="192.168.1.200",
        protocol="TCP",
        confidence_score=0.95,
        is_resolved=False
    )

def get_sample_alerts():
    """Get a list of sample alerts for testing"""
    return [
        create_alert(),
        create_signature_alert()
    ]
