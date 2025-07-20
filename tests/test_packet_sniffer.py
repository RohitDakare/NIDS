import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from app.core.packet_sniffer import PacketSniffer
from app.models.schemas import SnifferConfig, PacketInfo

class TestPacketSniffer:
    """Test cases for PacketSniffer class"""
    
    @pytest.fixture
    def sniffer_config(self):
        """Create a test sniffer configuration"""
        return SnifferConfig(
            interface="lo",  # Use loopback for testing
            packet_count=10,
            timeout=5
        )
    
    @pytest.fixture
    def packet_sniffer(self, sniffer_config):
        """Create a test packet sniffer instance"""
        return PacketSniffer(sniffer_config)
    
    def test_initialization(self, packet_sniffer, sniffer_config):
        """Test packet sniffer initialization"""
        assert packet_sniffer.config == sniffer_config
        assert packet_sniffer.is_running == False
        assert packet_sniffer.packets_captured == 0
        assert packet_sniffer.start_time is None
    
    def test_start_stop(self, packet_sniffer):
        """Test starting and stopping the sniffer"""
        # Test start
        result = packet_sniffer.start()
        assert result == True
        assert packet_sniffer.is_running == True
        assert packet_sniffer.start_time is not None
        
        # Test stop
        result = packet_sniffer.stop()
        assert result == True
        assert packet_sniffer.is_running == False
    
    def test_start_already_running(self, packet_sniffer):
        """Test starting when already running"""
        packet_sniffer.start()
        result = packet_sniffer.start()  # Try to start again
        assert result == False
    
    def test_stop_not_running(self, packet_sniffer):
        """Test stopping when not running"""
        result = packet_sniffer.stop()
        assert result == False
    
    def test_extract_packet_info_tcp(self, packet_sniffer):
        """Test TCP packet info extraction"""
        # Mock TCP packet
        mock_packet = Mock()
        mock_packet.__len__ = Mock(return_value=100)
        
        # Mock IP layer
        mock_ip = Mock()
        mock_ip.src = "192.168.1.1"
        mock_ip.dst = "192.168.1.2"
        mock_ip.proto = 6  # TCP
        
        # Mock TCP layer
        mock_tcp = Mock()
        mock_tcp.sport = 12345
        mock_tcp.dport = 80
        mock_tcp.flags = 2  # SYN flag
        mock_tcp.payload = b"test payload"
        
        # Set up packet structure
        mock_packet.__contains__ = lambda layer: layer.__name__ == "IP"
        mock_packet.__getitem__ = lambda layer: mock_ip if layer.__name__ == "IP" else mock_tcp
        
        # Test extraction
        packet_info = packet_sniffer._extract_packet_info(mock_packet)
        
        assert packet_info is not None
        assert packet_info.source_ip == "192.168.1.1"
        assert packet_info.dest_ip == "192.168.1.2"
        assert packet_info.protocol == "TCP"
        assert packet_info.source_port == 12345
        assert packet_info.dest_port == 80
        assert packet_info.packet_length == 100
        assert "SYN" in packet_info.tcp_flags
    
    def test_extract_packet_info_udp(self, packet_sniffer):
        """Test UDP packet info extraction"""
        # Mock UDP packet
        mock_packet = Mock()
        mock_packet.__len__ = Mock(return_value=64)
        
        # Mock IP layer
        mock_ip = Mock()
        mock_ip.src = "10.0.0.1"
        mock_ip.dst = "10.0.0.2"
        mock_ip.proto = 17  # UDP
        
        # Mock UDP layer
        mock_udp = Mock()
        mock_udp.sport = 53
        mock_udp.dport = 53
        mock_udp.payload = b"dns query"
        
        # Set up packet structure
        mock_packet.__contains__ = lambda layer: layer.__name__ == "IP"
        mock_packet.__getitem__ = lambda layer: mock_ip if layer.__name__ == "IP" else mock_udp
        
        # Test extraction
        packet_info = packet_sniffer._extract_packet_info(mock_packet)
        
        assert packet_info is not None
        assert packet_info.source_ip == "10.0.0.1"
        assert packet_info.dest_ip == "10.0.0.2"
        assert packet_info.protocol == "UDP"
        assert packet_info.source_port == 53
        assert packet_info.dest_port == 53
        assert packet_info.packet_length == 64
    
    def test_extract_tcp_flags(self, packet_sniffer):
        """Test TCP flags extraction"""
        # Mock TCP layer with different flags
        mock_tcp = Mock()
        
        # Test SYN flag
        mock_tcp.flags = 2
        flags = packet_sniffer._extract_tcp_flags(mock_tcp)
        assert "SYN" in flags
        
        # Test ACK flag
        mock_tcp.flags = 16
        flags = packet_sniffer._extract_tcp_flags(mock_tcp)
        assert "ACK" in flags
        
        # Test SYN+ACK
        mock_tcp.flags = 18
        flags = packet_sniffer._extract_tcp_flags(mock_tcp)
        assert "SYN" in flags and "ACK" in flags
        
        # Test no flags
        mock_tcp.flags = 0
        flags = packet_sniffer._extract_tcp_flags(mock_tcp)
        assert flags == "NONE"
    
    def test_get_stats(self, packet_sniffer):
        """Test getting sniffer statistics"""
        stats = packet_sniffer.get_stats()
        
        assert "is_running" in stats
        assert "uptime" in stats
        assert "packets_captured" in stats
        assert "buffer_size" in stats
        assert "interface" in stats
    
    def test_get_recent_packets(self, packet_sniffer):
        """Test getting recent packets"""
        # Add some test packets
        test_packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.1",
            dest_ip="192.168.1.2",
            protocol="TCP",
            source_port=12345,
            dest_port=80,
            packet_length=100,
            tcp_flags="SYN",
            payload_size=20
        )
        
        packet_sniffer.packets_buffer.append(test_packet)
        
        # Test getting recent packets
        recent_packets = packet_sniffer.get_recent_packets(limit=5)
        assert len(recent_packets) == 1
        assert recent_packets[0].source_ip == "192.168.1.1"
    
    def test_clear_buffer(self, packet_sniffer):
        """Test clearing packet buffer"""
        # Add some test packets
        test_packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.1",
            dest_ip="192.168.1.2",
            protocol="TCP",
            source_port=12345,
            dest_port=80,
            packet_length=100,
            tcp_flags="SYN",
            payload_size=20
        )
        
        packet_sniffer.packets_buffer.append(test_packet)
        assert len(packet_sniffer.packets_buffer) == 1
        
        # Clear buffer
        packet_sniffer.clear_buffer()
        assert len(packet_sniffer.packets_buffer) == 0 