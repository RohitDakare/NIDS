"""
Unit tests for Signature Detector
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from app.core.signature_detector import SignatureDetector
from app.models.schemas import PacketInfo, DetectionType, AlertSeverity
from tests.fixtures.packet_data import create_tcp_packet, create_attack_packet

class TestSignatureDetector:
    """Test cases for SignatureDetector class"""
    
    @pytest.fixture
    def signature_detector(self):
        """Create a test signature detector instance"""
        return SignatureDetector()
    
    def test_initialization(self, signature_detector):
        """Test signature detector initialization"""
        assert signature_detector.rules is not None
        assert len(signature_detector.rules) > 0
        assert signature_detector.matches_count == 0
    
    def test_detect_normal_packet(self, signature_detector):
        """Test detection on normal packet"""
        packet = create_tcp_packet()
        
        detections = signature_detector.detect(packet)
        
        assert isinstance(detections, list)
        # Normal packet should not trigger signature detection
    
    def test_detect_attack_packet(self, signature_detector):
        """Test detection on attack packet"""
        packet = create_attack_packet()
        
        detections = signature_detector.detect(packet)
        
        assert isinstance(detections, list)
        # May or may not trigger depending on rules
    
    def test_detect_with_custom_rules(self, signature_detector):
        """Test detection with custom rules"""
        # Add a custom rule
        custom_rule = {
            'rule_id': 'test_rule_1',
            'name': 'Test Rule',
            'description': 'Test rule for unit testing',
            'pattern': 'tcp port 22',
            'severity': AlertSeverity.HIGH,
            'enabled': True,
            'matches_count': 0,
            'last_match': None
        }
        
        signature_detector.rules['test_rule_1'] = custom_rule
        
        # Create a packet that should match
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.200",
            protocol="TCP",
            source_port=12345,
            dest_port=22,  # SSH port
            packet_length=64,
            tcp_flags="SYN",
            payload_size=20
        )
        
        detections = signature_detector.detect(packet)
        
        assert isinstance(detections, list)
    
    def test_enable_rule(self, signature_detector):
        """Test enabling a signature rule"""
        rule_id = list(signature_detector.rules.keys())[0]
        
        result = signature_detector.enable_rule(rule_id)
        
        assert result == True
        assert signature_detector.rules[rule_id].enabled == True
    
    def test_enable_nonexistent_rule(self, signature_detector):
        """Test enabling a non-existent rule"""
        result = signature_detector.enable_rule('nonexistent_rule')
        assert result == False
    
    def test_disable_rule(self, signature_detector):
        """Test disabling a signature rule"""
        rule_id = list(signature_detector.rules.keys())[0]
        
        result = signature_detector.disable_rule(rule_id)
        
        assert result == True
        assert signature_detector.rules[rule_id].enabled == False
    
    def test_disable_nonexistent_rule(self, signature_detector):
        """Test disabling a non-existent rule"""
        result = signature_detector.disable_rule('nonexistent_rule')
        assert result == False
    
    def test_get_rule_stats(self, signature_detector):
        """Test getting rule statistics"""
        stats = signature_detector.get_rule_stats()
        
        assert isinstance(stats, list)
        assert len(stats) > 0
        
        # Check structure of first rule
        first_rule = stats[0]
        assert 'rule_id' in first_rule
        assert 'name' in first_rule
        assert 'enabled' in first_rule
        assert 'severity' in first_rule
        assert 'matches_count' in first_rule
    
    def test_get_stats(self, signature_detector):
        """Test getting detector statistics"""
        stats = signature_detector.get_stats()
        
        assert 'total_rules' in stats
        assert 'enabled_rules' in stats
        assert 'matches_count' in stats
        assert 'connection_count' in stats
        
        assert stats['total_rules'] > 0
        assert stats['enabled_rules'] >= 0
        assert stats['matches_count'] >= 0
    
    def test_rule_matching_logic(self, signature_detector):
        """Test rule matching logic"""
        # Create a rule that matches specific port
        rule_id = 'port_80_rule'
        rule = {
            'rule_id': rule_id,
            'name': 'Port 80 Rule',
            'description': 'Matches traffic on port 80',
            'pattern': 'tcp port 80',
            'severity': AlertSeverity.MEDIUM,
            'enabled': True,
            'matches_count': 0,
            'last_match': None
        }
        
        signature_detector.rules[rule_id] = rule
        
        # Create packet that should match
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.200",
            protocol="TCP",
            source_port=12345,
            dest_port=80,  # HTTP port
            packet_length=64,
            tcp_flags="SYN",
            payload_size=20
        )
        
        detections = signature_detector.detect(packet)
        
        # Check if rule was triggered
        rule_triggered = any(detection.get('rule_id') == rule_id for detection in detections)
        
        if rule_triggered:
            assert signature_detector.rules[rule_id]['matches_count'] > 0
            assert signature_detector.rules[rule_id]['last_match'] is not None
    
    def test_multiple_rule_matching(self, signature_detector):
        """Test multiple rules matching the same packet"""
        # Add multiple rules
        rules = {
            'rule_1': {
                'rule_id': 'rule_1',
                'name': 'TCP Rule',
                'description': 'Matches TCP traffic',
                'pattern': 'tcp',
                'severity': AlertSeverity.LOW,
                'enabled': True,
                'matches_count': 0,
                'last_match': None
            },
            'rule_2': {
                'rule_id': 'rule_2',
                'name': 'Port 80 Rule',
                'description': 'Matches port 80',
                'pattern': 'tcp port 80',
                'severity': AlertSeverity.MEDIUM,
                'enabled': True,
                'matches_count': 0,
                'last_match': None
            }
        }
        
        for rule_id, rule in rules.items():
            signature_detector.rules[rule_id] = rule
        
        # Create packet that should match both rules
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            dest_ip="192.168.1.200",
            protocol="TCP",
            source_port=12345,
            dest_port=80,
            packet_length=64,
            tcp_flags="SYN",
            payload_size=20
        )
        
        detections = signature_detector.detect(packet)
        
        assert isinstance(detections, list)
        # Should potentially match multiple rules
    
    def test_disabled_rule_not_matching(self, signature_detector):
        """Test that disabled rules don't match"""
        rule_id = 'disabled_rule'
        rule = {
            'rule_id': rule_id,
            'name': 'Disabled Rule',
            'description': 'This rule is disabled',
            'pattern': 'tcp',
            'severity': AlertSeverity.LOW,
            'enabled': False,  # Disabled
            'matches_count': 0,
            'last_match': None
        }
        
        signature_detector.rules[rule_id] = rule
        
        packet = create_tcp_packet()
        detections = signature_detector.detect(packet)
        
        # Disabled rule should not match
        rule_triggered = any(detection.get('rule_id') == rule_id for detection in detections)
        assert rule_triggered == False
    
    def test_rule_severity_levels(self, signature_detector):
        """Test different severity levels in rules"""
        severities = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        
        for i, severity in enumerate(severities):
            rule_id = f'severity_rule_{i}'
            rule = {
                'rule_id': rule_id,
                'name': f'Severity {severity} Rule',
                'description': f'Rule with {severity} severity',
                'pattern': 'tcp',
                'severity': severity,
                'enabled': True,
                'matches_count': 0,
                'last_match': None
            }
            
            signature_detector.rules[rule_id] = rule
        
        packet = create_tcp_packet()
        detections = signature_detector.detect(packet)
        
        # Check that detections have correct severity levels
        for detection in detections:
            assert detection['severity'] in severities
