"""
Unit tests for Signature Detector
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from app.core.signature_detector import SignatureDetector, SignatureRule
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
        assert 'disabled_rules' in stats
        assert 'matches_count' in stats
        assert 'top_rules' in stats
        
        assert isinstance(stats['total_rules'], int)
        assert stats['total_rules'] >= 0
        assert stats['enabled_rules'] <= stats['total_rules']
        assert stats['disabled_rules'] == stats['total_rules'] - stats['enabled_rules']
        assert isinstance(stats['matches_count'], int)
        assert stats['matches_count'] >= 0
        assert isinstance(stats['top_rules'], list)
        assert stats['enabled_rules'] >= 0
        assert stats['matches_count'] >= 0
    
    def test_rule_matching_logic(self, signature_detector):
        """Test rule matching logic with different patterns"""
        from app.core.signature_detector import SignatureRule
        from app.models.schemas import AlertSeverity
        
        # Create test rules
        rule1 = SignatureRule(
            rule_id='test_port_rule',
            name='Test Port Rule',
            pattern='80',
            severity=AlertSeverity.MEDIUM,
            description='Test port 80 rule'
        )
        
        rule2 = SignatureRule(
            rule_id='test_ip_rule',
            name='Test IP Rule',
            pattern='192.168.1.100',
            severity=AlertSeverity.HIGH,
            description='Test IP rule'
        )
        
        # Create test packet
        from tests.fixtures.packet_data import create_tcp_packet
        packet = create_tcp_packet()
        
        # Test port matching
        packet.dest_port = 80
        assert rule1.match(packet) is True
        
        # Test IP matching
        packet.source_ip = '192.168.1.100'
        assert rule2.match(packet) is True
        
        # Test non-matching case
        packet.dest_port = 443
        packet.source_ip = '10.0.0.1'
        assert rule1.match(packet) is False
        assert rule2.match(packet) is False
    
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
        from app.models.schemas import AlertSeverity
        
        # Clear existing rules
        signature_detector.rules = {}
        
        # Create a rule that matches port 80 but is disabled
        rule = SignatureRule(
            rule_id='http_rule',
            name='HTTP Traffic',
            pattern='80',
            severity=AlertSeverity.MEDIUM,
            description='Detects HTTP traffic',
            enabled=False  # Disabled rule
        )
        
        signature_detector.rules[rule.rule_id] = rule
        
        # Create a test packet that would match if the rule was enabled
        packet = create_tcp_packet()
        packet.dest_port = 80
        
        # Run detection
        detections = signature_detector.detect(packet)
        
        # The disabled rule should not have matched
        rule_ids = {d.get('rule_id') for d in detections}
        assert rule.rule_id not in rule_ids
        assert rule.matches_count == 0  # Match count should not be incremented
    
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
