"""
Unit tests for Alert Manager
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from app.core.alert_manager import AlertManager
from app.models.schemas import Alert, AlertSeverity, DetectionType, PacketInfo
from tests.fixtures.packet_data import create_alert, create_signature_alert, create_tcp_packet

class TestAlertManager:
    """Test cases for AlertManager class"""
    
    @pytest.fixture
    def alert_manager(self):
        """Create a test alert manager instance"""
        return AlertManager()
    
    @pytest.fixture
    def sample_alert(self):
        """Create a sample alert"""
        return create_alert()
    
    @pytest.fixture
    def sample_packet(self):
        """Create a sample packet"""
        return create_tcp_packet()
    
    def test_initialization(self, alert_manager):
        """Test alert manager initialization"""
        assert len(alert_manager.alerts) == 0
        assert alert_manager.alert_callback is None
        assert alert_manager.alert_id_counter == 0
    
    def test_initialization_with_callback(self):
        """Test alert manager initialization with callback"""
        callback = Mock()
        alert_manager = AlertManager(alert_callback=callback)
        
        assert alert_manager.alert_callback == callback
    
    def test_create_ml_alert(self, alert_manager, sample_packet):
        """Test creating ML-based alert"""
        ml_detection = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': AlertSeverity.HIGH,
            'description': 'ML anomaly detected',
            'detection_type': DetectionType.ML
        }
        
        alert = alert_manager.create_ml_alert(ml_detection, sample_packet)
        
        assert alert is not None
        assert alert.detection_type == DetectionType.ML
        assert alert.severity == AlertSeverity.HIGH
        assert alert.confidence_score == 0.85
        assert alert.source_ip == sample_packet.source_ip
        assert alert.dest_ip == sample_packet.dest_ip
        assert alert.protocol == sample_packet.protocol
        assert alert.is_resolved == False
        
        # Check that alert was added to the list
        assert len(alert_manager.alerts) == 1
        assert alert_manager.alerts[0] == alert
    
    def test_create_signature_alert(self, alert_manager, sample_packet):
        """Test creating signature-based alert"""
        signature_detection = {
            'rule_id': 'test_rule',
            'rule_name': 'Test Rule',
            'severity': AlertSeverity.CRITICAL,
            'description': 'Signature match detected',
            'detection_type': DetectionType.SIGNATURE,
            'confidence': 0.95
        }
        
        alert = alert_manager.create_signature_alert(signature_detection, sample_packet)
        
        assert alert is not None
        assert alert.detection_type == DetectionType.SIGNATURE
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.confidence_score == 0.95
        assert alert.description == 'Signature match detected'
        
        # Check that alert was added to the list
        assert len(alert_manager.alerts) == 1
    
    def test_create_hybrid_alert(self, alert_manager, sample_packet):
        """Test creating hybrid alert (ML + Signature)"""
        ml_detection = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': AlertSeverity.HIGH,
            'description': 'ML anomaly detected',
            'detection_type': DetectionType.ML
        }
        
        signature_detection = {
            'rule_id': 'test_rule',
            'rule_name': 'Test Rule',
            'severity': AlertSeverity.CRITICAL,
            'description': 'Signature match detected',
            'detection_type': DetectionType.SIGNATURE,
            'confidence': 0.95
        }
        
        alert = alert_manager.create_hybrid_alert(ml_detection, signature_detection, sample_packet)
        
        assert alert is not None
        assert alert.detection_type == DetectionType.HYBRID
        assert alert.severity == AlertSeverity.CRITICAL  # Should use higher severity
        assert alert.confidence_score == 0.95  # Should use higher confidence
        assert 'ML anomaly detected' in alert.description
        assert 'Signature match detected' in alert.description
    
    def test_alert_callback_invocation(self, sample_packet):
        """Test that alert callback is invoked"""
        callback = Mock()
        alert_manager = AlertManager(alert_callback=callback)
        
        ml_detection = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': AlertSeverity.HIGH,
            'description': 'ML anomaly detected',
            'detection_type': DetectionType.ML
        }
        
        alert = alert_manager.create_ml_alert(ml_detection, sample_packet)
        
        callback.assert_called_once_with(alert)
    
    def test_get_alerts(self, alert_manager):
        """Test getting alerts"""
        # Create some test alerts
        alert1 = create_alert()
        alert2 = create_signature_alert()
        
        alert_manager.alerts = [alert1, alert2]
        
        # Test getting all alerts
        alerts = alert_manager.get_alerts()
        assert len(alerts) == 2
        
        # Test getting limited alerts
        alerts = alert_manager.get_alerts(limit=1)
        assert len(alerts) == 1
        
        # Test filtering by severity
        alerts = alert_manager.get_alerts(severity=AlertSeverity.HIGH)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.HIGH
    
    def test_get_alert_by_id(self, alert_manager):
        """Test getting alert by ID"""
        alert = create_alert()
        alert_manager.alerts = [alert]
        
        # Test getting existing alert
        found_alert = alert_manager.get_alert_by_id(alert.id)
        assert found_alert == alert
        
        # Test getting non-existent alert
        found_alert = alert_manager.get_alert_by_id(999)
        assert found_alert is None
    
    def test_resolve_alert(self, alert_manager):
        """Test resolving an alert"""
        alert = create_alert()
        alert_manager.alerts.append(alert)
        
        result = alert_manager.resolve_alert(alert.id, "Resolved by admin")
        
        assert result == True
        assert alert.is_resolved == True
        assert alert.packet_data['resolution_notes'] == "Resolved by admin"
        assert 'resolved_at' in alert.packet_data
    
    def test_resolve_nonexistent_alert(self, alert_manager):
        """Test resolving non-existent alert"""
        result = alert_manager.resolve_alert(999, "Test resolution")
        assert result == False
    
    def test_delete_alert(self, alert_manager):
        """Test deleting an alert"""
        alert = create_alert()
        alert_manager.alerts = [alert]
        
        result = alert_manager.delete_alert(alert.id)
        
        assert result == True
        assert len(alert_manager.alerts) == 0
    
    def test_delete_nonexistent_alert(self, alert_manager):
        """Test deleting non-existent alert"""
        result = alert_manager.delete_alert(999)
        assert result == False
    
    def test_clear_alerts(self, alert_manager):
        """Test clearing alerts"""
        # Add some alerts
        alert1 = create_alert()
        alert2 = create_signature_alert()
        alert_manager.alerts = [alert1, alert2]
        
        alert_manager.clear_alerts()
        
        assert len(alert_manager.alerts) == 0
    
    def test_clear_alerts_older_than(self, alert_manager):
        """Test clearing alerts older than specified time"""
        # Create old alert
        old_alert = create_alert()
        old_alert.timestamp = datetime.now() - timedelta(days=10)
        
        # Create recent alert
        recent_alert = create_alert()
        recent_alert.timestamp = datetime.now() - timedelta(days=1)
        
        alert_manager.alerts = [old_alert, recent_alert]
        
        # Clear alerts older than 5 days
        alert_manager.clear_alerts(older_than=timedelta(days=5))
        
        assert len(alert_manager.alerts) == 1
        assert alert_manager.alerts[0] == recent_alert
    
    def test_export_alerts_json(self, alert_manager):
        """Test exporting alerts as JSON"""
        alert = create_alert()
        alert_manager.alerts = [alert]
        
        exported_data = alert_manager.export_alerts('json')
        
        assert isinstance(exported_data, str)
        assert 'timestamp' in exported_data
        assert 'severity' in exported_data
    
    def test_export_alerts_csv(self, alert_manager):
        """Test exporting alerts as CSV"""
        alert = create_alert()
        alert_manager.alerts = [alert]
        
        exported_data = alert_manager.export_alerts('csv')
        
        assert isinstance(exported_data, str)
        assert 'timestamp' in exported_data
        assert 'severity' in exported_data
    
    def test_get_correlation_analysis(self, alert_manager):
        """Test getting correlation analysis"""
        # Create alerts from same source IP
        alert1 = create_alert()
        alert1.source_ip = "192.168.1.100"
        alert1.timestamp = datetime.now() - timedelta(minutes=10)
        
        alert2 = create_alert()
        alert2.source_ip = "192.168.1.100"
        alert2.timestamp = datetime.now() - timedelta(minutes=5)
        
        alert_manager.alerts = [alert1, alert2]
        
        correlation = alert_manager.get_correlation_analysis()
        
        assert 'total_correlations' in correlation
        assert 'correlations' in correlation
        assert isinstance(correlation['correlations'], list)
    
    def test_get_stats(self, alert_manager):
        """Test getting alert manager statistics"""
        # Add some alerts
        alert1 = create_alert()
        alert2 = create_signature_alert()
        alert_manager.alerts = [alert1, alert2]
        
        stats = alert_manager.get_stats()
        
        assert 'total_alerts' in stats
        assert 'resolved_alerts' in stats
        assert 'alerts_by_severity' in stats
        assert 'alerts_by_type' in stats
        
        assert stats['total_alerts'] == 2
        assert stats['resolved_alerts'] == 0
    
    def test_alert_id_generation(self, alert_manager):
        """Test that alert IDs are generated correctly"""
        # Create alerts through the manager to get proper IDs
        packet = create_tcp_packet()
        ml_detection = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': AlertSeverity.HIGH,
            'description': 'Test alert 1'
        }
        
        alert1 = alert_manager.create_ml_alert(ml_detection, packet)
        
        ml_detection2 = {
            'is_anomalous': True,
            'confidence': 0.90,
            'severity': AlertSeverity.HIGH,
            'description': 'Test alert 2'
        }
        
        alert2 = alert_manager.create_ml_alert(ml_detection2, packet)
        
        # IDs should be unique and not None
        assert alert1 is not None
        assert alert2 is not None
        assert alert1.id != alert2.id
        assert alert1.id is not None
        assert alert2.id is not None
    
    def test_alert_timestamp_generation(self, alert_manager, sample_packet):
        """Test that alert timestamps are generated correctly"""
        ml_detection = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': AlertSeverity.HIGH,
            'description': 'ML anomaly detected',
            'detection_type': DetectionType.ML
        }
        
        before_creation = datetime.now()
        alert = alert_manager.create_ml_alert(ml_detection, sample_packet)
        after_creation = datetime.now()
        
        assert alert is not None
        assert before_creation <= alert.timestamp <= after_creation
