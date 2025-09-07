"""
Integration tests for NIDS Orchestrator
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from app.core.nids_orchestrator import NIDSOrchestrator
from app.models.schemas import SnifferConfig, MLModelConfig, PacketInfo
from tests.fixtures.packet_data import create_sniffer_config, create_ml_config, create_tcp_packet

class TestNIDSOrchestrator:
    """Integration tests for NIDSOrchestrator class"""
    
    @pytest.fixture
    def sniffer_config(self):
        """Create a test sniffer configuration"""
        return create_sniffer_config()
    
    @pytest.fixture
    def ml_config(self):
        """Create a test ML configuration"""
        return create_ml_config()
    
    @pytest.fixture
    def orchestrator(self, sniffer_config, ml_config):
        """Create a test NIDS orchestrator instance"""
        with patch('app.core.packet_sniffer.PacketSniffer') as mock_sniffer, \
             patch('app.core.ml_detector.MLDetector') as mock_ml, \
             patch('app.core.signature_detector.SignatureDetector') as mock_sig, \
             patch('app.core.alert_manager.AlertManager') as mock_alert:
            
            # Mock the components
            mock_sniffer_instance = Mock()
            mock_sniffer_instance.is_running = False
            mock_sniffer_instance.packets_captured = 0
            mock_sniffer_instance.get_stats.return_value = {
                'is_running': False,
                'uptime': 0,
                'packets_captured': 0,
                'buffer_size': 0,
                'interface': 'lo'
            }
            mock_sniffer_instance.get_recent_packets.return_value = []
            mock_sniffer.return_value = mock_sniffer_instance
            
            mock_ml_instance = Mock()
            mock_ml_instance.is_loaded = True
            mock_ml_instance.get_stats.return_value = {
                'is_loaded': True,
                'model_type': 'RandomForestClassifier',
                'predictions_count': 0,
                'anomalies_detected': 0,
                'detection_rate': 0.0,
                'confidence_threshold': 0.8,
                'feature_count': 7
            }
            mock_ml.return_value = mock_ml_instance
            
            mock_sig_instance = Mock()
            mock_sig_instance.get_stats.return_value = {
                'total_rules': 10,
                'enabled_rules': 8,
                'matches_count': 0,
                'detection_rate': 0.0
            }
            mock_sig_instance.get_rule_stats.return_value = []
            mock_sig.return_value = mock_sig_instance
            
            mock_alert_instance = Mock()
            mock_alert_instance.get_stats.return_value = {
                'total_alerts': 0,
                'resolved_alerts': 0,
                'unresolved_alerts': 0,
                'severity_distribution': {},
                'detection_type_distribution': {}
            }
            mock_alert_instance.get_alerts.return_value = []
            mock_alert_instance.get_correlation_analysis.return_value = {
                'total_correlations': 0,
                'correlations': []
            }
            mock_alert.return_value = mock_alert_instance
            
            orchestrator = NIDSOrchestrator(
                sniffer_config=sniffer_config,
                ml_config=ml_config,
                alert_callback=Mock()
            )
            
            # Replace real components with mocks
            orchestrator.packet_sniffer = mock_sniffer_instance
            orchestrator.ml_detector = mock_ml_instance
            orchestrator.signature_detector = mock_sig_instance
            orchestrator.alert_manager = mock_alert_instance
            
            # Store references to mocked components
            orchestrator._mock_sniffer = mock_sniffer_instance
            orchestrator._mock_ml = mock_ml_instance
            orchestrator._mock_sig = mock_sig_instance
            orchestrator._mock_alert = mock_alert_instance
            
            return orchestrator
    
    def test_initialization(self, orchestrator, sniffer_config, ml_config):
        """Test orchestrator initialization"""
        assert orchestrator.sniffer_config == sniffer_config
        assert orchestrator.ml_config == ml_config
        assert orchestrator.is_running == False
        assert orchestrator.start_time is None
        assert orchestrator.packets_processed == 0
        assert orchestrator.alerts_generated == 0
        assert orchestrator.ml_predictions == 0
        assert orchestrator.signature_matches == 0
    
    def test_start_system(self, orchestrator):
        """Test starting the NIDS system"""
        result = orchestrator.start()
        
        assert result == True
        assert orchestrator.is_running == True
        assert orchestrator.start_time is not None
        assert orchestrator.packets_processed == 0
        assert orchestrator.alerts_generated == 0
    
    def test_stop_system(self, orchestrator):
        """Test stopping the NIDS system"""
        # Start first
        orchestrator.start()
        assert orchestrator.is_running == True
        
        # Stop
        result = orchestrator.stop()
        
        assert result == True
        assert orchestrator.is_running == False
        orchestrator._mock_sniffer.stop.assert_called_once()
    
    def test_start_already_running(self, orchestrator):
        """Test starting when already running"""
        orchestrator.start()
        result = orchestrator.start()  # Try to start again
        
        assert result == False
    
    def test_stop_not_running(self, orchestrator):
        """Test stopping when not running"""
        result = orchestrator.stop()
        assert result == False
    
    def test_process_packet_ml_detection(self, orchestrator):
        """Test packet processing with ML detection"""
        orchestrator.start()
        
        # Mock ML detection result
        orchestrator._mock_ml.get_detection_info.return_value = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': 'high',
            'description': 'ML anomaly detected',
            'detection_type': 'ml'
        }
        
        # Mock signature detection result
        orchestrator._mock_sig.detect.return_value = []
        
        # Mock alert creation
        mock_alert = Mock()
        orchestrator._mock_alert.create_ml_alert.return_value = mock_alert
        
        packet = create_tcp_packet()
        orchestrator._process_packet(packet)
        
        # Verify ML detection was called
        orchestrator._mock_ml.get_detection_info.assert_called_once_with(packet)
        assert orchestrator.ml_predictions == 1
        
        # Verify alert was created
        orchestrator._mock_alert.create_ml_alert.assert_called_once()
        assert orchestrator.alerts_generated == 1
    
    def test_process_packet_signature_detection(self, orchestrator):
        """Test packet processing with signature detection"""
        orchestrator.start()
        
        # Mock ML detection result (no anomaly)
        orchestrator._mock_ml.get_detection_info.return_value = {
            'is_anomalous': False,
            'confidence': 0.2,
            'severity': 'low',
            'description': 'Normal traffic',
            'detection_type': 'ml'
        }
        
        # Mock signature detection result
        signature_detection = {
            'rule_id': 'test_rule',
            'severity': 'high',
            'description': 'Signature match'
        }
        orchestrator._mock_sig.detect.return_value = [signature_detection]
        
        # Mock alert creation
        mock_alert = Mock()
        orchestrator._mock_alert.create_signature_alert.return_value = mock_alert
        
        packet = create_tcp_packet()
        orchestrator._process_packet(packet)
        
        # Verify signature detection was called
        orchestrator._mock_sig.detect.assert_called_once_with(packet)
        assert orchestrator.signature_matches == 1
        
        # Verify alert was created
        orchestrator._mock_alert.create_signature_alert.assert_called_once()
        assert orchestrator.alerts_generated == 1
    
    def test_process_packet_hybrid_detection(self, orchestrator):
        """Test packet processing with both ML and signature detection"""
        orchestrator.start()
        
        # Mock ML detection result (anomaly)
        orchestrator._mock_ml.get_detection_info.return_value = {
            'is_anomalous': True,
            'confidence': 0.85,
            'severity': 'high',
            'description': 'ML anomaly detected',
            'detection_type': 'ml'
        }
        
        # Mock signature detection result
        signature_detection = {
            'rule_id': 'test_rule',
            'severity': 'critical',
            'description': 'Signature match'
        }
        orchestrator._mock_sig.detect.return_value = [signature_detection]
        
        # Mock alert creation
        mock_ml_alert = Mock()
        mock_sig_alert = Mock()
        mock_hybrid_alert = Mock()
        
        orchestrator._mock_alert.create_ml_alert.return_value = mock_ml_alert
        orchestrator._mock_alert.create_signature_alert.return_value = mock_sig_alert
        orchestrator._mock_alert.create_hybrid_alert.return_value = mock_hybrid_alert
        
        packet = create_tcp_packet()
        orchestrator._process_packet(packet)
        
        # Verify both detections were called
        orchestrator._mock_ml.get_detection_info.assert_called_once_with(packet)
        orchestrator._mock_sig.detect.assert_called_once_with(packet)
        
        # Verify all three types of alerts were created
        orchestrator._mock_alert.create_ml_alert.assert_called_once()
        orchestrator._mock_alert.create_signature_alert.assert_called_once()
        orchestrator._mock_alert.create_hybrid_alert.assert_called_once()
        
        assert orchestrator.alerts_generated == 3
    
    def test_get_system_status(self, orchestrator):
        """Test getting system status"""
        orchestrator.start()
        
        with patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.cpu_percent') as mock_cpu:
            
            mock_memory.return_value.percent = 50.0
            mock_cpu.return_value = 25.0
            
            status = orchestrator.get_system_status()
            
            assert status.is_running == True
            assert status.uptime >= 0
            assert status.memory_usage == 50.0
            assert status.cpu_usage == 25.0
            assert status.packets_captured == 0
            assert status.alerts_generated == 0
            assert status.ml_predictions == 0
            assert status.signature_matches == 0
    
    def test_get_detailed_stats(self, orchestrator):
        """Test getting detailed statistics"""
        stats = orchestrator.get_detailed_stats()
        
        assert 'system_status' in stats
        assert 'sniffer_stats' in stats
        assert 'ml_stats' in stats
        assert 'signature_stats' in stats
        assert 'alert_stats' in stats
        assert 'performance_stats' in stats
        assert 'detection_rates' in stats
        assert 'component_health' in stats
        
        # Verify component health
        component_health = stats['component_health']
        assert 'sniffer_healthy' in component_health
        assert 'ml_healthy' in component_health
        assert 'signature_healthy' in component_health
        assert 'alert_manager_healthy' in component_health
    
    def test_get_recent_packets(self, orchestrator):
        """Test getting recent packets"""
        mock_packets = [create_tcp_packet()]
        orchestrator._mock_sniffer.get_recent_packets.return_value = mock_packets
        
        packets = orchestrator.get_recent_packets(limit=10)
        
        assert packets == mock_packets
        orchestrator._mock_sniffer.get_recent_packets.assert_called_once_with(10)
    
    def test_get_alerts(self, orchestrator):
        """Test getting alerts"""
        mock_alerts = [Mock()]
        orchestrator._mock_alert.get_alerts.return_value = mock_alerts
        
        alerts = orchestrator.get_alerts(limit=10, severity='high')
        
        assert alerts == mock_alerts
        orchestrator._mock_alert.get_alerts.assert_called_once_with(limit=10, severity='high')
    
    def test_resolve_alert(self, orchestrator):
        """Test resolving an alert"""
        orchestrator._mock_alert.resolve_alert.return_value = True
        
        result = orchestrator.resolve_alert('alert_123', 'Resolved by admin')
        
        assert result == True
        orchestrator._mock_alert.resolve_alert.assert_called_once_with('alert_123', 'Resolved by admin')
    
    def test_clear_alerts(self, orchestrator):
        """Test clearing alerts"""
        orchestrator.clear_alerts()
        orchestrator._mock_alert.clear_alerts.assert_called_once()
    
    def test_export_alerts(self, orchestrator):
        """Test exporting alerts"""
        mock_export_data = '{"alerts": []}'
        orchestrator._mock_alert.export_alerts.return_value = mock_export_data
        
        result = orchestrator.export_alerts('json')
        
        assert result == mock_export_data
        orchestrator._mock_alert.export_alerts.assert_called_once_with('json', None)
    
    def test_update_sniffer_config(self, orchestrator):
        """Test updating sniffer configuration"""
        new_config = SnifferConfig(
            interface="eth0",
            packet_count=2000,
            timeout=60
        )
        
        result = orchestrator.update_sniffer_config(new_config)
        
        assert result == True
        assert orchestrator.sniffer_config == new_config
    
    def test_update_ml_config(self, orchestrator):
        """Test updating ML configuration"""
        new_config = MLModelConfig(
            model_path="models/new_model.joblib",
            confidence_threshold=0.9
        )
        
        result = orchestrator.update_ml_config(new_config)
        
        assert result == True
        assert orchestrator.ml_config == new_config
    
    def test_get_correlation_analysis(self, orchestrator):
        """Test getting correlation analysis"""
        mock_correlation = {'total_correlations': 5, 'correlations': []}
        orchestrator._mock_alert.get_correlation_analysis.return_value = mock_correlation
        
        result = orchestrator.get_correlation_analysis()
        
        assert result == mock_correlation
        orchestrator._mock_alert.get_correlation_analysis.assert_called_once()
    
    def test_get_signature_rule_stats(self, orchestrator):
        """Test getting signature rule statistics"""
        mock_rules = [{'rule_id': 'rule1', 'name': 'Test Rule'}]
        orchestrator._mock_sig.get_rule_stats.return_value = mock_rules
        
        result = orchestrator.get_signature_rule_stats()
        
        assert result == mock_rules
        orchestrator._mock_sig.get_rule_stats.assert_called_once()
    
    def test_enable_signature_rule(self, orchestrator):
        """Test enabling a signature rule"""
        orchestrator._mock_sig.enable_rule.return_value = True
        
        result = orchestrator.enable_signature_rule('rule_123')
        
        assert result == True
        orchestrator._mock_sig.enable_rule.assert_called_once_with('rule_123')
    
    def test_disable_signature_rule(self, orchestrator):
        """Test disabling a signature rule"""
        orchestrator._mock_sig.disable_rule.return_value = True
        
        result = orchestrator.disable_signature_rule('rule_123')
        
        assert result == True
        orchestrator._mock_sig.disable_rule.assert_called_once_with('rule_123')
    
    def test_performance_stats_update(self, orchestrator):
        """Test performance statistics update"""
        orchestrator.start()
        
        # Process a packet to update performance stats
        packet = create_tcp_packet()
        orchestrator._process_packet(packet)
        
        # Check performance stats
        assert orchestrator.performance_stats['total_processing_time'] > 0
        assert orchestrator.performance_stats['avg_processing_time'] > 0
        assert orchestrator.performance_stats['min_processing_time'] > 0
        assert orchestrator.performance_stats['max_processing_time'] > 0
    
    def test_error_handling_in_packet_processing(self, orchestrator):
        """Test error handling in packet processing"""
        orchestrator.start()
        
        # Mock an error in ML detection
        orchestrator._mock_ml.get_detection_info.side_effect = Exception("ML Error")
        
        packet = create_tcp_packet()
        
        # Should not raise exception
        orchestrator._process_packet(packet)
        
        # Should still increment packet counter
        assert orchestrator.packets_processed == 1
