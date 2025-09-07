"""
Unit tests for ML Detector
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from app.core.ml_detector import MLDetector
from app.models.schemas import MLModelConfig, PacketInfo, DetectionType, AlertSeverity
from tests.fixtures.packet_data import create_tcp_packet, create_suspicious_packet, create_ml_config

class TestMLDetector:
    """Test cases for MLDetector class"""
    
    @pytest.fixture
    def ml_config(self):
        """Create a test ML configuration"""
        return create_ml_config()
    
    @pytest.fixture
    def ml_detector(self, ml_config):
        """Create a test ML detector instance"""
        with patch('joblib.load') as mock_load:
            mock_model = Mock()
            mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])
            mock_model.predict.return_value = np.array([1])
            mock_load.return_value = mock_model
            
            detector = MLDetector(ml_config)
            detector.model = mock_model
            return detector
    
    def test_initialization(self, ml_detector, ml_config):
        """Test ML detector initialization"""
        assert ml_detector.config == ml_config
        assert ml_detector.is_loaded == True
        assert ml_detector.predictions_count == 0
        assert ml_detector.anomalies_detected == 0
    
    def test_predict_normal_packet(self, ml_detector):
        """Test prediction on normal packet"""
        packet = create_tcp_packet()
        
        is_anomalous, confidence, additional_info = ml_detector.predict(packet)
        
        assert is_anomalous == True  # Mock returns 1 (anomalous)
        assert confidence == 0.8
        assert 'model_type' in additional_info
        assert ml_detector.predictions_count == 1
        assert ml_detector.anomalies_detected == 1
    
    def test_predict_suspicious_packet(self, ml_detector):
        """Test prediction on suspicious packet"""
        packet = create_suspicious_packet()
        
        is_anomalous, confidence, additional_info = ml_detector.predict(packet)
        
        assert is_anomalous == True
        assert confidence == 0.8
        assert ml_detector.predictions_count == 1
        assert ml_detector.anomalies_detected == 1
    
    def test_predict_with_anomaly_detection_model(self, ml_config):
        """Test prediction with anomaly detection model (IsolationForest)"""
        # Create a simple mock model that behaves like an anomaly detection model
        class MockAnomalyModel:
            def predict(self, features):
                return np.array([-1])  # Always return anomaly
            
            def decision_function(self, features):
                return np.array([-0.5])  # Anomaly score
        
        with patch('joblib.load') as mock_load:
            mock_load.return_value = MockAnomalyModel()
            
            # Create detector
            detector = MLDetector(ml_config)
            
            # Mock the feature extraction method to return a proper numpy array
            mock_features = np.array([[1.0, 2.0, 3.0, 4.0, 5.0]])  # 5 features
            detector._extract_features = Mock(return_value=mock_features)
            
            # Verify the model was loaded
            assert detector.model is not None
            assert detector.is_loaded == True
            
            packet = create_tcp_packet()
            is_anomalous, confidence, additional_info = detector.predict(packet)
            
            assert is_anomalous == True
            assert confidence > 0.0  # Should have some confidence score
    
    def test_extract_features(self, ml_detector):
        """Test feature extraction from packets"""
        packets = [create_tcp_packet(), create_suspicious_packet()]
        
        features = ml_detector._extract_features(packets)
        
        assert features is not None
        assert features.shape[0] == 2  # Two packets
        assert features.shape[1] == len(ml_detector.feature_columns)
    
    def test_extract_features_empty_list(self, ml_detector):
        """Test feature extraction with empty packet list"""
        features = ml_detector._extract_features([])
        assert features is None
    
    def test_extract_features_single_packet(self, ml_detector):
        """Test feature extraction with single packet"""
        packet = create_tcp_packet()
        features = ml_detector._extract_features([packet])
        
        assert features is not None
        assert features.shape[0] == 1
        assert features.shape[1] == len(ml_detector.feature_columns)
    
    def test_is_private_ip(self, ml_detector):
        """Test private IP detection"""
        # Private IPs
        assert ml_detector._is_private_ip("10.0.0.1") == True
        assert ml_detector._is_private_ip("172.16.0.1") == True
        assert ml_detector._is_private_ip("192.168.1.1") == True
        
        # Public IPs
        assert ml_detector._is_private_ip("8.8.8.8") == False
        assert ml_detector._is_private_ip("1.1.1.1") == False
        
        # Invalid IPs
        assert ml_detector._is_private_ip("invalid") == False
        assert ml_detector._is_private_ip("192.168.1") == False
    
    def test_get_detection_info(self, ml_detector):
        """Test getting detection information"""
        packet = create_tcp_packet()
        
        detection_info = ml_detector.get_detection_info(packet)
        
        assert 'is_anomalous' in detection_info
        assert 'confidence' in detection_info
        assert 'severity' in detection_info
        assert 'description' in detection_info
        assert 'detection_type' in detection_info
        assert 'model_info' in detection_info
        
        assert detection_info['detection_type'] == DetectionType.ML
        assert detection_info['severity'] in [AlertSeverity.LOW, AlertSeverity.MEDIUM, 
                                            AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    
    def test_get_stats(self, ml_detector):
        """Test getting ML detector statistics"""
        # Make some predictions first
        packet = create_tcp_packet()
        ml_detector.predict(packet)
        ml_detector.predict(packet)
        
        stats = ml_detector.get_stats()
        
        assert 'is_loaded' in stats
        assert 'model_type' in stats
        assert 'predictions_count' in stats
        assert 'anomalies_detected' in stats
        assert 'detection_rate' in stats
        assert 'confidence_threshold' in stats
        assert 'feature_count' in stats
        
        assert stats['predictions_count'] == 2
        assert stats['anomalies_detected'] == 2
        assert stats['detection_rate'] == 1.0  # 100% detection rate
    
    def test_retrain_model(self, ml_detector):
        """Test model retraining"""
        training_data = [create_tcp_packet(), create_suspicious_packet()]
        labels = [0, 1]  # Normal, Anomalous
        
        with patch('joblib.dump') as mock_dump:
            result = ml_detector.retrain_model(training_data, labels)
            
            assert result == True
            mock_dump.assert_called_once()
    
    def test_retrain_model_empty_data(self, ml_detector):
        """Test model retraining with empty data"""
        result = ml_detector.retrain_model([], [])
        assert result == False
    
    def test_model_not_loaded(self, ml_config):
        """Test behavior when model is not loaded"""
        detector = MLDetector(ml_config)
        detector.is_loaded = False
        
        packet = create_tcp_packet()
        is_anomalous, confidence, additional_info = detector.predict(packet)
        
        assert is_anomalous == False
        assert confidence == 0.0
        assert additional_info == {}
    
    def test_feature_extraction_error_handling(self, ml_detector):
        """Test feature extraction error handling"""
        # Create a packet with invalid data
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="invalid_ip",
            dest_ip="192.168.1.2",
            protocol="TCP",
            source_port=12345,
            dest_port=80,
            packet_length=100,
            tcp_flags="SYN",
            payload_size=20
        )
        
        features = ml_detector._extract_features([packet])
        
        # Should still work with default values for invalid IP
        assert features is not None
        assert features.shape[0] == 1
