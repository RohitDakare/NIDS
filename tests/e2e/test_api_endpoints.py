"""
End-to-end tests for API endpoints
"""

import pytest
import requests
import time
from unittest.mock import patch, Mock

from app.main import app
from app.models.schemas import SnifferConfig, MLModelConfig
from tests.fixtures.packet_data import create_sniffer_config, create_ml_config

class TestAPIEndpoints:
    """End-to-end tests for API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create a test client"""
        from fastapi.testclient import TestClient
        return TestClient(app)
    
    @pytest.fixture
    def mock_orchestrator(self):
        """Create a mock orchestrator"""
        mock_orchestrator = Mock()
        from app.models.schemas import SystemStatus
        mock_orchestrator.get_system_status.return_value = SystemStatus(
            is_running=False,
            uptime=0.0,
            packets_captured=0,
            alerts_generated=0,
            ml_predictions=0,
            signature_matches=0,
            memory_usage=50.0,
            cpu_usage=25.0
        )
        mock_orchestrator.get_detailed_stats.return_value = {
            'system_status': {
                'is_running': False,
                'uptime': 0.0,
                'packets_captured': 0,
                'alerts_generated': 0,
                'ml_predictions': 0,
                'signature_matches': 0,
                'memory_usage': 50.0,
                'cpu_usage': 25.0
            },
            'component_health': {
                'sniffer_healthy': True,
                'ml_healthy': True,
                'signature_healthy': True,
                'alert_manager_healthy': True
            }
        }
        mock_orchestrator.get_recent_packets.return_value = []
        mock_orchestrator.get_alerts.return_value = []
        mock_orchestrator.get_correlation_analysis.return_value = {
            'total_correlations': 0,
            'correlations': []
        }
        mock_orchestrator.get_signature_rule_stats.return_value = []
        mock_orchestrator.start.return_value = True
        mock_orchestrator.stop.return_value = True
        mock_orchestrator.update_sniffer_config.return_value = True
        mock_orchestrator.update_ml_config.return_value = True
        mock_orchestrator.resolve_alert.return_value = True
        mock_orchestrator.clear_alerts.return_value = None
        mock_orchestrator.export_alerts.return_value = '{"alerts": []}'
        mock_orchestrator.enable_signature_rule.return_value = True
        mock_orchestrator.disable_signature_rule.return_value = True
        
        # Mock the alert manager
        mock_orchestrator.alert_manager = Mock()
        mock_orchestrator.alert_manager.get_alert_by_id.return_value = None
        mock_orchestrator.alert_manager.delete_alert.return_value = True
        
        with patch('app.api.routes.nids_orchestrator', mock_orchestrator):
            yield mock_orchestrator
    
    def test_root_endpoint(self, client):
        """Test root endpoint"""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "status" in data
        assert data["status"] == "running"
    
    def test_system_info_endpoint(self, client):
        """Test system info endpoint"""
        response = client.get("/info")
        
        assert response.status_code == 200
        data = response.json()
        assert "system" in data
        assert "version" in data
        assert "description" in data
        assert "features" in data
        assert "endpoints" in data
    
    def test_health_check_endpoint(self, client, mock_orchestrator):
        """Test health check endpoint"""
        response = client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "system_running" in data
        assert "component_health" in data
        assert "uptime_seconds" in data
    
    def test_system_status_endpoint(self, client, mock_orchestrator):
        """Test system status endpoint"""
        response = client.get("/api/v1/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "is_running" in data
        assert "uptime" in data
        assert "packets_captured" in data
        assert "alerts_generated" in data
        assert "ml_predictions" in data
        assert "signature_matches" in data
        assert "memory_usage" in data
        assert "cpu_usage" in data
    
    def test_start_sniffer_endpoint(self, client, mock_orchestrator):
        """Test start sniffer endpoint"""
        response = client.post("/api/v1/start-sniffer", json={})
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "system_status" in data
        assert data["status"] == "success"
        
        mock_orchestrator.start.assert_called_once()
    
    def test_start_sniffer_with_config(self, client, mock_orchestrator):
        """Test start sniffer endpoint with configuration"""
        config = {
            "interface": "eth0",
            "packet_count": 1000,
            "timeout": 30
        }
        
        response = client.post("/api/v1/start-sniffer", json={"config": config})
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        mock_orchestrator.update_sniffer_config.assert_called_once()
        mock_orchestrator.start.assert_called_once()
    
    def test_stop_sniffer_endpoint(self, client, mock_orchestrator):
        """Test stop sniffer endpoint"""
        response = client.post("/api/v1/stop-sniffer", json={})
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "system_status" in data
        assert data["status"] == "success"
        
        mock_orchestrator.stop.assert_called_once()
    
    def test_get_packets_endpoint(self, client, mock_orchestrator):
        """Test get packets endpoint"""
        response = client.get("/api/v1/packets?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        assert "packets" in data
        assert "total_count" in data
        assert "page" in data
        assert "page_size" in data
        
        mock_orchestrator.get_recent_packets.assert_called_once_with(limit=10)
    
    def test_get_alerts_endpoint(self, client, mock_orchestrator):
        """Test get alerts endpoint"""
        response = client.get("/api/v1/alerts?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total_count" in data
        assert "page" in data
        assert "page_size" in data
        
        mock_orchestrator.get_alerts.assert_called_once_with(limit=10)
    
    def test_get_alerts_with_filters(self, client, mock_orchestrator):
        """Test get alerts endpoint with filters"""
        response = client.get("/api/v1/alerts?limit=5&severity=high&detection_type=ml")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        
        mock_orchestrator.get_alerts.assert_called_once_with(
            limit=5, severity='high', detection_type='ml'
        )
    
    def test_get_alert_by_id_endpoint(self, client, mock_orchestrator):
        """Test get alert by ID endpoint"""
        mock_alert = Mock()
        mock_alert.id = "alert_123"
        mock_alert.severity = "high"
        mock_alert.detection_type = "ml"
        mock_alert.description = "Test alert"
        mock_alert.source_ip = "192.168.1.1"
        mock_alert.dest_ip = "192.168.1.2"
        mock_alert.protocol = "TCP"
        mock_alert.packet_data = {"test": "data"}
        mock_alert.timestamp = "2024-01-01T00:00:00Z"
        mock_alert.resolved = False
        mock_alert.resolution_notes = None
        mock_alert.confidence_score = 0.95
        mock_alert.is_resolved = False
        
        mock_orchestrator.alert_manager.get_alert_by_id.return_value = mock_alert
        
        response = client.get("/api/v1/alerts/alert_123")
        
        assert response.status_code == 200
        mock_orchestrator.alert_manager.get_alert_by_id.assert_called_once_with("alert_123")
    
    def test_get_alert_by_id_not_found(self, client, mock_orchestrator):
        """Test get alert by ID endpoint when alert not found"""
        mock_orchestrator.alert_manager.get_alert_by_id.return_value = None
        
        response = client.get("/api/v1/alerts/nonexistent")
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"]
    
    def test_resolve_alert_endpoint(self, client, mock_orchestrator):
        """Test resolve alert endpoint"""
        response = client.post("/api/v1/alerts/alert_123/resolve?resolution_notes=Resolved")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.resolve_alert.assert_called_once_with("alert_123", "Resolved")
    
    def test_resolve_alert_not_found(self, client, mock_orchestrator):
        """Test resolve alert endpoint when alert not found"""
        mock_orchestrator.resolve_alert.return_value = False
        
        response = client.post("/api/v1/alerts/nonexistent/resolve")
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"]
    
    def test_delete_alert_endpoint(self, client, mock_orchestrator):
        """Test delete alert endpoint"""
        mock_orchestrator.alert_manager.delete_alert.return_value = True
        
        response = client.delete("/api/v1/alerts/alert_123")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.alert_manager.delete_alert.assert_called_once_with("alert_123")
    
    def test_delete_alert_not_found(self, client, mock_orchestrator):
        """Test delete alert endpoint when alert not found"""
        mock_orchestrator.alert_manager.delete_alert.return_value = False
        
        response = client.delete("/api/v1/alerts/nonexistent")
        
        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"]
    
    def test_get_stats_endpoint(self, client, mock_orchestrator):
        """Test get stats endpoint"""
        response = client.get("/api/v1/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "system_status" in data
        assert "component_health" in data
        
        mock_orchestrator.get_detailed_stats.assert_called_once()
    
    def test_get_correlation_endpoint(self, client, mock_orchestrator):
        """Test get correlation analysis endpoint"""
        response = client.get("/api/v1/correlation")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_correlations" in data
        assert "correlations" in data
        
        mock_orchestrator.get_correlation_analysis.assert_called_once()
    
    def test_get_signature_rules_endpoint(self, client, mock_orchestrator):
        """Test get signature rules endpoint"""
        response = client.get("/api/v1/signature-rules")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        mock_orchestrator.get_signature_rule_stats.assert_called_once()
    
    def test_enable_signature_rule_endpoint(self, client, mock_orchestrator):
        """Test enable signature rule endpoint"""
        response = client.post("/api/v1/signature-rules/rule_123/enable")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.enable_signature_rule.assert_called_once_with("rule_123")
    
    def test_disable_signature_rule_endpoint(self, client, mock_orchestrator):
        """Test disable signature rule endpoint"""
        response = client.post("/api/v1/signature-rules/rule_123/disable")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.disable_signature_rule.assert_called_once_with("rule_123")
    
    def test_update_sniffer_config_endpoint(self, client, mock_orchestrator):
        """Test update sniffer config endpoint"""
        config = {
            "interface": "eth0",
            "packet_count": 2000,
            "timeout": 60
        }
        
        response = client.post("/api/v1/config/sniffer", json=config)
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "config" in data
        assert data["status"] == "success"
        
        mock_orchestrator.update_sniffer_config.assert_called_once()
    
    def test_update_ml_config_endpoint(self, client, mock_orchestrator):
        """Test update ML config endpoint"""
        config = {
            "model_path": "app/ml_models/new_model.joblib",
            "confidence_threshold": 0.9
        }

        response = client.post("/api/v1/config/ml", json=config)

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert "config" in data
        assert data["status"] == "success"

        mock_orchestrator.update_ml_config.assert_called_once()
    
    def test_clear_alerts_endpoint(self, client, mock_orchestrator):
        """Test clear alerts endpoint"""
        response = client.post("/api/v1/alerts/clear")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.clear_alerts.assert_called_once()
    
    def test_clear_alerts_with_age_filter(self, client, mock_orchestrator):
        """Test clear alerts endpoint with age filter"""
        response = client.post("/api/v1/alerts/clear?older_than_days=7")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "message" in data
        assert data["status"] == "success"
        
        mock_orchestrator.clear_alerts.assert_called_once()
    
    def test_export_alerts_json_endpoint(self, client, mock_orchestrator):
        """Test export alerts JSON endpoint"""
        response = client.get("/api/v1/export/alerts?format=json")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "format" in data
        assert "data" in data
        assert "message" in data
        assert data["status"] == "success"
        assert data["format"] == "json"
        
        mock_orchestrator.export_alerts.assert_called_once_with(format="json")
    
    def test_export_alerts_csv_endpoint(self, client, mock_orchestrator):
        """Test export alerts CSV endpoint"""
        response = client.get("/api/v1/export/alerts?format=csv")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "format" in data
        assert "data" in data
        assert "message" in data
        assert data["status"] == "success"
        assert data["format"] == "csv"
        
        mock_orchestrator.export_alerts.assert_called_once_with(format="csv")
    
    def test_export_alerts_invalid_format(self, client, mock_orchestrator):
        """Test export alerts endpoint with invalid format"""
        response = client.get("/api/v1/export/alerts?format=invalid")
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "Invalid format" in data["detail"]
    
    def test_error_handling(self, client, mock_orchestrator):
        """Test error handling in endpoints"""
        # Mock an error in the orchestrator
        mock_orchestrator.start.side_effect = Exception("Test error")
        
        response = client.post("/api/v1/start-sniffer", json={})
        
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "Test error" in data["detail"]
    
    def test_nids_not_initialized(self, client):
        """Test endpoints when NIDS is not initialized"""
        with patch('app.api.routes.nids_orchestrator', None):
            response = client.get("/api/v1/status")
            
            assert response.status_code == 503
            data = response.json()
            assert "detail" in data
            assert "not initialized" in data["detail"]
