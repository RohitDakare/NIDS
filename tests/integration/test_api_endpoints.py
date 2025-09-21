"""Integration tests for API endpoints."""
import pytest
import httpx
import asyncio
from fastapi import status
from unittest.mock import patch, MagicMock

from app.main import app
from app.models.schemas import SystemStatus, SnifferConfig, MLModelConfig

@pytest.fixture
async def test_client():
    """Create a test client for the FastAPI app."""
    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.mark.asyncio
async def test_root_endpoint(test_client):
    """Test the root endpoint."""
    response = await test_client.get("/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "status" in data

@pytest.mark.asyncio
async def test_system_status_endpoint(test_client):
    """Test the system status endpoint."""
    # Mock the NIDSOrchestrator instance
    mock_orchestrator = MagicMock()
    mock_status = SystemStatus(
        status="running",
        start_time="2023-01-01T00:00:00",
        uptime_seconds=3600,
        packets_processed=1000,
        alerts_generated=10,
        ml_predictions=1000,
        signature_matches=5,
        cpu_usage=25.5,
        memory_usage=512.3
    )
    mock_orchestrator.get_system_status.return_value = mock_status
    
    with patch('app.api.routes.nids_orchestrator', mock_orchestrator):
        response = await test_client.get("/api/v1/status")
        
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "running"
    assert data["packets_processed"] == 1000
    assert data["alerts_generated"] == 10

@pytest.mark.asyncio
async def test_start_stop_sniffing(test_client):
    """Test starting and stopping packet sniffing."""
    # Mock the NIDSOrchestrator instance
    mock_orchestrator = MagicMock()
    mock_orchestrator.start = AsyncMock()
    mock_orchestrator.stop = AsyncMock()
    
    with patch('app.api.routes.nids_orchestrator', mock_orchestrator):
        # Test starting sniffing
        start_response = await test_client.post("/api/v1/sniffer/start")
        assert start_response.status_code == status.HTTP_200_OK
        mock_orchestrator.start.assert_awaited_once()
        
        # Test stopping sniffing
        stop_response = await test_client.post("/api/v1/sniffer/stop")
        assert stop_response.status_code == status.HTTP_200_OK
        mock_orchestrator.stop.assert_awaited_once()

@pytest.mark.asyncio
async def test_get_alerts(test_client):
    """Test retrieving alerts."""
    # Mock the database query
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_cursor = MagicMock()
    
    sample_alerts = [
        {
            "_id": "507f1f77bcf86cd799439011",
            "timestamp": "2023-01-01T12:00:00",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "severity": "high",
            "message": "Suspicious activity detected"
        }
    ]
    
    mock_cursor.to_list.return_value = sample_alerts
    mock_collection.find.return_value = mock_cursor
    mock_db.__getitem__.return_value = mock_collection
    
    with patch('app.api.routes.db', mock_db):
        response = await test_client.get("/api/v1/alerts")
        
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["source_ip"] == "192.168.1.1"
    assert data[0]["severity"] == "high"

@pytest.mark.asyncio
async def test_update_config(test_client):
    """Test updating configuration."""
    # Mock the NIDSOrchestrator instance
    mock_orchestrator = MagicMock()
    
    config_update = {
        "sniffer": {
            "interface": "eth0",
            "packet_count": 500,
            "timeout": 60
        },
        "ml_model": {
            "model_path": "new_model.joblib",
            "confidence_threshold": 0.9
        }
    }
    
    with patch('app.api.routes.nids_orchestrator', mock_orchestrator):
        response = await test_client.put(
            "/api/v1/config",
            json=config_update
        )
        
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "success"
    
    # Verify the orchestrator was updated
    mock_orchestrator.update_config.assert_called_once()
    args, _ = mock_orchestrator.update_config.call_args
    assert isinstance(args[0], SnifferConfig)
    assert isinstance(args[1], MLModelConfig)
    assert args[0].packet_count == 500
    assert args[1].confidence_threshold == 0.9
