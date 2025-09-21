"""Unit tests for the NIDSOrchestrator class."""
import pytest
import asyncio
import psutil
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime

from app.core.nids_orchestrator import NIDSOrchestrator
from app.models.schemas import SnifferConfig, MLModelConfig, PacketInfo, Alert, DetectionType, SystemStatus

@pytest.fixture
def mock_components():
    """Create mock components for testing."""
    with patch('app.core.packet_sniffer.PacketSniffer') as mock_sniffer, \
         patch('app.core.ml_detector.MLDetector') as mock_ml_detector, \
         patch('app.core.signature_detector.SignatureDetector') as mock_sig_detector, \
         patch('app.core.alert_manager.AlertManager') as mock_alert_manager:
        
        # Configure mock components
        mock_sniffer.return_value.start = AsyncMock()
        mock_sniffer.return_value.stop = AsyncMock()
        mock_ml_detector.return_value.detect = AsyncMock(return_value=[])
        mock_sig_detector.return_value.detect = AsyncMock(return_value=[])
        mock_alert_manager.return_value.process_alert = AsyncMock()
        
        yield {
            'sniffer': mock_sniffer,
            'ml_detector': mock_ml_detector,
            'sig_detector': mock_sig_detector,
            'alert_manager': mock_alert_manager
        }

@pytest.fixture
def sample_packet():
    """Create a sample packet for testing."""
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.1",
        dest_ip="192.168.1.2",
        source_port=12345,
        dest_port=80,
        protocol="TCP",
        packet_length=100,
        payload_size=len(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        tcp_flags="S"
    )

@pytest.mark.asyncio
async def test_nids_orchestrator_initialization(mock_components):
    """Test NIDSOrchestrator initialization."""
    # Arrange
    sniffer_config = SnifferConfig(interface="eth0", packet_count=100, timeout=30)
    ml_config = MLModelConfig(model_path="test_model.joblib", confidence_threshold=0.8)
    
    # Act
    orchestrator = NIDSOrchestrator(sniffer_config, ml_config)
    
    # Assert
    assert orchestrator.is_running is False
    assert orchestrator.packets_processed == 0
    assert orchestrator.alerts_generated == 0
    mock_components['sniffer'].assert_called_once()
    mock_components['ml_detector'].assert_called_once_with(ml_config)
    mock_components['sig_detector'].assert_called_once()
    mock_components['alert_manager'].assert_called_once()

@pytest.mark.asyncio
async def test_start_and_stop(mock_components):
    """Test starting and stopping the orchestrator."""
    # Arrange
    sniffer_config = SnifferConfig(interface="eth0", packet_count=100, timeout=30)
    ml_config = MLModelConfig(model_path="test_model.joblib", confidence_threshold=0.8)
    orchestrator = NIDSOrchestrator(sniffer_config, ml_config)
    
    # Mock packet processing
    async def mock_process_packet(packet):
        orchestrator.stop()
    
    orchestrator._process_packet = AsyncMock(side_effect=mock_process_packet)
    
    # Act
    await orchestrator.start()
    
    # Assert
    assert orchestrator.is_running is False
    mock_components['sniffer'].return_value.start.assert_called_once()
    mock_components['sniffer'].return_value.stop.assert_called_once()

@pytest.mark.asyncio
async def test_process_packet(mock_components, sample_packet):
    """Test packet processing flow."""
    # Arrange
    sniffer_config = SnifferConfig(interface="eth0", packet_count=100, timeout=30)
    ml_config = MLModelConfig(model_path="test_model.joblib", confidence_threshold=0.8)
    orchestrator = NIDSOrchestrator(sniffer_config, ml_config)
    
    # Configure mocks
    mock_ml_alert = {
        "timestamp": datetime.now(),
        "severity": "high",
        "detection_type": "ml",
        "description": "Anomaly detected",
        "source_ip": "192.168.1.1",
        "dest_ip": "192.168.1.2",
        "protocol": "TCP",
        "confidence_score": 0.95
    }
    mock_sig_alert = {
        "timestamp": datetime.now(),
        "severity": "critical",
        "detection_type": "signature",
        "description": "Signature match detected",
        "source_ip": "192.168.1.1",
        "dest_ip": "192.168.1.2",
        "protocol": "TCP",
        "signature_id": "1001"
    }
    
    mock_components['ml_detector'].return_value.detect.return_value = [mock_ml_alert]
    mock_components['sig_detector'].return_value.detect.return_value = [mock_sig_alert]
    
    # Act
    await orchestrator._process_packet(sample_packet)
    
    # Assert
    assert orchestrator.packets_processed == 1
    mock_components['ml_detector'].return_value.detect.assert_called_once()
    mock_components['sig_detector'].return_value.detect.assert_called_once()
    assert mock_components['alert_manager'].return_value.process_alert.call_count == 2  # One for each alert

@pytest.mark.asyncio
async def test_alert_callback(mock_components, sample_packet):
    """Test alert callback functionality."""
    # Arrange
    mock_callback = AsyncMock()
    sniffer_config = SnifferConfig(interface="eth0", packet_count=100, timeout=30)
    ml_config = MLModelConfig(model_path="test_model.joblib", confidence_threshold=0.8)
    orchestrator = NIDSOrchestrator(sniffer_config, ml_config, alert_callback=mock_callback)
    
    # Configure mocks
    mock_alert = Alert(
        timestamp=sample_packet.timestamp,
        severity="high",
        detection_type=DetectionType.SIGNATURE,
        description="Test alert",
        source_ip=sample_packet.source_ip,
        dest_ip=sample_packet.dest_ip,
        protocol=sample_packet.protocol,
        signature_id="1001"
    )
    
    # Act
    await orchestrator._handle_alert(mock_alert)
    
    # Assert
    mock_callback.assert_called_once_with(mock_alert)
    assert orchestrator.alerts_generated == 1

def test_get_system_status(mock_components):
    """Test system status retrieval."""
    # Arrange
    sniffer_config = SnifferConfig(interface="eth0", packet_count=100, timeout=30)
    ml_config = MLModelConfig(model_path="test_model.joblib", confidence_threshold=0.8)
    orchestrator = NIDSOrchestrator(sniffer_config, ml_config)
    
    # Mock the packet_sniffer
    mock_packet_sniffer = MagicMock()
    mock_packet_sniffer.packets_captured = 100
    orchestrator.packet_sniffer = mock_packet_sniffer
    
    # Create fixed timestamps
    start_time = datetime(2023, 1, 1, 12, 0, 0)
    current_time = datetime(2023, 1, 1, 12, 1, 40)  # 100 seconds later
    expected_uptime = 100.0  # seconds
    
    # Set some state
    orchestrator.is_running = True
    orchestrator.start_time = start_time
    orchestrator.alerts_generated = 5
    orchestrator.ml_predictions = 100
    orchestrator.signature_matches = 5
    
    # Mock psutil and datetime
    with patch('psutil.virtual_memory') as mock_vm, \
         patch('psutil.cpu_percent') as mock_cpu, \
         patch('datetime.datetime') as mock_datetime:
        
        # Setup mock return values
        mock_memory = MagicMock()
        mock_memory.percent = 50.0
        mock_vm.return_value = mock_memory
        mock_cpu.return_value = 25.5
        
        # Mock datetime.now() to return our fixed current time
        mock_datetime.now.return_value = current_time
        
        # Act
        status = orchestrator.get_system_status()
        
        # Assert
        assert status.is_running is True
        # Check that uptime is within 1 second of expected (in case of small timing differences)
        assert abs(status.uptime - expected_uptime) <= 1.0
        assert status.packets_captured == 100
        assert status.alerts_generated == 5
        assert status.ml_predictions == 100
        assert status.signature_matches == 5
        assert status.memory_usage == 50.0
        assert status.cpu_usage == 25.5
