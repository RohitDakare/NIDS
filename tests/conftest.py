"""
Pytest configuration and shared fixtures
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch

# Add the project root to Python path
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture(scope="session")
def test_data_dir():
    """Create a temporary directory for test data"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture(scope="session")
def test_models_dir(test_data_dir):
    """Create a temporary directory for test models"""
    models_dir = os.path.join(test_data_dir, "app/ml_models")
    os.makedirs(models_dir, exist_ok=True)
    return models_dir

@pytest.fixture(scope="session")
def test_logs_dir(test_data_dir):
    """Create a temporary directory for test logs"""
    logs_dir = os.path.join(test_data_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir

@pytest.fixture(autouse=True)
def mock_environment_variables():
    """Mock environment variables for testing"""
    with patch.dict(os.environ, {
        'INTERFACE': 'lo',
        'PACKET_COUNT': '100',
        'TIMEOUT': '30',
        'MODEL_PATH': 'app/ml_models/test_model.joblib',
        'CONFIDENCE_THRESHOLD': '0.8',
        'API_HOST': '127.0.0.1',
        'API_PORT': '8000',
        'LOG_LEVEL': 'INFO',
        'LOG_FILE': 'logs/test.log'
    }):
        yield

@pytest.fixture
def mock_scapy():
    """Mock Scapy for testing"""
    with patch('scapy.all.sniff') as mock_sniff, \
         patch('scapy.all.IP') as mock_ip, \
         patch('scapy.all.TCP') as mock_tcp, \
         patch('scapy.all.UDP') as mock_udp, \
         patch('scapy.all.ICMP') as mock_icmp, \
         patch('scapy.all.ARP') as mock_arp:
        
        # Configure mocks
        mock_sniff.return_value = []
        
        yield {
            'sniff': mock_sniff,
            'IP': mock_ip,
            'TCP': mock_tcp,
            'UDP': mock_udp,
            'ICMP': mock_icmp,
            'ARP': mock_arp
        }

@pytest.fixture
def mock_psutil():
    """Mock psutil for testing"""
    with patch('psutil.virtual_memory') as mock_memory, \
         patch('psutil.cpu_percent') as mock_cpu:
        
        # Configure mocks
        mock_memory.return_value.percent = 50.0
        mock_cpu.return_value = 25.0
        
        yield {
            'memory': mock_memory,
            'cpu': mock_cpu
        }

@pytest.fixture
def mock_joblib():
    """Mock joblib for testing"""
    with patch('joblib.load') as mock_load, \
         patch('joblib.dump') as mock_dump:
        
        # Create a mock model
        mock_model = Mock()
        mock_model.predict_proba.return_value = [[0.2, 0.8]]
        mock_model.predict.return_value = [1]
        mock_load.return_value = mock_model
        
        yield {
            'load': mock_load,
            'dump': mock_dump,
            'model': mock_model
        }

@pytest.fixture
def mock_logging():
    """Mock logging for testing"""
    with patch('logging.getLogger') as mock_get_logger:
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        yield mock_logger

@pytest.fixture
def sample_packet_data():
    """Sample packet data for testing"""
    from tests.fixtures.packet_data import get_sample_packets
    return get_sample_packets()

@pytest.fixture
def sample_alert_data():
    """Sample alert data for testing"""
    from tests.fixtures.packet_data import get_sample_alerts
    return get_sample_alerts()

@pytest.fixture
def mock_network_interfaces():
    """Mock network interfaces for testing"""
    return [
        "Ethernet",
        "Wi-Fi", 
        "Loopback Pseudo-Interface 1",
        "VMware Network Adapter"
    ]

# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as an end-to-end test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Add markers based on test file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        
        # Mark slow tests
        if "slow" in item.name or "performance" in item.name:
            item.add_marker(pytest.mark.slow)
