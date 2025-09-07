# 🧪 NIDS Test Suite

This directory contains comprehensive tests for the NIDS (Network Intrusion Detection System) project.

## 📁 Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── test_ml_detector.py
│   ├── test_signature_detector.py
│   ├── test_alert_manager.py
│   └── test_packet_sniffer.py
├── integration/             # Integration tests for component interactions
│   └── test_nids_orchestrator.py
├── e2e/                     # End-to-end tests for complete workflows
│   └── test_api_endpoints.py
├── fixtures/                # Test data and fixtures
│   └── packet_data.py
├── mocks/                   # Mock objects for testing
│   └── scapy_mocks.py
├── conftest.py             # Pytest configuration and shared fixtures
├── run_tests.py            # Test runner script
└── README.md               # This file
```

## 🚀 Running Tests

### Prerequisites

Make sure you have the required dependencies installed:

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock flake8 black autoflake

# Or install from requirements
pip install -r requirements.txt
```

### Quick Start

```bash
# Run all tests
python tests/run_tests.py all

# Run specific test types
python tests/run_tests.py unit
python tests/run_tests.py integration
python tests/run_tests.py e2e

# Run with coverage
python tests/run_tests.py coverage

# Run specific test file
python tests/run_tests.py specific --test-path tests/unit/test_ml_detector.py
```

### Using pytest directly

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test
pytest tests/unit/test_ml_detector.py::TestMLDetector::test_predict_normal_packet

# Run tests matching pattern
pytest -k "test_predict"

# Run slow tests only
pytest -m slow
```

## 📋 Test Categories

### Unit Tests (`tests/unit/`)

Test individual components in isolation:

- **`test_ml_detector.py`**: Tests for ML-based anomaly detection
- **`test_signature_detector.py`**: Tests for signature-based detection
- **`test_alert_manager.py`**: Tests for alert management
- **`test_packet_sniffer.py`**: Tests for packet capture functionality

### Integration Tests (`tests/integration/`)

Test component interactions:

- **`test_nids_orchestrator.py`**: Tests for the main orchestrator component

### End-to-End Tests (`tests/e2e/`)

Test complete workflows:

- **`test_api_endpoints.py`**: Tests for all API endpoints

## 🔧 Test Configuration

### Pytest Configuration (`pytest.ini`)

- Test discovery patterns
- Output formatting
- Markers for test categorization
- Timeout settings
- Logging configuration

### Shared Fixtures (`conftest.py`)

- Test data directories
- Mock objects for external dependencies
- Environment variable mocking
- Common test utilities

## 📊 Test Data and Fixtures

### Fixtures (`tests/fixtures/`)

- **`packet_data.py`**: Sample packet data for testing
  - TCP, UDP, ICMP, ARP packets
  - Suspicious and attack packets
  - Configuration objects
  - Sample alerts

### Mocks (`tests/mocks/`)

- **`scapy_mocks.py`**: Mock objects for Scapy packet testing
  - Mock packet objects
  - Mock network layers
  - Test packet generators

## 🏷️ Test Markers

Tests are categorized using pytest markers:

- `@pytest.mark.unit`: Unit tests
- `@pytest.mark.integration`: Integration tests
- `@pytest.mark.e2e`: End-to-end tests
- `@pytest.mark.slow`: Slow-running tests
- `@pytest.mark.performance`: Performance tests

## 📈 Coverage Reports

Generate coverage reports:

```bash
# HTML coverage report
pytest --cov=app --cov-report=html

# Terminal coverage report
pytest --cov=app --cov-report=term-missing

# XML coverage report (for CI/CD)
pytest --cov=app --cov-report=xml
```

Coverage reports are generated in:
- `htmlcov/` - HTML report (open `htmlcov/index.html`)
- `coverage.xml` - XML report for CI/CD

## 🐛 Debugging Tests

### Verbose Output

```bash
# Very verbose output
pytest -vvv

# Show local variables on failure
pytest -l

# Drop into debugger on failure
pytest --pdb
```

### Test Debugging

```bash
# Run single test with debugging
pytest tests/unit/test_ml_detector.py::TestMLDetector::test_predict_normal_packet -vvv --pdb

# Show print statements
pytest -s

# Capture output
pytest --capture=no
```

## 🔍 Code Quality

### Linting

```bash
# Run linting
python tests/run_tests.py lint

# Or directly
flake8 app/ tests/ --max-line-length=100
```

### Code Formatting

```bash
# Format code
python tests/run_tests.py format

# Or directly
black app/ tests/ --line-length=100
```

### Import Checking

```bash
# Check for unused imports
python tests/run_tests.py imports

# Or directly
autoflake --check --recursive app/ tests/
```

## 🚀 Continuous Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    - name: Run tests
      run: pytest --cov=app --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v1
```

## 📝 Writing New Tests

### Unit Test Example

```python
import pytest
from unittest.mock import Mock, patch
from app.core.ml_detector import MLDetector

class TestMLDetector:
    @pytest.fixture
    def ml_detector(self):
        return MLDetector(config)
    
    def test_predict_normal_packet(self, ml_detector):
        packet = create_test_packet()
        result = ml_detector.predict(packet)
        assert result is not None
```

### Integration Test Example

```python
import pytest
from app.core.nids_orchestrator import NIDSOrchestrator

class TestNIDSOrchestrator:
    def test_start_stop_system(self, orchestrator):
        assert orchestrator.start() == True
        assert orchestrator.is_running == True
        assert orchestrator.stop() == True
        assert orchestrator.is_running == False
```

### End-to-End Test Example

```python
import pytest
from fastapi.testclient import TestClient

def test_api_endpoint(client):
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    assert "is_running" in response.json()
```

## 🎯 Test Best Practices

1. **Test Isolation**: Each test should be independent
2. **Mock External Dependencies**: Use mocks for network, file system, etc.
3. **Descriptive Names**: Test names should clearly describe what they test
4. **Arrange-Act-Assert**: Structure tests clearly
5. **Edge Cases**: Test boundary conditions and error cases
6. **Fast Tests**: Keep unit tests fast (< 1 second each)
7. **Deterministic**: Tests should produce consistent results

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**: Make sure the project root is in Python path
2. **Permission Errors**: Some tests may require admin privileges for network access
3. **Port Conflicts**: Tests use port 8000, make sure it's available
4. **Missing Dependencies**: Install all required packages

### Test Environment

```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Check installed packages
pip list | grep pytest

# Check test discovery
pytest --collect-only
```

## 📚 Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Mock Documentation](https://docs.python.org/3/library/unittest.mock.html)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)

## 🤝 Contributing

When adding new tests:

1. Follow the existing test structure
2. Add appropriate markers
3. Update this documentation
4. Ensure tests pass in CI/CD
5. Maintain good test coverage
