# NIDS Attack Testing Suite

This directory contains various tools for testing the NIDS (Network Intrusion Detection System) with different types of attack traffic and anomalies.

## Files Overview

### Attack Generation Scripts

1. **`generate_attack_traffic.py`** - Simulates various attack patterns without sending real network traffic
2. **`real_attack_generator.py`** - Generates actual network packets using Scapy (requires network permissions)
3. **`create_test_attacks.py`** - Creates predefined attack patterns and saves them to JSON files

### Testing Scripts

4. **`test_nids_with_attacks.py`** - Comprehensive test suite that runs attacks against the NIDS system
5. **`run_attack_tests.py`** - Simple script to run attack tests against the running NIDS system

## Attack Types Supported

### 1. DDoS (Distributed Denial of Service)
- **Description**: High-frequency requests from multiple source IPs
- **Detection**: Rate limiting, connection count monitoring
- **Test Duration**: 30 seconds
- **Expected Alerts**: High packet rate, multiple connections

### 2. Port Scanning
- **Description**: Systematic scanning of multiple ports on target
- **Detection**: Sequential port access patterns
- **Test Duration**: 20 seconds
- **Expected Alerts**: Port scan detection, reconnaissance activity

### 3. Brute Force Attacks
- **Description**: Multiple login attempts with common passwords
- **Detection**: Failed authentication patterns
- **Test Duration**: 25 seconds
- **Expected Alerts**: Authentication failures, brute force detection

### 4. SYN Flood
- **Description**: High volume of SYN packets without completing handshake
- **Detection**: SYN flood patterns, incomplete connections
- **Test Duration**: 20 seconds
- **Expected Alerts**: SYN flood detection, connection exhaustion

### 5. ICMP Flood
- **Description**: High volume of ICMP packets (ping flood)
- **Detection**: ICMP rate limiting
- **Test Duration**: 15 seconds
- **Expected Alerts**: ICMP flood detection

### 6. Slowloris Attack
- **Description**: Slow HTTP requests to exhaust server connections
- **Detection**: Slow connection patterns, incomplete requests
- **Test Duration**: 20 seconds
- **Expected Alerts**: Slow connection detection

### 7. Anomalous Traffic
- **Description**: Various unusual traffic patterns
- **Detection**: ML-based anomaly detection
- **Test Duration**: 30 seconds
- **Expected Alerts**: Anomaly detection, unusual patterns

## Usage Instructions

### Prerequisites

1. **Install Dependencies**:
   ```bash
   pip install scapy requests
   ```

2. **Start NIDS System**:
   ```bash
   python -m app.main
   ```

### Running Attack Tests

#### Method 1: Simulated Attacks (Safe)
```bash
# Generate attack patterns without real network traffic
python generate_attack_traffic.py

# Create predefined attack patterns
python create_test_attacks.py

# Run comprehensive test suite
python test_nids_with_attacks.py
```

#### Method 2: Real Network Attacks (Use with Caution)
```bash
# WARNING: This generates real network traffic!
# Only use on networks you own or have permission to test
python real_attack_generator.py
```

#### Method 3: Automated Testing
```bash
# Run automated attack tests
python run_attack_tests.py
```

### Configuration

#### Target IP Configuration
- Default target IP: `192.168.1.100`
- Change target IP in the scripts or when prompted
- Ensure target IP is reachable from your network

#### Network Interface
- Default interface: `Wi-Fi` (Windows) or `eth0` (Linux)
- Change interface in scripts if needed
- Use `ipconfig` (Windows) or `ifconfig` (Linux) to see available interfaces

#### Attack Intensity
- Intensity levels: 1-5 (1 = low, 5 = high)
- Higher intensity = more packets per second
- Adjust based on your network capacity

## Expected Results

### Successful Detection
- NIDS should generate alerts for each attack type
- Detection rate should be > 80% for known attack patterns
- Alerts should include:
  - Attack type classification
  - Source IP information
  - Severity level
  - Timestamp

### Performance Metrics
- **Packet Capture Rate**: Should capture > 90% of attack packets
- **Alert Generation**: Should generate alerts within 1-2 seconds of attack start
- **False Positive Rate**: Should be < 10% for normal traffic

## Troubleshooting

### Common Issues

1. **Permission Denied (Scapy)**
   - Run as administrator/root
   - Check network interface permissions

2. **No Packets Captured**
   - Verify network interface name
   - Check if target IP is reachable
   - Ensure NIDS is running

3. **No Alerts Generated**
   - Check ML model is loaded
   - Verify signature rules are enabled
   - Check detection thresholds

4. **API Connection Errors**
   - Ensure NIDS system is running
   - Check port 8000 is not blocked
   - Verify authentication settings

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export LOG_LEVEL=DEBUG
python test_nids_with_attacks.py
```

## Security Considerations

### Important Warnings

1. **Real Attack Generator**: Only use on networks you own or have explicit permission to test
2. **Target Selection**: Never target systems you don't own
3. **Network Impact**: High-intensity attacks may impact network performance
4. **Legal Compliance**: Ensure compliance with local laws and regulations

### Safe Testing Environment

- Use isolated test networks
- Test on virtual machines when possible
- Monitor network impact during testing
- Have network administrator approval

## Customization

### Adding New Attack Types

1. Create new attack method in `AttackTrafficGenerator` class
2. Add attack type to available options
3. Update test scenarios in `test_nids_with_attacks.py`

### Modifying Detection Rules

1. Edit signature rules in `app/rules/` directory
2. Adjust ML model thresholds in configuration
3. Update alert generation logic

### Performance Tuning

1. Adjust packet capture buffer sizes
2. Modify detection timeouts
3. Tune ML model parameters
4. Optimize database operations

## Results Analysis

### Attack Detection Report
After running tests, analyze:
- Detection rates by attack type
- False positive rates
- Response times
- System performance impact

### Log Analysis
Check logs in `logs/nids.log` for:
- Attack detection events
- System performance metrics
- Error messages
- Alert generation details

## Support

For issues or questions:
1. Check the main NIDS documentation
2. Review log files for error details
3. Verify system configuration
4. Test with lower intensity settings first
