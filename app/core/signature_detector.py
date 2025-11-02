import re
import ipaddress
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple, Any, Set, Deque, DefaultDict
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque, namedtuple
import yaml
import json
import os

from app.models.schemas import PacketInfo, DetectionType, AlertSeverity, Alert

logger = logging.getLogger(__name__)

# Type aliases
Port = int
IPAddress = str
PortRange = Tuple[int, int]

# Define a named tuple for connection tracking
Connection = namedtuple('Connection', ['src_ip', 'dst_ip', 'dst_port', 'timestamp', 'packet_count'])

class SignatureRule:
    """Enhanced signature rule for pattern matching with improved detection capabilities."""
    
    def __init__(self, rule_id: str, name: str, pattern: str, severity: AlertSeverity, 
                 description: str, enabled: bool = True, tags: List[str] = None,
                 metadata: Dict[str, Any] = None):
        """Initialize a signature rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name of the rule
            pattern: Pattern to match (can be regex, port range, or specific string)
            severity: Severity level of the alert
            description: Detailed description of the rule
            enabled: Whether the rule is enabled
            tags: List of tags for categorization
            metadata: Additional metadata for the rule
        """
        self.rule_id = rule_id
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.description = description
        self.enabled = enabled
        self.tags = tags or []
        self.metadata = metadata or {}
        self.matches_count = 0
        self.last_match = None
        self.compiled_pattern = self._compile_pattern()
    
    def _compile_pattern(self):
        """Compile the pattern for efficient matching."""
        try:
            # Check if it's a port range (e.g., "80-443")
            if '-' in self.pattern and self.pattern.replace('-', '').isdigit():
                start, end = map(int, self.pattern.split('-'))
                return ('port_range', start, end)
            
            # Check if it's a single port
            elif self.pattern.isdigit():
                port = int(self.pattern)
                return ('port', port)
            
            # Check if it's an IP address or CIDR
            try:
                if '/' in self.pattern:
                    return ('cidr', ipaddress.IPv4Network(self.pattern, strict=False))
                else:
                    return ('ip', ipaddress.IPv4Address(self.pattern))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass
            
            # Default to regex pattern matching
            return ('regex', re.compile(self.pattern, re.IGNORECASE))
            
        except Exception as e:
            logger.error(f"Error compiling pattern '{self.pattern}': {e}")
            return None
    
    def match(self, packet: PacketInfo, connection_tracker: 'ConnectionTracker' = None) -> bool:
        """Check if the packet matches this rule.
        
        Args:
            packet: The packet to check
            connection_tracker: Optional connection tracker for stateful analysis
            
        Returns:
            bool: True if the packet matches the rule, False otherwise
        """
        if not self.enabled or not self.compiled_pattern:
            return False
            
        try:
            pattern_type = self.compiled_pattern[0]
            
            # Port range matching
            if pattern_type == 'port_range' and packet.dest_port:
                _, start, end = self.compiled_pattern
                if start <= packet.dest_port <= end:
                    return True
            
            # Single port matching
            elif pattern_type == 'port' and packet.dest_port:
                _, port = self.compiled_pattern
                if packet.dest_port == port:
                    return True
            
            # IP address matching
            elif pattern_type == 'ip':
                _, ip = self.compiled_pattern
                if str(ip) in [packet.source_ip, packet.dest_ip]:
                    return True
            
            # CIDR network matching
            elif pattern_type == 'cidr':
                _, network = self.compiled_pattern
                src_ip = ipaddress.IPv4Address(packet.source_ip)
                dst_ip = ipaddress.IPv4Address(packet.dest_ip)
                if src_ip in network or dst_ip in network:
                    return True
            
            # Regex pattern matching
            elif pattern_type == 'regex':
                _, regex = self.compiled_pattern
                # Check various packet fields for matches
                fields_to_check = [
                    packet.protocol or '',
                    packet.tcp_flags or '',
                    str(packet.source_port or ''),
                    str(packet.dest_port or ''),
                    packet.source_ip,
                    packet.dest_ip,
                    str(packet.packet_length),
                    str(packet.payload_size or '')
                ]
                
                if any(regex.search(str(field)) for field in fields_to_check if field):
                    return True
            
            # Special case: Port scan detection
            if 'port_scan' in self.tags and connection_tracker:
                return self._detect_port_scan(packet, connection_tracker)
            
            # Special case: DDoS detection
            if 'ddos' in self.tags and connection_tracker:
                return self._detect_ddos(packet, connection_tracker)
            
            # Special case: Brute force detection
            if 'brute_force' in self.tags and connection_tracker:
                return self._detect_brute_force(packet, connection_tracker)
            
            return False
            
        except Exception as e:
            logger.error(f"Error matching rule {self.rule_id}: {e}")
            return False
    
    def _detect_port_scan(self, packet: PacketInfo, connection_tracker: 'ConnectionTracker') -> bool:
        """Detect port scanning patterns."""
        # Check for horizontal scan (multiple ports on single host)
        if connection_tracker.get_destination_ports_count(packet.source_ip) > 50:
            return True
        
        # Check for vertical scan (single port on multiple hosts)
        if connection_tracker.get_source_ips_count(packet.dest_port) > 50:
            return True
            
        # Check for SYN scanning (SYN without ACK)
        if (packet.protocol == 'TCP' and 
            'SYN' in (packet.tcp_flags or '') and 
            'ACK' not in (packet.tcp_flags or '')):
            syn_count = connection_tracker.get_syn_count(packet.source_ip)
            if syn_count > 10:  # Threshold for SYN scan
                return True
        
        return False
    
    def _detect_ddos(self, packet: PacketInfo, connection_tracker: 'ConnectionTracker') -> bool:
        """Detect DDoS attack patterns."""
        # Check for high packet rate from single source
        packet_rate = connection_tracker.get_packet_rate(packet.source_ip)
        if packet_rate > 1000:  # More than 1000 packets per second
            return True
            
        # Check for SYN flood
        if (packet.protocol == 'TCP' and 
            'SYN' in (packet.tcp_flags or '') and 
            'ACK' not in (packet.tcp_flags or '')):
            syn_count = connection_tracker.get_syn_count(packet.source_ip)
            if syn_count > 100:  # Threshold for SYN flood
                return True
        
        # Check for UDP flood
        if packet.protocol == 'UDP':
            udp_count = connection_tracker.get_protocol_count(packet.source_ip, 'UDP')
            if udp_count > 1000:  # Threshold for UDP flood
                return True
                
        return False
    
    def _detect_brute_force(self, packet: PacketInfo, connection_tracker: 'ConnectionTracker') -> bool:
        """Detect brute force attack patterns."""
        # Check for multiple failed login attempts
        if packet.dest_port in [21, 22, 23, 80, 443, 3306, 3389, 8080]:
            failed_attempts = connection_tracker.get_failed_auth_attempts(packet.source_ip, packet.dest_ip)
            if failed_attempts > 5:  # Threshold for failed attempts
                return True
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the rule to a dictionary."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'pattern': self.pattern,
            'severity': self.severity.value,
            'description': self.description,
            'enabled': self.enabled,
            'tags': self.tags,
            'metadata': self.metadata,
            'matches_count': self.matches_count,
            'last_match': self.last_match.isoformat() if self.last_match else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureRule':
        """Create a rule from a dictionary."""
        rule = cls(
            rule_id=data['rule_id'],
            name=data['name'],
            pattern=data['pattern'],
            severity=AlertSeverity(data['severity']),
            description=data['description'],
            enabled=data.get('enabled', True),
            tags=data.get('tags', []),
            metadata=data.get('metadata', {})
        )
        rule.matches_count = data.get('matches_count', 0)
        if 'last_match' in data and data['last_match']:
            rule.last_match = datetime.fromisoformat(data['last_match'])
        return rule


class ConnectionTracker:
    """Track network connections for stateful analysis."""
    
    def __init__(self, window_size: int = 300):
        """Initialize the connection tracker.
        
        Args:
            window_size: Time window in seconds for tracking connections
        """
        self.window_size = window_size
        self.connections: List[Connection] = []
        self.syn_counts: DefaultDict[IPAddress, int] = defaultdict(int)
        self.packet_counts: DefaultDict[IPAddress, int] = defaultdict(int)
        self.failed_auth_attempts: Dict[Tuple[IPAddress, IPAddress], int] = defaultdict(int)
        self.last_cleanup = time.time()
    
    def update(self, packet: PacketInfo):
        """Update connection tracking with a new packet."""
        # Clean up old connections periodically
        if time.time() - self.last_cleanup > 60:  # Cleanup every minute
            self._cleanup_old_connections()
        
        # Create a connection entry
        conn = Connection(
            src_ip=packet.source_ip,
            dst_ip=packet.dest_ip,
            dst_port=packet.dest_port or 0,
            timestamp=datetime.now(),
            packet_count=1
        )
        
        # Update connection tracking
        self.connections.append(conn)
        
        # Update SYN count for SYN flood detection
        if packet.protocol == 'TCP' and 'SYN' in (packet.tcp_flags or '') and 'ACK' not in (packet.tcp_flags or ''):
            self.syn_counts[packet.source_ip] += 1
        
        # Update packet count for rate limiting
        self.packet_counts[packet.source_ip] += 1
    
    def _cleanup_old_connections(self):
        """Remove old connections from tracking."""
        cutoff = datetime.now() - timedelta(seconds=self.window_size)
        self.connections = [conn for conn in self.connections if conn.timestamp >= cutoff]
        self.last_cleanup = time.time()
    
    def get_connections(self, src_ip: str = None, dst_ip: str = None, 
                       dst_port: int = None) -> List[Connection]:
        """Get connections matching the specified criteria."""
        result = self.connections
        if src_ip:
            result = [conn for conn in result if conn.src_ip == src_ip]
        if dst_ip:
            result = [conn for conn in result if conn.dst_ip == dst_ip]
        if dst_port is not None:
            result = [conn for conn in result if conn.dst_port == dst_port]
        return result
    
    def get_destination_ports_count(self, src_ip: str) -> int:
        """Get the number of unique destination ports for a source IP."""
        ports = {conn.dst_port for conn in self.get_connections(src_ip=src_ip)}
        return len(ports)
    
    def get_source_ips_count(self, dst_port: int) -> int:
        """Get the number of unique source IPs for a destination port."""
        ips = {conn.src_ip for conn in self.get_connections(dst_port=dst_port)}
        return len(ips)
    
    def get_syn_count(self, src_ip: str) -> int:
        """Get the SYN count for a source IP."""
        return self.syn_counts.get(src_ip, 0)
    
    def get_packet_rate(self, src_ip: str) -> float:
        """Get the packet rate (packets per second) for a source IP."""
        packets = self.packet_counts.get(src_ip, 0)
        return packets / self.window_size if self.window_size > 0 else 0
    
    def get_protocol_count(self, src_ip: str, protocol: str) -> int:
        """Get the packet count for a specific protocol from a source IP."""
        # This is a simplified version - in a real implementation, you'd track protocol info
        return len([conn for conn in self.get_connections(src_ip=src_ip) if conn.dst_port == protocol])
    
    def get_failed_auth_attempts(self, src_ip: str, dst_ip: str) -> int:
        """Get the number of failed authentication attempts from src_ip to dst_ip."""
        # This is a simplified version - in a real implementation, you'd track auth attempts
        return self.failed_auth_attempts.get((src_ip, dst_ip), 0)
    
    def record_failed_auth(self, src_ip: str, dst_ip: str):
        """Record a failed authentication attempt."""
        self.failed_auth_attempts[(src_ip, dst_ip)] = self.failed_auth_attempts.get((src_ip, dst_ip), 0) + 1


class RateLimiter:
    """Rate limiting for traffic analysis."""
    
    def __init__(self, window_size: int = 60):
        """Initialize the rate limiter.
        
        Args:
            window_size: Time window in seconds for rate limiting
        """
        self.window_size = window_size
        self.rate_limits: Dict[str, Deque[float]] = defaultdict(deque)
        self.thresholds = {
            'packets_per_second': 1000,  # Max packets per second
            'connections_per_second': 100,  # Max new connections per second
            'bytes_per_second': 10 * 1024 * 1024,  # 10 MB/s
        }
    
    def is_rate_limited(self, packet: PacketInfo) -> bool:
        """Check if the packet should be rate limited."""
        current_time = time.time()
        src_ip = packet.source_ip
        
        # Clean up old entries
        self._cleanup_old_entries(src_ip, current_time)
        
        # Add current timestamp
        self.rate_limits[src_ip].append(current_time)
        
        # Check rate limits
        if len(self.rate_limits[src_ip]) > self.thresholds['packets_per_second']:
            return True
            
        return False
    
    def _cleanup_old_entries(self, key: str, current_time: float):
        """Remove old entries from the rate limiting window."""
        while (self.rate_limits[key] and 
               current_time - self.rate_limits[key][0] > self.window_size):
            self.rate_limits[key].popleft()


class SignatureDetector:
    """Enhanced signature-based detection for known attack patterns with rule management."""
    
    def __init__(self, rules_dir: str = 'app/rules'):
        """Initialize the signature detector.
        
        Args:
            rules_dir: Directory containing rule files
        """
        self.rules: Dict[str, SignatureRule] = {}
        self.rules_dir = rules_dir
        self.connection_tracker = ConnectionTracker()
        self.rate_limiter = RateLimiter()
        self.matches_count = 0
        self._load_rules()
    
    def _load_rules(self):
        """Load signature rules from rule files."""
        try:
            if not os.path.exists(self.rules_dir):
                os.makedirs(self.rules_dir, exist_ok=True)
                logger.warning(f"Rules directory {self.rules_dir} created")
                self._create_default_rules()
                return
            
            # Load rules from YAML files
            for filename in os.listdir(self.rules_dir):
                if filename.endswith(('.yaml', '.yml')):
                    self._load_rule_file(os.path.join(self.rules_dir, filename))
            
            # If no rules were loaded, create default rules
            if not self.rules:
                logger.warning("No rules found, creating default rules")
                self._create_default_rules()
            else:
                logger.info(f"Loaded {len(self.rules)} signature rules")
                
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            # Fall back to default rules if loading fails
            self._create_default_rules()
    
    def _load_rule_file(self, filepath: str):
        """Load rules from a YAML file."""
        try:
            with open(filepath, 'r') as f:
                rules_data = yaml.safe_load(f)
                
            if not isinstance(rules_data, list):
                logger.error(f"Invalid rule file format in {filepath}")
                return
                
            for rule_data in rules_data:
                try:
                    rule = SignatureRule(
                        rule_id=rule_data['id'],
                        name=rule_data['name'],
                        pattern=rule_data['pattern'],
                        severity=AlertSeverity[rule_data['severity'].upper()],
                        description=rule_data.get('description', ''),
                        enabled=rule_data.get('enabled', True),
                        tags=rule_data.get('tags', []),
                        metadata=rule_data.get('metadata', {})
                    )
                    self.rules[rule.rule_id] = rule
                except KeyError as e:
                    logger.error(f"Invalid rule format in {filepath}: missing field {e}")
                except Exception as e:
                    logger.error(f"Error loading rule from {filepath}: {e}")
                    
        except Exception as e:
            logger.error(f"Error loading rule file {filepath}: {e}")
    
    def _create_default_rules(self):
        """Create a set of default signature rules."""
        default_rules = [
            {
                'id': 'SIG-001',
                'name': 'SSH Brute Force',
                'pattern': '22',
                'severity': 'high',
                'description': 'Detects multiple failed SSH login attempts',
                'tags': ['brute_force', 'ssh'],
                'metadata': {'mitre_technique': 'T1110.001'}
            },
            {
                'id': 'SIG-002',
                'name': 'Port Scan',
                'pattern': 'port_scan',
                'severity': 'medium',
                'description': 'Detects port scanning activity',
                'tags': ['scan', 'reconnaissance'],
                'metadata': {'mitre_technique': 'T1046'}
            },
            {
                'id': 'SIG-003',
                'name': 'DDoS Attack',
                'pattern': 'ddos',
                'severity': 'critical',
                'description': 'Detects potential DDoS attack patterns',
                'tags': ['ddos', 'dos'],
                'metadata': {'mitre_technique': 'T1498'}
            },
            {
                'id': 'SIG-004',
                'name': 'SQL Injection',
                'pattern': r'(?i)(?:union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)',
                'severity': 'high',
                'description': 'Detects SQL injection attempts',
                'tags': ['web', 'injection'],
                'metadata': {'mitre_technique': 'T1190'}
            },
            {
                'id': 'SIG-005',
                'name': 'XSS Attack',
                'pattern': r'(?i)(?:<script[^>]*>.*</script>|javascript:)',
                'severity': 'high',
                'description': 'Detects Cross-Site Scripting (XSS) attempts',
                'tags': ['web', 'xss'],
                'metadata': {'mitre_technique': 'T1059.007'}
            },
            {
                'id': 'SIG-006',
                'name': 'Suspicious HTTP User Agent',
                'pattern': r'(?i)(nmap|nikto|sqlmap|wget|curl|python-requests|hydra|metasploit|nessus|openvas)',
                'severity': 'medium',
                'description': 'Detects suspicious HTTP User-Agent strings',
                'tags': ['web', 'reconnaissance'],
                'metadata': {'mitre_technique': 'T1040'}
            },
            {
                'id': 'SIG-007',
                'name': 'Suspicious DNS Query',
                'pattern': r'(?i)(?:dns-tunneling|tunnel|exfil|malware|command-and-control|cnc|c2)',
                'severity': 'medium',
                'description': 'Detects suspicious DNS queries',
                'tags': ['dns', 'exfiltration'],
                'metadata': {'mitre_technique': 'T1071.004'}
            },
            {
                'id': 'SIG-008',
                'name': 'Suspicious IP Address',
                'pattern': 'suspicious_ip',
                'severity': 'low',
                'description': 'Detects traffic from known suspicious IP addresses',
                'tags': ['reputation', 'ioc'],
                'metadata': {'mitre_technique': 'T1589.001'}
            },
            {
                'id': 'SIG-009',
                'name': 'ICMP Tunnel',
                'pattern': 'ICMP',
                'severity': 'high',
                'description': 'Detects potential ICMP tunneling',
                'tags': ['tunnel', 'exfiltration'],
                'metadata': {'mitre_technique': 'T1572'}
            },
            {
                'id': 'SIG-010',
                'name': 'Data Exfiltration',
                'pattern': r'(?i)(?:passwd|shadow|confidential|secret|token|api[_-]?key)',
                'severity': 'critical',
                'description': 'Detects potential data exfiltration attempts',
                'tags': ['exfiltration', 'data_loss'],
                'metadata': {'mitre_technique': 'T1020'}
            }
        ]
        
        for rule_data in default_rules:
            try:
                rule = SignatureRule(
                    rule_id=rule_data['id'],
                    name=rule_data['name'],
                    pattern=rule_data['pattern'],
                    severity=AlertSeverity[rule_data['severity'].upper()],
                    description=rule_data['description'],
                    enabled=True,
                    tags=rule_data.get('tags', []),
                    metadata=rule_data.get('metadata', {})
                )
                self.rules[rule.rule_id] = rule
            except Exception as e:
                logger.error(f"Error creating default rule {rule_data.get('id', 'unknown')}: {e}")
        
        # Save default rules to a file
        self._save_rules()
    
    def _save_rules(self):
        """Save the current rules to a file."""
        try:
            os.makedirs(self.rules_dir, exist_ok=True)
            rules_file = os.path.join(self.rules_dir, 'default_rules.yaml')
            
            rules_data = []
            for rule in self.rules.values():
                rule_dict = rule.to_dict()
                # Convert severity back to string for YAML
                rule_dict['severity'] = rule_dict['severity'].lower()
                rules_data.append(rule_dict)
            
            with open(rules_file, 'w') as f:
                yaml.dump(rules_data, f, default_flow_style=False)
                
        except Exception as e:
            logger.error(f"Error saving rules: {e}")
    
    def add_rule(self, rule: SignatureRule) -> bool:
        """Add a new signature rule."""
        if not rule.rule_id:
            logger.error("Cannot add rule: missing rule_id")
            return False
            
        self.rules[rule.rule_id] = rule
        self._save_rules()
        return True
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a signature rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self._save_rules()
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a signature rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            self._save_rules()
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a signature rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            self._save_rules()
            return True
        return False
    
    def detect(self, packet: PacketInfo) -> List[Dict[str, Any]]:
        """Detect signatures in a packet.
        
        Returns:
            List of detection results, each containing rule and match information
        """
        detections = []
        
        # Update connection tracker
        self.connection_tracker.update(packet)
        
        # Check rate limiting
        if self.rate_limiter.is_rate_limited(packet):
            detections.append({
                'rule_id': 'RATE_LIMIT',
                'name': 'Rate Limiting',
                'severity': AlertSeverity.HIGH,
                'description': 'Traffic rate limit exceeded',
                'detection_type': DetectionType.SIGNATURE,
                'metadata': {
                    'source_ip': packet.source_ip,
                    'packet_rate': len(self.rate_limiter.rate_limits[packet.source_ip])
                }
            })
        
        # Check each rule
        for rule in self.rules.values():
            if rule.match(packet, self.connection_tracker):
                # Update rule statistics
                rule.matches_count += 1
                rule.last_match = datetime.now()
                
                # Create detection result
                detection = {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description,
                    'detection_type': DetectionType.SIGNATURE,
                    'metadata': {
                        'source_ip': packet.source_ip,
                        'dest_ip': packet.dest_ip,
                        'dest_port': packet.dest_port,
                        'protocol': packet.protocol,
                        'timestamp': datetime.now().isoformat(),
                        **rule.metadata
                    }
                }
                
                detections.append(detection)
                self.matches_count += 1
        
        return detections
    
    def get_stats(self) -> Dict[str, Any]:
        """Get signature detection statistics."""
        enabled_rules_count = sum(1 for rule in self.rules.values() if rule.enabled)
        disabled_rules = len(self.rules) - enabled_rules_count
        
        # Get all enabled rules as an array (for frontend)
        enabled_rules_list = [
            {
                'id': rule.rule_id,
                'name': rule.name,
                'enabled': rule.enabled,
                'matches': rule.matches_count,
                'severity': rule.severity.value
            }
            for rule in self.rules.values() if rule.enabled
        ]
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_rules_list,  # Array of enabled rules
            'enabled_rules_count': enabled_rules_count,  # Count for backward compatibility
            'disabled_rules': disabled_rules,
            'matches_count': self.matches_count,
            'top_rules': sorted(
                [rule.to_dict() for rule in self.rules.values()], 
                key=lambda x: x['matches_count'], 
                reverse=True
            )[:10]  # Top 10 rules by match count
        }
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the signature rules.
        
        Returns:
            Dictionary containing rule statistics
        """
        total_rules = len(self.rules)
        enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
        disabled_rules = total_rules - enabled_rules
        
        # Get top 5 most matched rules
        top_rules = sorted(
            [rule for rule in self.rules.values() if rule.matches_count > 0],
            key=lambda x: x.matches_count,
            reverse=True
        )[:5]
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': disabled_rules,
            'total_matches': self.matches_count,
            'top_rules': [
                {
                    'name': rule.name,
                    'id': rule.rule_id,
                    'matches': rule.matches_count,
                    'last_match': rule.last_match.isoformat() if rule.last_match else None,
                    'severity': rule.severity.value,
                    'enabled': rule.enabled,
                    'description': rule.description
                }
                for rule in top_rules
            ]
        }
    
    def reload_rules(self) -> bool:
        """Reload rules from disk."""
        try:
            self.rules.clear()
            self._load_rules()
            return True
        except Exception as e:
            logger.error(f"Error reloading rules: {e}")
            return False