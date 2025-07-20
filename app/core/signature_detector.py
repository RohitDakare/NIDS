import re
import ipaddress
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque

from app.models.schemas import PacketInfo, DetectionType, AlertSeverity

logger = logging.getLogger(__name__)

class SignatureRule:
    """Signature rule for pattern matching"""
    
    def __init__(self, rule_id: str, name: str, pattern: str, severity: AlertSeverity, 
                 description: str, enabled: bool = True):
        self.rule_id = rule_id
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.description = description
        self.enabled = enabled
        self.matches_count = 0
        self.last_match = None
        
    def match(self, packet: PacketInfo) -> bool:
        """Check if packet matches this rule"""
        if not self.enabled:
            return False
            
        try:
            # Basic pattern matching
            if self.pattern in packet.protocol:
                return True
                
            # Port-based patterns
            if "port_scan" in self.pattern and self._is_port_scan(packet):
                return True
                
            # DDoS patterns
            if "ddos" in self.pattern and self._is_ddos_pattern(packet):
                return True
                
            # Brute force patterns
            if "brute_force" in self.pattern and self._is_brute_force(packet):
                return True
                
            # Suspicious IP patterns
            if "suspicious_ip" in self.pattern and self._is_suspicious_ip(packet):
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error matching rule {self.rule_id}: {e}")
            return False
    
    def _is_port_scan(self, packet: PacketInfo) -> bool:
        """Detect port scanning patterns"""
        # This would be enhanced with connection tracking
        return False
    
    def _is_ddos_pattern(self, packet: PacketInfo) -> bool:
        """Detect DDoS attack patterns"""
        # This would be enhanced with rate limiting
        return False
    
    def _is_brute_force(self, packet: PacketInfo) -> bool:
        """Detect brute force attack patterns"""
        # This would be enhanced with authentication tracking
        return False
    
    def _is_suspicious_ip(self, packet: PacketInfo) -> bool:
        """Check for suspicious IP addresses"""
        try:
            # Check for known malicious IPs (simplified)
            suspicious_ips = [
                "0.0.0.0",
                "127.0.0.1",
                "255.255.255.255"
            ]
            return packet.source_ip in suspicious_ips or packet.dest_ip in suspicious_ips
        except:
            return False

class SignatureDetector:
    """Signature-based detection for known attack patterns"""
    
    def __init__(self):
        self.rules: Dict[str, SignatureRule] = {}
        self.matches_count = 0
        self.connection_tracker = ConnectionTracker()
        self.rate_limiter = RateLimiter()
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default signature rules"""
        default_rules = [
            {
                "rule_id": "SIG_001",
                "name": "TCP SYN Flood",
                "pattern": "tcp_syn_flood",
                "severity": AlertSeverity.HIGH,
                "description": "Detected TCP SYN flood attack pattern"
            },
            {
                "rule_id": "SIG_002", 
                "name": "Port Scanning",
                "pattern": "port_scan",
                "severity": AlertSeverity.MEDIUM,
                "description": "Detected port scanning activity"
            },
            {
                "rule_id": "SIG_003",
                "name": "DDoS Attack",
                "pattern": "ddos",
                "severity": AlertSeverity.CRITICAL,
                "description": "Detected DDoS attack pattern"
            },
            {
                "rule_id": "SIG_004",
                "name": "Brute Force",
                "pattern": "brute_force",
                "severity": AlertSeverity.HIGH,
                "description": "Detected brute force attack pattern"
            },
            {
                "rule_id": "SIG_005",
                "name": "Suspicious IP",
                "pattern": "suspicious_ip",
                "severity": AlertSeverity.LOW,
                "description": "Detected traffic from suspicious IP address"
            },
            {
                "rule_id": "SIG_006",
                "name": "ICMP Flood",
                "pattern": "ICMP",
                "severity": AlertSeverity.MEDIUM,
                "description": "Detected ICMP flood attack"
            },
            {
                "rule_id": "SIG_007",
                "name": "UDP Flood",
                "pattern": "UDP",
                "severity": AlertSeverity.MEDIUM,
                "description": "Detected UDP flood attack"
            }
        ]
        
        for rule_data in default_rules:
            rule = SignatureRule(**rule_data)
            self.rules[rule.rule_id] = rule
    
    def add_rule(self, rule: SignatureRule):
        """Add a new signature rule"""
        self.rules[rule.rule_id] = rule
        logger.info(f"Added signature rule: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """Remove a signature rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed signature rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable a signature rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            logger.info(f"Enabled signature rule: {rule_id}")
    
    def disable_rule(self, rule_id: str):
        """Disable a signature rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            logger.info(f"Disabled signature rule: {rule_id}")
    
    def detect(self, packet: PacketInfo) -> List[Dict[str, Any]]:
        """Detect signatures in a packet"""
        detections = []
        
        try:
            # Update connection tracker
            self.connection_tracker.update(packet)
            
            # Check rate limiting
            if self.rate_limiter.is_rate_limited(packet):
                detections.append({
                    'rule_id': 'RATE_LIMIT',
                    'name': 'Rate Limiting',
                    'severity': AlertSeverity.MEDIUM,
                    'description': 'Traffic rate limit exceeded',
                    'detection_type': DetectionType.SIGNATURE
                })
            
            # Check each rule
            for rule in self.rules.values():
                if rule.match(packet):
                    rule.matches_count += 1
                    rule.last_match = datetime.now()
                    self.matches_count += 1
                    
                    detections.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'description': rule.description,
                        'detection_type': DetectionType.SIGNATURE,
                        'pattern': rule.pattern
                    })
            
            # Advanced pattern detection
            advanced_detections = self._advanced_detection(packet)
            detections.extend(advanced_detections)
            
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
        
        return detections
    
    def _advanced_detection(self, packet: PacketInfo) -> List[Dict[str, Any]]:
        """Advanced pattern detection methods"""
        detections = []
        
        try:
            # TCP SYN flood detection
            if self._detect_syn_flood(packet):
                detections.append({
                    'rule_id': 'ADV_SYN_FLOOD',
                    'name': 'Advanced SYN Flood',
                    'severity': AlertSeverity.HIGH,
                    'description': 'Detected TCP SYN flood using advanced analysis',
                    'detection_type': DetectionType.SIGNATURE
                })
            
            # Port scanning detection
            if self._detect_port_scan(packet):
                detections.append({
                    'rule_id': 'ADV_PORT_SCAN',
                    'name': 'Advanced Port Scan',
                    'severity': AlertSeverity.MEDIUM,
                    'description': 'Detected port scanning using connection analysis',
                    'detection_type': DetectionType.SIGNATURE
                })
            
            # DDoS detection
            if self._detect_ddos(packet):
                detections.append({
                    'rule_id': 'ADV_DDOS',
                    'name': 'Advanced DDoS',
                    'severity': AlertSeverity.CRITICAL,
                    'description': 'Detected DDoS attack using traffic analysis',
                    'detection_type': DetectionType.SIGNATURE
                })
            
        except Exception as e:
            logger.error(f"Error in advanced detection: {e}")
        
        return detections
    
    def _detect_syn_flood(self, packet: PacketInfo) -> bool:
        """Detect TCP SYN flood attacks"""
        if packet.protocol != 'TCP' or not packet.tcp_flags:
            return False
        
        # Check for SYN flag without ACK
        if 'SYN' in packet.tcp_flags and 'ACK' not in packet.tcp_flags:
            # Check connection rate from source IP
            connections = self.connection_tracker.get_connections(packet.source_ip)
            syn_connections = [c for c in connections if c.get('flags') == 'SYN']
            
            # If too many SYN packets without ACK, it's likely a flood
            if len(syn_connections) > 10:  # Threshold
                return True
        
        return False
    
    def _detect_port_scan(self, packet: PacketInfo) -> bool:
        """Detect port scanning activity"""
        if not packet.source_port or not packet.dest_port:
            return False
        
        # Get recent connections from source IP
        connections = self.connection_tracker.get_connections(packet.source_ip)
        
        # Count unique destination ports
        dest_ports = set()
        for conn in connections:
            if conn.get('dest_port'):
                dest_ports.add(conn['dest_port'])
        
        # If scanning many ports in short time, it's likely a port scan
        if len(dest_ports) > 20:  # Threshold
            return True
        
        return False
    
    def _detect_ddos(self, packet: PacketInfo) -> bool:
        """Detect DDoS attacks"""
        # Check if source IP is sending too much traffic
        traffic_stats = self.rate_limiter.get_traffic_stats(packet.source_ip)
        
        if traffic_stats['packet_count'] > 1000:  # High packet count
            return True
        
        if traffic_stats['bytes_per_second'] > 1000000:  # High bandwidth
            return True
        
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get signature detector statistics"""
        enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
        total_rules = len(self.rules)
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'matches_count': self.matches_count,
            'connection_count': len(self.connection_tracker.connections),
            'rate_limited_ips': len(self.rate_limiter.rate_limits)
        }
    
    def get_rule_stats(self) -> List[Dict[str, Any]]:
        """Get statistics for each rule"""
        stats = []
        for rule in self.rules.values():
            stats.append({
                'rule_id': rule.rule_id,
                'name': rule.name,
                'enabled': rule.enabled,
                'matches_count': rule.matches_count,
                'last_match': rule.last_match.isoformat() if rule.last_match else None,
                'severity': rule.severity
            })
        return stats

class ConnectionTracker:
    """Track network connections for pattern analysis"""
    
    def __init__(self, max_connections: int = 10000):
        self.connections = {}
        self.max_connections = max_connections
    
    def update(self, packet: PacketInfo):
        """Update connection tracking with new packet"""
        try:
            if packet.protocol not in ['TCP', 'UDP']:
                return
            
            # Create connection key
            conn_key = f"{packet.source_ip}:{packet.source_port}-{packet.dest_ip}:{packet.dest_port}"
            
            # Update connection info
            if conn_key not in self.connections:
                self.connections[conn_key] = {
                    'source_ip': packet.source_ip,
                    'source_port': packet.source_port,
                    'dest_ip': packet.dest_ip,
                    'dest_port': packet.dest_port,
                    'protocol': packet.protocol,
                    'first_seen': packet.timestamp,
                    'last_seen': packet.timestamp,
                    'packet_count': 0,
                    'flags': packet.tcp_flags or 'NONE'
                }
            
            conn = self.connections[conn_key]
            conn['last_seen'] = packet.timestamp
            conn['packet_count'] += 1
            conn['flags'] = packet.tcp_flags or conn['flags']
            
            # Clean old connections
            self._cleanup_old_connections()
            
        except Exception as e:
            logger.error(f"Error updating connection tracker: {e}")
    
    def get_connections(self, ip: str) -> List[Dict[str, Any]]:
        """Get all connections for a specific IP"""
        connections = []
        for conn in self.connections.values():
            if conn['source_ip'] == ip or conn['dest_ip'] == ip:
                connections.append(conn)
        return connections
    
    def _cleanup_old_connections(self):
        """Remove old connections to prevent memory issues"""
        if len(self.connections) <= self.max_connections:
            return
        
        # Remove oldest connections
        sorted_connections = sorted(
            self.connections.items(),
            key=lambda x: x[1]['last_seen']
        )
        
        # Remove oldest 20%
        remove_count = len(sorted_connections) // 5
        for i in range(remove_count):
            del self.connections[sorted_connections[i][0]]

class RateLimiter:
    """Rate limiting for traffic analysis"""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size  # seconds
        self.rate_limits = defaultdict(lambda: deque())
        self.thresholds = {
            'packets_per_second': 100,
            'bytes_per_second': 1000000  # 1MB
        }
    
    def is_rate_limited(self, packet: PacketInfo) -> bool:
        """Check if IP should be rate limited"""
        try:
            current_time = packet.timestamp
            source_ip = packet.source_ip
            
            # Clean old entries
            self._cleanup_old_entries(source_ip, current_time)
            
            # Add current packet
            self.rate_limits[source_ip].append({
                'timestamp': current_time,
                'packet_size': packet.packet_length
            })
            
            # Check thresholds
            recent_packets = self.rate_limits[source_ip]
            
            if len(recent_packets) > self.thresholds['packets_per_second']:
                return True
            
            total_bytes = sum(p['packet_size'] for p in recent_packets)
            if total_bytes > self.thresholds['bytes_per_second']:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in rate limiting: {e}")
            return False
    
    def get_traffic_stats(self, ip: str) -> Dict[str, Any]:
        """Get traffic statistics for an IP"""
        try:
            packets = self.rate_limits[ip]
            if not packets:
                return {'packet_count': 0, 'bytes_per_second': 0}
            
            total_bytes = sum(p['packet_size'] for p in packets)
            return {
                'packet_count': len(packets),
                'bytes_per_second': total_bytes
            }
        except:
            return {'packet_count': 0, 'bytes_per_second': 0}
    
    def _cleanup_old_entries(self, ip: str, current_time: datetime):
        """Remove old entries from rate limiting window"""
        try:
            cutoff_time = current_time - timedelta(seconds=self.window_size)
            packets = self.rate_limits[ip]
            
            # Remove packets older than window
            while packets and packets[0]['timestamp'] < cutoff_time:
                packets.popleft()
                
        except Exception as e:
            logger.error(f"Error cleaning up rate limit entries: {e}") 