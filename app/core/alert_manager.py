import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Callable
from collections import deque
import logging
import json

from app.models.schemas import Alert, PacketInfo, AlertSeverity, DetectionType

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alerts from ML and signature-based detections"""
    
    def __init__(self, max_alerts: int = 10000, alert_callback: Optional[Callable] = None, db_manager: Optional[Any] = None):
        self.max_alerts = max_alerts
        self.alert_callback = alert_callback
        self.db_manager = db_manager
        self.alerts: deque = deque(maxlen=max_alerts)
        self.alert_id_counter = 0
        self.alerts_by_severity = {
            AlertSeverity.LOW: 0,
            AlertSeverity.MEDIUM: 0,
            AlertSeverity.HIGH: 0,
            AlertSeverity.CRITICAL: 0
        }
        self.alerts_by_type = {
            DetectionType.ML: 0,
            DetectionType.SIGNATURE: 0,
            DetectionType.HYBRID: 0
        }
        self.start_time = datetime.now()
        
        # Alert correlation
        self.correlation_window = timedelta(minutes=5)
        self.correlated_alerts = {}
        
        # Alert suppression
        self.suppression_rules = {}
        self.suppressed_alerts = 0
        
    def create_alert(self, 
                    detection_info: Dict[str, Any], 
                    packet: PacketInfo,
                    detection_type: DetectionType) -> Alert:
        """Create a new alert from detection information"""
        try:
            # Generate alert ID
            self.alert_id_counter += 1
            alert_id = f"ALERT_{self.alert_id_counter:06d}"
            
            # Extract detection info
            severity_raw = detection_info.get('severity', AlertSeverity.MEDIUM)
            description = detection_info.get('description', 'Unknown detection')
            confidence = detection_info.get('confidence', 0.0)
            try:
                severity = severity_raw.value if hasattr(severity_raw, 'value') else str(severity_raw).lower()
            except Exception:
                severity = 'low'
            
            # Create alert
            alert = Alert(
                id=alert_id,
                timestamp=datetime.now(),
                severity=severity,
                detection_type=detection_type,
                description=description,
                source_ip=packet.source_ip,
                dest_ip=packet.dest_ip,
                protocol=packet.protocol,
                confidence_score=confidence,
                packet_data={
                    'source_port': packet.source_port,
                    'dest_port': packet.dest_port,
                    'packet_length': packet.packet_length,
                    'tcp_flags': packet.tcp_flags,
                    'payload_size': packet.payload_size,
                    'detection_info': detection_info
                },
                is_resolved=False
            )
            
            # Check for alert suppression
            if self._should_suppress_alert(alert):
                self.suppressed_alerts += 1
                logger.debug(f"Suppressed alert: {alert.description}")
                return None
            
            # Add to alert storage (in-memory)
            self.alerts.append(alert)

            # Persist to database if available
            try:
                if self.db_manager and getattr(self.db_manager, 'db', None) is not None:
                    doc = {
                        'timestamp': alert.timestamp,
                        'source_ip': alert.source_ip,
                        'destination_ip': alert.dest_ip,
                        'source_port': alert.packet_data.get('source_port') if alert.packet_data else alert.source_port,
                        'destination_port': alert.packet_data.get('dest_port') if alert.packet_data else alert.dest_port,
                        'protocol': alert.protocol,
                        'severity': alert.severity if isinstance(alert.severity, str) else getattr(alert.severity, 'value', str(alert.severity).lower()),
                        'message': alert.description,
                        'status': 'resolved' if alert.is_resolved else 'new',
                        'confidence_score': alert.confidence_score,
                        'detection_type': alert.detection_type.value,
                    }
                    if alert.packet_data:
                        doc['payload'] = json.dumps(alert.packet_data, default=str)
                    self.db_manager.insert_alert(doc)
            except Exception as db_err:
                logger.error(f"Failed to persist alert {alert_id} to DB: {db_err}")
            
            # Update statistics
            self.alerts_by_severity[severity] += 1
            self.alerts_by_type[detection_type] += 1
            
            # Check for correlation
            self._correlate_alert(alert)
            
            # Call callback if provided
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.info(f"Created alert {alert_id}: {description} (Severity: {severity})")
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def create_ml_alert(self, ml_detection: Dict[str, Any], packet: PacketInfo) -> Optional[Alert]:
        """Create alert from ML detection"""
        if not ml_detection.get('is_anomalous', False):
            return None
        
        # Check confidence threshold
        confidence = ml_detection.get('confidence', 0.0)
        if confidence < 0.3:  # Minimum confidence threshold (tuned for testing)
            return None
        
        return self.create_alert(ml_detection, packet, DetectionType.ML)
    
    def create_signature_alert(self, signature_detection: Dict[str, Any], packet: PacketInfo) -> Optional[Alert]:
        """Create alert from signature detection"""
        return self.create_alert(signature_detection, packet, DetectionType.SIGNATURE)
    
    def create_hybrid_alert(self, ml_detection: Dict[str, Any], signature_detection: Dict[str, Any], packet: PacketInfo) -> Optional[Alert]:
        """Create hybrid alert combining ML and signature detections"""
        # Combine detection information
        ml_severity = ml_detection.get('severity', AlertSeverity.LOW)
        sig_severity = signature_detection.get('severity', AlertSeverity.LOW)
        
        # Use higher severity (critical > high > medium > low)
        severity_order = {AlertSeverity.LOW: 0, AlertSeverity.MEDIUM: 1, 
                         AlertSeverity.HIGH: 2, AlertSeverity.CRITICAL: 3}
        combined_severity = ml_severity if severity_order[ml_severity] >= severity_order[sig_severity] else sig_severity
        
        combined_info = {
            'severity': combined_severity,
            'description': f"Hybrid detection: {ml_detection.get('description', '')} + {signature_detection.get('description', '')}",
            'confidence': max(ml_detection.get('confidence', 0.0), 
                            signature_detection.get('confidence', 0.0)),
            'ml_info': ml_detection,
            'signature_info': signature_detection
        }
        
        return self.create_alert(combined_info, packet, DetectionType.HYBRID)
    
    def get_alerts(self, 
                  limit: int = 100, 
                  severity: Optional[AlertSeverity] = None,
                  detection_type: Optional[DetectionType] = None,
                  source_ip: Optional[str] = None,
                  resolved: Optional[bool] = None) -> List[Alert]:
        """Get alerts with optional filtering"""
        try:
            # Prefer database if available
            if self.db_manager and getattr(self.db_manager, 'db', None) is not None:
                filters = {}
                if severity:
                    filters['severity'] = severity.value
                if detection_type:
                    filters['detection_type'] = detection_type.value
                if source_ip:
                    filters['source_ip'] = source_ip
                if resolved is not None:
                    filters['resolved'] = resolved
                raw_alerts = self.db_manager.get_alerts(filters, limit)
                # Map DB documents to Alert models minimally
                alerts = []
                for a in raw_alerts:
                    try:
                        alerts.append(Alert(
                            id=str(a.get('id') or a.get('_id')),
                            timestamp=a.get('timestamp', datetime.now()),
                            severity=AlertSeverity(a.get('severity', 'low')),
                            detection_type=DetectionType(a.get('detection_type', 'ml')),
                            description=a.get('description', ''),
                            source_ip=a.get('source_ip', ''),
                            dest_ip=a.get('dest_ip', ''),
                            protocol=a.get('protocol', ''),
                            confidence_score=a.get('confidence_score'),
                            packet_data=a,
                            is_resolved=a.get('is_resolved', a.get('resolved', False))
                        ))
                    except Exception:
                        continue
            else:
                alerts = list(self.alerts)
            
            # Apply filters
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            if detection_type:
                alerts = [a for a in alerts if a.detection_type == detection_type]
            
            if source_ip:
                alerts = [a for a in alerts if a.source_ip == source_ip]
            
            if resolved is not None:
                alerts = [a for a in alerts if a.is_resolved == resolved]
            
            # Sort by timestamp (newest first)
            alerts.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Apply limit
            return alerts[:limit]
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Get a specific alert by ID"""
        try:
            for alert in self.alerts:
                if alert.id == alert_id:
                    return alert
            return None
        except Exception as e:
            logger.error(f"Error getting alert by ID: {e}")
            return None
    
    def resolve_alert(self, alert_id: str, resolution_notes: str = "") -> bool:
        """Mark an alert as resolved"""
        try:
            alert = self.get_alert_by_id(alert_id)
            if alert:
                alert.is_resolved = True
                # Add resolution info to packet_data
                if not alert.packet_data:
                    alert.packet_data = {}
                alert.packet_data['resolution_notes'] = resolution_notes
                alert.packet_data['resolved_at'] = datetime.now().isoformat()
                
                logger.info(f"Resolved alert {alert_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
            return False
    
    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert"""
        try:
            for i, alert in enumerate(self.alerts):
                if alert.id == alert_id:
                    # Update statistics
                    self.alerts_by_severity[alert.severity] -= 1
                    self.alerts_by_type[alert.detection_type] -= 1
                    
                    # Remove from storage
                    del self.alerts[i]
                    
                    logger.info(f"Deleted alert {alert_id}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error deleting alert: {e}")
            return False
    
    def clear_alerts(self, older_than: Optional[timedelta] = None):
        """Clear alerts, optionally only those older than specified time"""
        try:
            if older_than:
                cutoff_time = datetime.now() - older_than
                original_count = len(self.alerts)
                
                # Remove old alerts
                self.alerts = deque(
                    [a for a in self.alerts if a.timestamp > cutoff_time],
                    maxlen=self.max_alerts
                )
                
                removed_count = original_count - len(self.alerts)
                logger.info(f"Cleared {removed_count} alerts older than {older_than}")
            else:
                # Clear all alerts
                original_count = len(self.alerts)
                self.alerts.clear()
                
                # Reset statistics
                self.alerts_by_severity = {severity: 0 for severity in AlertSeverity}
                self.alerts_by_type = {detection_type: 0 for detection_type in DetectionType}
                
                logger.info(f"Cleared all {original_count} alerts")
                
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics"""
        try:
            uptime = datetime.now() - self.start_time
            
            return {
                'total_alerts': len(self.alerts),
                'alerts_by_severity': self.alerts_by_severity,
                'alerts_by_type': self.alerts_by_type,
                'resolved_alerts': sum(1 for a in self.alerts if a.is_resolved),
                'suppressed_alerts': self.suppressed_alerts,
                'correlated_alerts': len(self.correlated_alerts),
                'uptime_seconds': uptime.total_seconds(),
                'alert_rate_per_minute': len(self.alerts) / max(uptime.total_seconds() / 60, 1)
            }
        except Exception as e:
            logger.error(f"Error getting alert stats: {e}")
            return {}
    
    def _should_suppress_alert(self, alert: Alert) -> bool:
        """Check if alert should be suppressed based on rules"""
        try:
            # Check for duplicate alerts in short time window
            suppression_key = f"{alert.source_ip}_{alert.description}"
            
            if suppression_key in self.suppression_rules:
                last_alert_time = self.suppression_rules[suppression_key]
                if datetime.now() - last_alert_time < timedelta(minutes=1):
                    return True
            
            # Update suppression rule
            self.suppression_rules[suppression_key] = datetime.now()
            
            # Clean old suppression rules
            cutoff_time = datetime.now() - timedelta(minutes=5)
            self.suppression_rules = {
                k: v for k, v in self.suppression_rules.items() 
                if v > cutoff_time
            }
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking alert suppression: {e}")
            return False
    
    def _correlate_alert(self, alert: Alert):
        """Correlate alerts to identify patterns"""
        try:
            # Simple correlation by source IP
            source_ip = alert.source_ip
            correlation_key = f"source_ip_{source_ip}"
            
            if correlation_key not in self.correlated_alerts:
                self.correlated_alerts[correlation_key] = {
                    'source_ip': source_ip,
                    'alerts': [],
                    'first_seen': alert.timestamp,
                    'last_seen': alert.timestamp,
                    'severity_counts': {severity: 0 for severity in AlertSeverity}
                }
            
            correlation = self.correlated_alerts[correlation_key]
            correlation['alerts'].append(alert)
            correlation['last_seen'] = alert.timestamp
            correlation['severity_counts'][alert.severity] += 1
            
            # Check for correlation patterns
            if len(correlation['alerts']) >= 5:
                # Multiple alerts from same IP
                logger.warning(f"Correlation detected: {len(correlation['alerts'])} alerts from {source_ip}")
            
            # Clean old correlations
            cutoff_time = datetime.now() - self.correlation_window
            self.correlated_alerts = {
                k: v for k, v in self.correlated_alerts.items()
                if v['last_seen'] > cutoff_time
            }
            
        except Exception as e:
            logger.error(f"Error correlating alert: {e}")
    
    def export_alerts(self, format: str = 'json', filepath: Optional[str] = None) -> str:
        """Export alerts to file or return as string"""
        try:
            alerts_data = []
            for alert in self.alerts:
                alert_dict = {
                    'id': alert.id,
                    'timestamp': alert.timestamp.isoformat(),
                    'severity': alert.severity.value,
                    'detection_type': alert.detection_type.value,
                    'description': alert.description,
                    'source_ip': alert.source_ip,
                    'dest_ip': alert.dest_ip,
                    'protocol': alert.protocol,
                    'confidence_score': alert.confidence_score,
                    'is_resolved': alert.is_resolved,
                    'packet_data': alert.packet_data
                }
                alerts_data.append(alert_dict)
            
            if format.lower() == 'json':
                output = json.dumps(alerts_data, indent=2)
            else:
                # CSV format
                import csv
                import io
                output_buffer = io.StringIO()
                if alerts_data:
                    writer = csv.DictWriter(output_buffer, fieldnames=alerts_data[0].keys())
                    writer.writeheader()
                    writer.writerows(alerts_data)
                output = output_buffer.getvalue()
            
            if filepath:
                with open(filepath, 'w') as f:
                    f.write(output)
                logger.info(f"Exported {len(alerts_data)} alerts to {filepath}")
            
            return output
            
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")
            return ""
    
    def get_correlation_analysis(self) -> Dict[str, Any]:
        """Get alert correlation analysis"""
        try:
            analysis = {
                'total_correlations': len(self.correlated_alerts),
                'correlations': []
            }
            
            for key, correlation in self.correlated_alerts.items():
                analysis['correlations'].append({
                    'source_ip': correlation['source_ip'],
                    'alert_count': len(correlation['alerts']),
                    'first_seen': correlation['first_seen'].isoformat(),
                    'last_seen': correlation['last_seen'].isoformat(),
                    'severity_distribution': correlation['severity_counts'],
                    'time_span_minutes': (correlation['last_seen'] - correlation['first_seen']).total_seconds() / 60
                })
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error getting correlation analysis: {e}")
            return {}