import asyncio
import threading
import time
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
import logging

from app.core.packet_sniffer import PacketSniffer
from app.core.ml_detector import MLDetector
from app.core.signature_detector import SignatureDetector
from app.core.alert_manager import AlertManager
from app.db.secure_mongodb import secure_mongo
from app.models.schemas import (
    PacketInfo, SnifferConfig, MLModelConfig, 
    SystemStatus, DetectionType, Alert
)

logger = logging.getLogger(__name__)

class NIDSOrchestrator:
    """Main orchestrator for the NIDS system"""
    
    def __init__(self, 
                 sniffer_config: SnifferConfig,
                 ml_config: MLModelConfig,
                 alert_callback: Optional[Callable] = None):
        
        self.sniffer_config = sniffer_config
        self.ml_config = ml_config
        self.alert_callback = alert_callback
        
        # Initialize components
        self.packet_sniffer = PacketSniffer(sniffer_config)
        self.ml_detector = MLDetector(ml_config)
        self.signature_detector = SignatureDetector()
        # Ensure DB connection
        try:
            if secure_mongo.connect():
                secure_mongo.create_indexes()
        except Exception:
            logger.warning("Proceeding without MongoDB persistence")
        self.alert_manager = AlertManager(alert_callback=alert_callback, db_manager=secure_mongo)
        
        # System state
        self.is_running = False
        self.start_time = None
        self.packets_processed = 0
        self.alerts_generated = 0
        self.ml_predictions = 0
        self.signature_matches = 0
        
        # Performance monitoring
        self.performance_stats = {
            'avg_processing_time': 0.0,
            'max_processing_time': 0.0,
            'min_processing_time': float('inf'),
            'total_processing_time': 0.0
        }
        
        # Set up packet processing callback
        # Don't auto-start the sniffer, let the start() method handle it
        # self.packet_sniffer.start(callback=self._process_packet)
        
    def start(self) -> bool:
        """Start the NIDS system"""
        try:
            if self.is_running:
                logger.warning("NIDS system is already running")
                return False
            
            self.is_running = True
            self.start_time = datetime.now()
            self.packets_processed = 0
            self.alerts_generated = 0
            self.ml_predictions = 0
            self.signature_matches = 0
            
            # Reset performance stats
            self.performance_stats = {
                'avg_processing_time': 0.0,
                'max_processing_time': 0.0,
                'min_processing_time': float('inf'),
                'total_processing_time': 0.0
            }
            
            # Start the packet sniffer
            if not self.packet_sniffer.start(callback=self._process_packet):
                logger.error("Failed to start packet sniffer")
                self.is_running = False
                return False
            
            logger.info("NIDS system started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting NIDS system: {e}")
            self.is_running = False
            return False
    
    def stop(self) -> bool:
        """Stop the NIDS system"""
        try:
            if not self.is_running:
                logger.warning("NIDS system is not running")
                return False
            
            self.is_running = False
            
            # Stop packet sniffer
            self.packet_sniffer.stop()
            
            logger.info("NIDS system stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping NIDS system: {e}")
            return False
    
    def _process_packet(self, packet: PacketInfo):
        """Process a single packet through all detection methods"""
        if not self.is_running:
            return
        
        start_time = time.time()
        
        try:
            # Increment packet counter
            self.packets_processed += 1
            
            # ML-based detection
            ml_detection = self._perform_ml_detection(packet)
            
            # Signature-based detection
            signature_detections = self._perform_signature_detection(packet)
            
            # Generate alerts
            self._generate_alerts(packet, ml_detection, signature_detections)
            
            # Update performance stats
            processing_time = time.time() - start_time
            self._update_performance_stats(processing_time)
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _perform_ml_detection(self, packet: PacketInfo) -> Dict[str, Any]:
        """Perform ML-based anomaly detection"""
        try:
            detection_info = self.ml_detector.get_detection_info(packet)
            self.ml_predictions += 1
            
            return detection_info
            
        except Exception as e:
            logger.error(f"Error in ML detection: {e}")
            return {
                'is_anomalous': False,
                'confidence': 0.0,
                'severity': 'low',
                'description': 'ML detection error',
                'detection_type': DetectionType.ML
            }
    
    def _perform_signature_detection(self, packet: PacketInfo) -> List[Dict[str, Any]]:
        """Perform signature-based detection"""
        try:
            detections = self.signature_detector.detect(packet)
            self.signature_matches += len(detections)
            
            return detections
            
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
            return []
    
    def _generate_alerts(self, packet: PacketInfo, ml_detection: Dict[str, Any], 
                        signature_detections: List[Dict[str, Any]]):
        """Generate alerts based on detections"""
        try:
            alerts_created = 0
            
            # Create ML alert if anomalous
            if ml_detection.get('is_anomalous', False):
                ml_alert = self.alert_manager.create_ml_alert(ml_detection, packet)
                if ml_alert:
                    alerts_created += 1
            
            # Create signature alerts
            for sig_detection in signature_detections:
                sig_alert = self.alert_manager.create_signature_alert(sig_detection, packet)
                if sig_alert:
                    alerts_created += 1
            
            # Create hybrid alert if both ML and signature detected something
            if (ml_detection.get('is_anomalous', False) and signature_detections):
                # Use the highest severity signature detection
                best_sig_detection = max(signature_detections, 
                                       key=lambda x: x.get('severity', 'low'))
                hybrid_alert = self.alert_manager.create_hybrid_alert(
                    ml_detection, best_sig_detection, packet
                )
                if hybrid_alert:
                    alerts_created += 1
            
            self.alerts_generated += alerts_created
            
        except Exception as e:
            logger.error(f"Error generating alerts: {e}")
    
    def _update_performance_stats(self, processing_time: float):
        """Update performance statistics"""
        try:
            stats = self.performance_stats
            
            # Update total processing time
            stats['total_processing_time'] += processing_time
            
            # Update min/max processing times
            if processing_time < stats['min_processing_time']:
                stats['min_processing_time'] = processing_time
            if processing_time > stats['max_processing_time']:
                stats['max_processing_time'] = processing_time
            
            # Update average processing time
            stats['avg_processing_time'] = stats['total_processing_time'] / self.packets_processed
            
        except Exception as e:
            logger.error(f"Error updating performance stats: {e}")
    
    def get_system_status(self) -> SystemStatus:
        """Get current system status"""
        try:
            uptime = 0.0
            if self.start_time:
                uptime = (datetime.now() - self.start_time).total_seconds()
            
            # Get system resource usage
            memory_usage = psutil.virtual_memory().percent
            cpu_usage = psutil.cpu_percent(interval=1)
            
            return SystemStatus(
                is_running=self.is_running,
                uptime=uptime,
                packets_captured=self.packet_sniffer.packets_captured,
                alerts_generated=self.alerts_generated,
                ml_predictions=self.ml_predictions,
                signature_matches=self.signature_matches,
                memory_usage=memory_usage,
                cpu_usage=cpu_usage
            )
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return SystemStatus(
                is_running=False,
                uptime=0.0,
                packets_captured=0,
                alerts_generated=0,
                ml_predictions=0,
                signature_matches=0,
                memory_usage=0.0,
                cpu_usage=0.0
            )
    
    def get_detailed_stats(self) -> Dict[str, Any]:
        """Get detailed system statistics"""
        try:
            # Get component stats
            sniffer_stats = self.packet_sniffer.get_stats()
            ml_stats = self.ml_detector.get_stats()
            signature_stats = self.signature_detector.get_stats()
            alert_stats = self.alert_manager.get_stats()
            
            # Calculate detection rates
            ml_detection_rate = 0.0
            if self.ml_predictions > 0:
                ml_detection_rate = ml_stats.get('anomalies_detected', 0) / self.ml_predictions
            
            signature_detection_rate = 0.0
            if self.packets_processed > 0:
                signature_detection_rate = self.signature_matches / self.packets_processed
            
            # Calculate overall detection rate
            overall_detection_rate = 0.0
            if self.packets_processed > 0:
                overall_detection_rate = self.alerts_generated / self.packets_processed
            
            # Get enabled rules from signature stats
            enabled_rules = signature_stats.get('enabled_rules', [])
            if not isinstance(enabled_rules, (list, tuple)):
                enabled_rules = []
            
            # Construct and return the detailed stats
            return {
                'system_status': self.get_system_status().model_dump(),
                'sniffer_stats': sniffer_stats,
                'ml_stats': ml_stats,
                'signature_stats': signature_stats,
                'alert_stats': alert_stats,
                'performance_stats': self.performance_stats,
                'detection_rates': {
                    'ml_detection_rate': ml_detection_rate,
                    'signature_detection_rate': signature_detection_rate,
                    'overall_detection_rate': overall_detection_rate
                },
                'component_health': {
                    'sniffer_healthy': self.packet_sniffer.is_running,
                    'ml_healthy': self.ml_detector.is_loaded,
                    'signature_healthy': len(self.signature_detector.rules) > 0,
                    'alert_manager_healthy': True
                },
                'component_details': {
                    'sniffer': {
                        'is_running': self.packet_sniffer.is_running,
                        'has_attempted_start': getattr(self.packet_sniffer, 'has_attempted_start', False),
                        'status': 'running' if self.packet_sniffer.is_running else (
                            'failed' if getattr(self.packet_sniffer, 'last_error', None) else 'not_started'
                        ),
                        'interface': self.packet_sniffer.config.interface,
                        'last_error': getattr(self.packet_sniffer, 'last_error', None),
                        'packets_captured': self.packet_sniffer.packets_captured
                    },
                    'ml_detector': {
                        'is_loaded': self.ml_detector.is_loaded,
                        'status': 'loaded' if self.ml_detector.is_loaded else 'not_loaded'
                    },
                    'signature_detector': {
                        'rules_count': len(self.signature_detector.rules),
                        'status': 'configured' if len(self.signature_detector.rules) > 0 else 'no_rules'
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting detailed stats: {e}")
            return {}
    
    def get_recent_packets(self, limit: int = 100) -> List[PacketInfo]:
        """Get recent packets from sniffer"""
        return self.packet_sniffer.get_recent_packets(limit)
    
    def get_alerts(self, limit: int = 100, **filters) -> List[Alert]:
        """Get alerts with optional filtering"""
        return self.alert_manager.get_alerts(limit=limit, **filters)
    
    def resolve_alert(self, alert_id: str, resolution_notes: str = "") -> bool:
        """Resolve an alert"""
        return self.alert_manager.resolve_alert(alert_id, resolution_notes)
    
    def clear_alerts(self, older_than_days: Optional[int] = None):
        """Clear alerts"""
        if older_than_days:
            from datetime import timedelta
            older_than = timedelta(days=older_than_days)
            self.alert_manager.clear_alerts(older_than)
        else:
            self.alert_manager.clear_alerts()
    
    def export_alerts(self, format: str = 'json', filepath: Optional[str] = None) -> str:
        """Export alerts"""
        return self.alert_manager.export_alerts(format, filepath)
    
    def update_sniffer_config(self, config: SnifferConfig) -> bool:
        """Update sniffer configuration"""
        try:
            if self.is_running:
                # Stop current sniffer
                self.packet_sniffer.stop()
                
                # Create new sniffer with updated config
                self.packet_sniffer = PacketSniffer(config)
                self.sniffer_config = config
                
                # Restart if system was running
                if self.is_running:
                    self.packet_sniffer.start(callback=self._process_packet)
                
                logger.info("Sniffer configuration updated successfully")
                return True
            else:
                # Just update config if not running
                self.sniffer_config = config
                self.packet_sniffer = PacketSniffer(config)
                return True
                
        except Exception as e:
            logger.error(f"Error updating sniffer config: {e}")
            return False
    
    def update_ml_config(self, config: MLModelConfig) -> bool:
        """Update ML model configuration"""
        try:
            # Create new ML detector with updated config
            self.ml_detector = MLDetector(config)
            self.ml_config = config
            
            logger.info("ML configuration updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error updating ML config: {e}")
            return False
    
    def get_correlation_analysis(self) -> Dict[str, Any]:
        """Get alert correlation analysis"""
        return self.alert_manager.get_correlation_analysis()
    
    def get_signature_rule_stats(self) -> List[Dict[str, Any]]:
        """Get signature rule statistics"""
        return self.signature_detector.get_rule_stats()
    
    def enable_signature_rule(self, rule_id: str) -> bool:
        """Enable a signature rule"""
        try:
            self.signature_detector.enable_rule(rule_id)
            return True
        except Exception as e:
            logger.error(f"Error enabling signature rule: {e}")
            return False
    
    def disable_signature_rule(self, rule_id: str) -> bool:
        """Disable a signature rule"""
        try:
            self.signature_detector.disable_rule(rule_id)
            return True
        except Exception as e:
            logger.error(f"Error disabling signature rule: {e}")
            return False 