import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import logging
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction import FeatureHasher
import warnings
warnings.filterwarnings('ignore')

from app.models.schemas import PacketInfo, MLModelConfig, DetectionType, AlertSeverity

logger = logging.getLogger(__name__)

class MLDetector:
    """Machine Learning-based anomaly detection for network traffic"""
    
    def __init__(self, config: MLModelConfig):
        self.config = config
        self.model = None
        self.scaler = None
        self.feature_hasher = None
        self.is_loaded = False
        self.predictions_count = 0
        self.anomalies_detected = 0
        
        # Default feature columns for network traffic
        self.default_features = [
            'packet_length', 'payload_size', 'source_port', 'dest_port',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp', 'protocol_other',
            'has_tcp_flags', 'tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst',
            'tcp_psh', 'tcp_urg', 'hour_of_day', 'day_of_week'
        ]
        
        self.feature_columns = config.feature_columns or self.default_features
        self._load_model()
    
    def _load_model(self):
        """Load the pre-trained ML model"""
        try:
            if self.config.model_path:
                # Try to load existing model
                self.model = joblib.load(self.config.model_path)
                self.is_loaded = True
                logger.info(f"Loaded ML model from {self.config.model_path}")
            else:
                # Create a default model if none exists
                self._create_default_model()
                
        except FileNotFoundError:
            logger.warning(f"Model file not found at {self.config.model_path}, creating default model")
            self._create_default_model()
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            self._create_default_model()
    
    def _create_default_model(self):
        """Create a default ML model for demonstration"""
        try:
            # Create a simple Random Forest classifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            
            # Create dummy training data for initialization
            dummy_data = self._generate_dummy_training_data()
            X_dummy = self._extract_features(dummy_data)
            y_dummy = np.zeros(len(dummy_data))  # All normal traffic
            
            # Fit the model
            self.model.fit(X_dummy, y_dummy)
            self.is_loaded = True
            
            # Save the model
            joblib.dump(self.model, self.config.model_path)
            logger.info(f"Created and saved default ML model to {self.config.model_path}")
            
        except Exception as e:
            logger.error(f"Error creating default model: {e}")
            self.is_loaded = False
    
    def _generate_dummy_training_data(self) -> List[PacketInfo]:
        """Generate dummy training data for model initialization"""
        dummy_packets = []
        
        # Generate normal traffic patterns
        for i in range(1000):
            packet = PacketInfo(
                timestamp=datetime.now(),
                source_ip=f"192.168.1.{i % 254 + 1}",
                dest_ip=f"10.0.0.{i % 254 + 1}",
                protocol="TCP" if i % 3 == 0 else "UDP" if i % 3 == 1 else "ICMP",
                source_port=1024 + (i % 64511),
                dest_port=80 if i % 4 == 0 else 443 if i % 4 == 1 else 22 if i % 4 == 2 else 53,
                packet_length=64 + (i % 1400),
                tcp_flags="SYN,ACK" if i % 5 == 0 else "ACK" if i % 5 == 1 else "PSH,ACK",
                payload_size=i % 1000
            )
            dummy_packets.append(packet)
        
        return dummy_packets
    
    def predict(self, packet: PacketInfo) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Predict if a packet is anomalous
        
        Returns:
            Tuple of (is_anomalous, confidence_score, additional_info)
        """
        if not self.is_loaded:
            logger.warning("ML model not loaded, skipping prediction")
            return False, 0.0, {}
        
        try:
            # Extract features from packet
            features = self._extract_features([packet])
            
            if features is None or len(features) == 0:
                return False, 0.0, {}
            
            # Make prediction
            if hasattr(self.model, 'predict_proba'):
                # For classification models
                prediction_proba = self.model.predict_proba(features)[0]
                prediction = self.model.predict(features)[0]
                
                # For binary classification, anomaly is class 1
                confidence = prediction_proba[1] if len(prediction_proba) > 1 else prediction_proba[0]
                is_anomalous = prediction == 1
                
            else:
                # For anomaly detection models (IsolationForest, OneClassSVM)
                prediction = self.model.predict(features)[0]
                # -1 indicates anomaly, 1 indicates normal
                is_anomalous = prediction == -1
                confidence = 0.8 if is_anomalous else 0.2  # Default confidence
            
            self.predictions_count += 1
            if is_anomalous:
                self.anomalies_detected += 1
            
            # Additional information for analysis
            additional_info = {
                'model_type': type(self.model).__name__,
                'features_used': len(self.feature_columns),
                'prediction_raw': prediction,
                'feature_vector': features[0].tolist() if len(features) > 0 else []
            }
            
            return is_anomalous, confidence, additional_info
            
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return False, 0.0, {}
    
    def _extract_features(self, packets: List[PacketInfo]) -> Optional[np.ndarray]:
        """Extract features from packets for ML model"""
        try:
            if not packets:
                return None
            
            features_list = []
            
            for packet in packets:
                # Basic numerical features
                feature_dict = {
                    'packet_length': packet.packet_length,
                    'payload_size': packet.payload_size,
                    'source_port': packet.source_port or 0,
                    'dest_port': packet.dest_port or 0,
                }
                
                # Protocol encoding (one-hot)
                feature_dict['protocol_tcp'] = 1 if packet.protocol == 'TCP' else 0
                feature_dict['protocol_udp'] = 1 if packet.protocol == 'UDP' else 0
                feature_dict['protocol_icmp'] = 1 if packet.protocol == 'ICMP' else 0
                feature_dict['protocol_other'] = 1 if packet.protocol not in ['TCP', 'UDP', 'ICMP'] else 0
                
                # TCP flags analysis
                feature_dict['has_tcp_flags'] = 1 if packet.tcp_flags else 0
                feature_dict['tcp_syn'] = 1 if packet.tcp_flags and 'SYN' in packet.tcp_flags else 0
                feature_dict['tcp_ack'] = 1 if packet.tcp_flags and 'ACK' in packet.tcp_flags else 0
                feature_dict['tcp_fin'] = 1 if packet.tcp_flags and 'FIN' in packet.tcp_flags else 0
                feature_dict['tcp_rst'] = 1 if packet.tcp_flags and 'RST' in packet.tcp_flags else 0
                feature_dict['tcp_psh'] = 1 if packet.tcp_flags and 'PSH' in packet.tcp_flags else 0
                feature_dict['tcp_urg'] = 1 if packet.tcp_flags and 'URG' in packet.tcp_flags else 0
                
                # Time-based features
                feature_dict['hour_of_day'] = packet.timestamp.hour
                feature_dict['day_of_week'] = packet.timestamp.weekday()
                
                # IP address features (simplified)
                try:
                    source_ip_parts = packet.source_ip.split('.')
                    dest_ip_parts = packet.dest_ip.split('.')
                    
                    feature_dict['source_ip_class'] = int(source_ip_parts[0]) if len(source_ip_parts) == 4 else 0
                    feature_dict['dest_ip_class'] = int(dest_ip_parts[0]) if len(dest_ip_parts) == 4 else 0
                    feature_dict['source_ip_private'] = 1 if self._is_private_ip(packet.source_ip) else 0
                    feature_dict['dest_ip_private'] = 1 if self._is_private_ip(packet.dest_ip) else 0
                except:
                    feature_dict['source_ip_class'] = 0
                    feature_dict['dest_ip_class'] = 0
                    feature_dict['source_ip_private'] = 0
                    feature_dict['dest_ip_private'] = 0
                
                features_list.append(feature_dict)
            
            # Convert to DataFrame for easier processing
            df = pd.DataFrame(features_list)
            
            # Ensure all expected columns are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0
            
            # Select only the expected features
            df = df[self.feature_columns]
            
            # Convert to numpy array
            features_array = df.values
            
            # Normalize features if scaler is available
            if self.scaler:
                features_array = self.scaler.transform(features_array)
            
            return features_array
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return True
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            elif first_octet == 192 and second_octet == 168:
                return True
            
            return False
        except:
            return False
    
    def get_detection_info(self, packet: PacketInfo) -> Dict[str, Any]:
        """Get detailed detection information for a packet"""
        is_anomalous, confidence, additional_info = self.predict(packet)
        
        # Determine severity based on confidence
        if confidence >= 0.9:
            severity = AlertSeverity.CRITICAL
        elif confidence >= 0.7:
            severity = AlertSeverity.HIGH
        elif confidence >= 0.5:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        # Generate description
        if is_anomalous:
            description = f"ML anomaly detected with {confidence:.2f} confidence"
        else:
            description = f"Normal traffic detected with {confidence:.2f} confidence"
        
        return {
            'is_anomalous': is_anomalous,
            'confidence': confidence,
            'severity': severity,
            'description': description,
            'detection_type': DetectionType.ML,
            'model_info': additional_info
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ML detector statistics"""
        return {
            'is_loaded': self.is_loaded,
            'model_type': type(self.model).__name__ if self.model else None,
            'predictions_count': self.predictions_count,
            'anomalies_detected': self.anomalies_detected,
            'detection_rate': self.anomalies_detected / max(self.predictions_count, 1),
            'confidence_threshold': self.config.confidence_threshold,
            'feature_count': len(self.feature_columns)
        }
    
    def retrain_model(self, training_data: List[PacketInfo], labels: List[int]):
        """Retrain the model with new data"""
        try:
            if not training_data or not labels:
                logger.warning("No training data provided for retraining")
                return False
            
            # Extract features
            X = self._extract_features(training_data)
            if X is None:
                logger.error("Failed to extract features for retraining")
                return False
            
            # Retrain model
            self.model.fit(X, labels)
            
            # Save updated model
            joblib.dump(self.model, self.config.model_path)
            
            logger.info("Model retrained and saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return False 