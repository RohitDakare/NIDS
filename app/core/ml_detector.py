import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Optional, List, Union
import logging
from datetime import datetime
import os
import warnings

from app.models.schemas import PacketInfo, MLModelConfig
from app.utils.security import model_security
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler, OneHotEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, precision_score, 
    recall_score, f1_score, roc_auc_score, confusion_matrix
)
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline
import json
import yaml

# Suppress warnings
warnings.filterwarnings('ignore')

from app.models.schemas import PacketInfo, MLModelConfig, DetectionType, AlertSeverity

logger = logging.getLogger(__name__)

class MLDetector:
    """Enhanced ML-based anomaly detection for network traffic with improved model training and evaluation."""
    
    def __init__(self, config: MLModelConfig):
        """Initialize the enhanced ML detector with configuration."""
        self.config = config
        self.model = None
        self.scaler = None
        self.label_encoder = LabelEncoder()
        self.feature_columns = self._get_feature_columns()
        self.categorical_columns = ['protocol']
        self.numerical_columns = [col for col in self.feature_columns if col not in self.categorical_columns]
        self.class_weights = None
        self.metrics = {}
        # Health/state
        self.is_loaded = False
        self.anomalies_detected = 0
        self.model_expects_raw = False
        self.pipeline = None
        self._init_model()
        
        # Try to load model from file if it exists
        if self.config.model_path and os.path.exists(self.config.model_path):
            try:
                loaded_detector = self.load_model(self.config.model_path)
                if loaded_detector and loaded_detector.is_loaded:
                    # Copy the loaded pipeline and model to this instance
                    self.pipeline = loaded_detector.pipeline
                    self.model = loaded_detector.model
                    self.is_loaded = True
                    self.feature_columns = loaded_detector.feature_columns
                    logger.info(f"Successfully loaded model from {self.config.model_path}")
                else:
                    logger.warning(f"Model file exists but failed to load: {self.config.model_path}")
            except Exception as e:
                logger.warning(f"Could not load model from {self.config.model_path}: {e}")
    
    def _get_feature_columns(self) -> List[str]:
        """Get the list of feature columns for model training."""
        return [
            'packet_length', 'payload_size', 'source_port', 'dest_port',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp', 'protocol_other',
            'has_tcp_flags', 'tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst',
            'tcp_psh', 'tcp_urg', 'hour_of_day', 'day_of_week',
            'flow_duration', 'flow_bytes_sent', 'flow_bytes_received',
            'packet_size_avg', 'packet_size_std', 'packet_size_min', 'packet_size_max',
            'flow_packets', 'flow_avg_packet_size', 'flow_avg_iat', 'flow_std_iat'
        ]
    
    def _init_model(self):
        """Initialize the ML model based on configuration."""
        # Use configured model_type
        model_type = getattr(self.config, 'model_type', 'random_forest') or 'random_forest'
        
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced',
                n_jobs=-1,
                random_state=42,
                verbose=1
            )
        elif model_type == 'isolation_forest':
            self.model = IsolationForest(
                n_estimators=200,
                max_samples='auto',
                contamination='auto',
                random_state=42,
                n_jobs=-1,
                verbose=1
            )
        elif model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=5,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                verbose=1
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
        
        # Initialize the preprocessing pipeline
        self._init_preprocessing_pipeline()
    
    def _init_preprocessing_pipeline(self):
        """Initialize the preprocessing pipeline."""
        # Numerical features pipeline
        numerical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])
        
        # Categorical features pipeline
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        # Combine preprocessing steps
        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, self.numerical_columns),
                ('cat', categorical_transformer, self.categorical_columns)
            ])
        
        # Create the full pipeline
        self.pipeline = Pipeline(steps=[
            ('preprocessor', self.preprocessor),
            ('classifier', self.model)
        ])
        # Mark as loaded once pipeline is constructed
        self.is_loaded = True
    
    def train(self, X: pd.DataFrame, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the ML model with the given data.
        
        Args:
            X: Input features as a pandas DataFrame
            y: Target labels as a numpy array
            test_size: Fraction of data to use for testing
            
        Returns:
            Dictionary containing training metrics and model information
        """
        try:
            # Split data into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            # Handle class imbalance using SMOTE and random undersampling
            over = SMOTE(sampling_strategy=0.5, random_state=42)
            under = RandomUnderSampler(sampling_strategy=0.8, random_state=42)
            
            # Create a pipeline with resampling and model
            self.pipeline = ImbPipeline(steps=[
                ('preprocessor', self.preprocessor),
                ('over', over),
                ('under', under),
                ('classifier', self.model)
            ])
            
            # Train the model
            self.pipeline.fit(X_train, y_train)
            
            # Evaluate the model
            train_metrics = self.evaluate(X_train, y_train, 'train')
            test_metrics = self.evaluate(X_test, y_test, 'test')
            
            # Save the trained model
            self.save_model()
            
            return {
                'status': 'success',
                'train_metrics': train_metrics,
                'test_metrics': test_metrics,
                'model_info': {
                    'model_type': type(self.model).__name__,
                    'features_used': len(self.feature_columns),
                    'training_date': datetime.now().isoformat(),
                    'model_version': '1.0.0'
                }
            }
            
        except Exception as e:
            logger.error(f"Error during model training: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def evaluate(self, X: pd.DataFrame, y: np.ndarray, dataset_name: str = 'test') -> Dict[str, Any]:
        """
        Evaluate the model on the given dataset.
        
        Args:
            X: Input features as a pandas DataFrame
            y: True labels as a numpy array
            dataset_name: Name of the dataset (train/test/validation)
            
        Returns:
            Dictionary containing evaluation metrics
        """
        try:
            # Make predictions
            y_pred = self.pipeline.predict(X)
            y_pred_proba = self.pipeline.predict_proba(X)[:, 1] if hasattr(self.model, 'predict_proba') else None
            
            # Calculate metrics
            metrics = {
                'accuracy': accuracy_score(y, y_pred),
                'precision': precision_score(y, y_pred, average='weighted'),
                'recall': recall_score(y, y_pred, average='weighted'),
                'f1': f1_score(y, y_pred, average='weighted'),
                'confusion_matrix': confusion_matrix(y, y_pred).tolist()
            }
            
            if y_pred_proba is not None:
                metrics['roc_auc'] = roc_auc_score(y, y_pred_proba)
            
            # Store metrics
            self.metrics[dataset_name] = metrics
            
            # Log metrics
            logger.info(f"\n=== {dataset_name.upper()} Metrics ===")
            for metric, value in metrics.items():
                if metric != 'confusion_matrix':
                    logger.info(f"{metric}: {value:.4f}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error during model evaluation: {str(e)}", exc_info=True)
            return {}
    
    def save_model(self, model_path: str = None):
        """Save the trained model and related artifacts."""
        if model_path is None:
            model_path = self.config.model_path
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save the model
        joblib.dump(self.pipeline, model_path)
        
        # Save metadata
        metadata = {
            'model_type': type(self.model).__name__,
            'feature_columns': self.feature_columns,
            'categorical_columns': self.categorical_columns,
            'numerical_columns': self.numerical_columns,
            'metrics': self.metrics,
            'training_date': datetime.now().isoformat(),
            'model_version': '1.0.0'
        }
        
        metadata_path = os.path.join(os.path.dirname(model_path), 'model_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
    
    @classmethod
    def load_model(cls, model_path: str):
        """Load a trained model from disk with security verification."""
        try:
            # Verify model integrity first
            if not model_security.verify_model_integrity(model_path):
                logger.error(f"Model integrity check failed for {model_path}")
                return None
            
            # Load the model/pipeline
            model_data = joblib.load(model_path)
            
            # Create detector instance
            detector = cls(MLModelConfig(model_path=model_path))
            
            # Check if we loaded a Pipeline (which is what save_model saves)
            if isinstance(model_data, (Pipeline, ImbPipeline)):
                # Pipeline format - load it directly
                detector.pipeline = model_data
                # Extract the model from the pipeline
                if hasattr(model_data, 'named_steps'):
                    detector.model = model_data.named_steps.get('classifier') or model_data.named_steps.get('classifier')
                    if detector.model is None:
                        # Try to get the last step which is usually the classifier
                        last_step = list(model_data.named_steps.values())[-1] if model_data.named_steps else None
                        detector.model = last_step
                else:
                    # Fallback: try to get model from steps
                    if hasattr(model_data, 'steps') and len(model_data.steps) > 0:
                        detector.model = model_data.steps[-1][1]  # Last step is usually the classifier
                logger.info(f"Loaded fitted pipeline from {model_path}")
            elif isinstance(model_data, dict):
                # New format with metadata
                model = model_data.get('model')
                feature_names = model_data.get('feature_names', [])
                model_type = model_data.get('model_type', 'unknown')
                training_score = model_data.get('training_score', 0.0)
                detector.model = model
                detector.feature_names = feature_names
                logger.info(f"Loaded model: {model_type} (score: {training_score:.4f})")
            else:
                # Legacy format - just the model, create pipeline around it
                detector.model = model_data
                # Reconstruct pipeline with the loaded model
                detector._init_preprocessing_pipeline()
                # Update the classifier in the pipeline
                if hasattr(detector.pipeline, 'named_steps'):
                    detector.pipeline.named_steps['classifier'] = detector.model
                elif hasattr(detector.pipeline, 'steps') and len(detector.pipeline.steps) > 0:
                    detector.pipeline.steps[-1] = ('classifier', detector.model)
                logger.info(f"Loaded legacy model format from {model_path}")
            
            detector.is_loaded = True
            
            logger.info(f"Secure model loaded successfully from {model_path}")
            return detector
            
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}: {e}", exc_info=True)
            return None
    
    def predict(self, packet: PacketInfo) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Predict if a packet is anomalous.
        
        Args:
            packet: Packet information
            
        Returns:
            Tuple of (is_anomalous, confidence_score, additional_info)
        """
        try:
            # Extract features from the packet
            features = self._extract_features(packet)
            
            if features is None or len(features) == 0:
                return False, 0.0, {}
            
            # Ensure input to pipeline is a DataFrame with expected schema
            if isinstance(features, pd.DataFrame):
                X = features
            elif isinstance(features, dict):
                X = pd.DataFrame([features])
            else:
                # Unexpected type
                return False, 0.0, {}
            
            # Prepare data depending on artifact type
            if self.model_expects_raw:
                # Use only numeric columns in a stable order
                X_num = X.select_dtypes(include=['number'])
                X_np = X_num.to_numpy()
                # Ensure 2D shape (1, n)
                if X_np.ndim == 1:
                    X_np = X_np.reshape(1, -1)
                # Align feature count with estimator if possible
                n_expected = getattr(self.model, 'n_features_in_', X_np.shape[1])
                if X_np.shape[1] < n_expected:
                    # Pad with zeros
                    import numpy as _np
                    pad = _np.zeros((X_np.shape[0], n_expected - X_np.shape[1]))
                    X_np = _np.concatenate([X_np, pad], axis=1)
                elif X_np.shape[1] > n_expected:
                    X_np = X_np[:, :n_expected]
                X_infer = X_np
            else:
                X_infer = X

            # Check if pipeline is fitted before making predictions
            if self.pipeline is None:
                logger.warning("Pipeline is not loaded - skipping prediction")
                return False, 0.0, {}
            
            # Check if pipeline is fitted
            try:
                # Check if pipeline has steps
                if not hasattr(self.pipeline, 'steps') or len(self.pipeline.steps) == 0:
                    logger.warning("Pipeline has no steps - model may not be loaded")
                    return False, 0.0, {}
                
                # Check if pipeline is fitted by trying to access fitted attributes
                # sklearn pipelines have fitted transformers/estimators
                if not hasattr(self.pipeline, 'named_steps') and not hasattr(self.pipeline, 'steps'):
                    logger.warning("Pipeline structure is invalid")
                    return False, 0.0, {}
                
                # Check if any step is fitted (most reliable check)
                try:
                    # Try to access a fitted attribute from the first transformer/estimator
                    first_step = self.pipeline.steps[0][1] if hasattr(self.pipeline, 'steps') else None
                    if first_step is not None:
                        # Check if fitted by looking for common fitted attributes
                        if not (hasattr(first_step, 'mean_') or hasattr(first_step, 'feature_names_in_') or 
                                hasattr(first_step, 'n_features_in_') or hasattr(first_step, 'classes_')):
                            # For models that don't have these, try to check if they're fitted
                            if hasattr(first_step, '__dict__') and len(first_step.__dict__) == 0:
                                logger.warning("Pipeline appears to be unfitted")
                                return False, 0.0, {}
                except Exception as check_error:
                    logger.debug(f"Could not verify pipeline fitted state: {check_error}")
            except Exception:
                pass

            # Make prediction - wrap in try-except to catch NotFittedError
            try:
                from sklearn.utils.validation import check_is_fitted
                # Check if pipeline is fitted
                check_is_fitted(self.pipeline)
            except Exception as fitted_check:
                logger.warning(f"Pipeline is not fitted yet: {fitted_check}. Skipping prediction.")
                return False, 0.0, {'error': 'Model not fitted', 'model_loaded': self.is_loaded}
            
            try:
                if hasattr(self.pipeline, 'predict_proba'):
                    # For classification models with probability estimates
                    prediction = self.pipeline.predict(X_infer)[0]
                    proba = self.pipeline.predict_proba(X_infer)[0]
                    confidence = max(proba)
                    is_anomalous = prediction == 1
                else:
                    # For anomaly detection models
                    prediction = self.pipeline.predict(X_infer)[0]
                    is_anomalous = prediction == -1
                    confidence = 0.8 if is_anomalous else 0.2  # Default confidence
            except Exception as pred_error:
                logger.error(f"Error during prediction: {pred_error}")
                return False, 0.0, {'error': str(pred_error), 'model_loaded': self.is_loaded}
            
            # Additional information for analysis
            additional_info = {
                'model_type': type(self.model).__name__,
                'features_used': len(self.feature_columns),
                'prediction': int(is_anomalous),
                'confidence': float(confidence),
                'timestamp': datetime.now().isoformat()
            }
            
            return is_anomalous, confidence, additional_info
            
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}", exc_info=True)
            return False, 0.0, {}
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if an IP address is private.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if the IP is private, False otherwise
        """
        try:
            # Handle None or empty string
            if not ip_address:
                return False
                
            # Split the IP into octets
            octets = ip_address.split('.')
            if len(octets) != 4:
                return False
                
            # Convert to integers
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # Check for private IP ranges
            # 10.0.0.0 - 10.255.255.255
            if first_octet == 10:
                return True
                
            # 172.16.0.0 - 172.31.255.255
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
                
            # 192.168.0.0 - 192.168.255.255
            if first_octet == 192 and second_octet == 168:
                return True
                
            return False
            
        except (ValueError, AttributeError):
            return False
    
    def get_detection_info(self, packet: PacketInfo) -> dict:
        """
        Get detection information for a packet.
        
        Args:
            packet: Packet information
            
        Returns:
            Dictionary containing detection information
        """
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
        
        # Update anomaly counter
        if is_anomalous:
            self.anomalies_detected += 1

        return {
            'is_anomalous': is_anomalous,
            'confidence': confidence,
            'severity': severity,
            'description': 'ML-based anomaly detected' if is_anomalous else 'Normal traffic',
            'detection_type': DetectionType.ML,
            'model_info': {
                'type': type(self.model).__name__,
                'version': '1.0',
                'features_used': len(self.feature_columns)
            }
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return ML detector statistics and health info used by orchestrator."""
        try:
            latest_test = self.metrics.get('test', {}) if isinstance(self.metrics, dict) else {}
            return {
                'is_loaded': self.is_loaded,
                'anomalies_detected': self.anomalies_detected,
                'model_type': type(self.model).__name__ if self.model is not None else None,
                'confidence_threshold': getattr(self.config, 'confidence_threshold', None),
                'last_metrics': latest_test,
            }
        except Exception:
            return {
                'is_loaded': self.is_loaded,
                'anomalies_detected': self.anomalies_detected,
            }

    def benchmark_inference(self, samples: Optional[List[PacketInfo]] = None, runs: int = 200, warmup: int = 20) -> Dict[str, Any]:
        """
        Benchmark real-time inference performance.
        If samples is None, generate synthetic packets. Returns latency stats and throughput.
        """
        import time
        from statistics import mean
        if not self.is_loaded or self.pipeline is None:
            raise RuntimeError("Model pipeline is not loaded")

        # Prepare samples
        if not samples:
            now = datetime.now()
            samples = [
                PacketInfo(
                    timestamp=now,
                    source_ip=f"192.168.1.{i%250+1}",
                    dest_ip=f"10.0.0.{i%250+1}",
                    protocol='TCP' if i % 2 == 0 else 'UDP',
                    source_port=10000 + (i % 1000),
                    dest_port=80 if i % 2 == 0 else 443,
                    packet_length=60 + (i % 1400),
                    tcp_flags="SYN" if i % 3 == 0 else "ACK",
                    payload_size=0 if i % 5 == 0 else 512
                ) for i in range(max(50, min(runs, 1000)))
            ]

        # Warmup
        for i in range(warmup):
            _ = self.get_detection_info(samples[i % len(samples)])

        # Timed runs
        latencies = []
        start_all = time.perf_counter()
        for i in range(runs):
            t0 = time.perf_counter()
            _ = self.get_detection_info(samples[i % len(samples)])
            latencies.append((time.perf_counter() - t0) * 1000.0)  # ms
        total_time = time.perf_counter() - start_all

        lat_sorted = sorted(latencies)
        p50 = lat_sorted[int(0.50 * len(lat_sorted))]
        p95 = lat_sorted[int(0.95 * len(lat_sorted)) - 1]
        p99 = lat_sorted[int(0.99 * len(lat_sorted)) - 1]
        avg = mean(latencies)
        throughput = runs / total_time

        result = {
            'runs': runs,
            'avg_ms': avg,
            'p50_ms': p50,
            'p95_ms': p95,
            'p99_ms': p99,
            'throughput_qps': throughput,
        }
        logger.info(f"Inference benchmark: {json.dumps(result, indent=2)}")
        return result
    
    def _extract_features(self, packet: Union[PacketInfo, List[PacketInfo]]) -> Optional[pd.DataFrame]:
        """
        Extract features from a packet or list of packets for ML model.
        
        Args:
            packet: Single PacketInfo object or list of PacketInfo objects
            
        Returns:
            DataFrame of features or None if input is invalid/empty
        """
        try:
            # Handle empty input
            if not packet:
                return None
                
            # Handle single packet
            if isinstance(packet, PacketInfo):
                packets = [packet]
            else:
                packets = packet
                
            if not packets:
                return None
                
            features_list = []
            
            for pkt in packets:
                # Basic features
                features = {
                    'packet_length': pkt.packet_length,
                    'payload_size': pkt.payload_size or 0,
                    'source_port': pkt.source_port or 0,
                    'dest_port': pkt.dest_port or 0,
                }
                
                # Protocol encoding (one-hot)
                protocol = pkt.protocol.lower() if pkt.protocol else 'other'
                features.update({
                    'protocol_tcp': 1 if protocol == 'tcp' else 0,
                    'protocol_udp': 1 if protocol == 'udp' else 0,
                    'protocol_icmp': 1 if protocol == 'icmp' else 0,
                    'protocol_other': 1 if protocol not in ['tcp', 'udp', 'icmp'] else 0,
                    'protocol': protocol
                })
                
                # TCP flags analysis
                tcp_flags = pkt.tcp_flags or '' if hasattr(pkt, 'tcp_flags') else ''
                features.update({
                    'has_tcp_flags': 1 if tcp_flags else 0,
                    'tcp_syn': 1 if 'SYN' in tcp_flags else 0,
                    'tcp_ack': 1 if 'ACK' in tcp_flags else 0,
                    'tcp_fin': 1 if 'FIN' in tcp_flags else 0,
                    'tcp_rst': 1 if 'RST' in tcp_flags else 0,
                    'tcp_psh': 1 if 'PSH' in tcp_flags else 0,
                    'tcp_urg': 1 if 'URG' in tcp_flags else 0
                })
                
                # Time-based features
                timestamp = getattr(pkt, 'timestamp', datetime.now())
                features.update({
                    'hour_of_day': timestamp.hour,
                    'day_of_week': timestamp.weekday(),
                    'is_weekend': 1 if timestamp.weekday() >= 5 else 0
                })
                
                # Flow-based features (simplified - in a real system, these would be tracked over time)
                features.update({
                    'flow_duration': 0,  # Would be calculated from flow start time
                    'flow_bytes_sent': pkt.packet_length,
                    'flow_bytes_received': 0,  # Would be tracked per flow
                    'packet_size_avg': pkt.packet_length,
                    'packet_size_std': 0,
                    'packet_size_min': pkt.packet_length,
                    'packet_size_max': pkt.packet_length,
                    'flow_packets': 1,  # Would be incremented per flow
                    'flow_avg_packet_size': pkt.packet_length,
                    'flow_avg_iat': 0,  # Average inter-arrival time
                    'flow_std_iat': 0   # Standard deviation of inter-arrival times
                })
                
                features_list.append(features)
            
            # Convert to DataFrame for consistency with tests
            df = pd.DataFrame(features_list)
            
            # Ensure all expected columns are present
            for col in self.feature_columns:
                if col not in df.columns and col != 'protocol':
                    df[col] = 0
            
            # Reorder columns to match feature_columns (excluding 'protocol' which is categorical)
            ordered_cols = [col for col in self.feature_columns if col != 'protocol']
            if 'protocol' in self.feature_columns:
                ordered_cols.append('protocol')
                
            return df[ordered_cols]
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}", exc_info=True)
            return None
    
# Example usage
if __name__ == "__main__":
    # Example configuration
    config = MLModelConfig(
        model_path="app/ml_models/enhanced_nids_model.joblib",
        model_type="random_forest",
        confidence_threshold=0.8
    )
    
    # Initialize the detector
    detector = MLDetector(config)
    
    # Example packet
    from datetime import datetime
    packet = PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        protocol="TCP",
        source_port=54321,
        dest_port=80,
        packet_length=1500,
        tcp_flags="SYN,ACK",
        payload_size=1460
    )
    
    # Make a prediction
    is_anomalous, confidence, info = detector.predict(packet)
    print(f"Anomaly detected: {is_anomalous}, Confidence: {confidence:.2f}")
    print("Additional info:", json.dumps(info, indent=2))