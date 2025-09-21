#!/usr/bin/env python3
"""
ML Model Training Script for NIDS

This script trains machine learning models for network intrusion detection
using the CIC-IDS2017 dataset or custom network traffic data.
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from typing import Tuple, Dict, Any
import logging
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

from app.utils.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/model_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NIDSModelTrainer:
    """Train ML models for network intrusion detection"""
    
    def __init__(self, data_path: str = None):
        self.data_path = data_path or "data/cic-ids2017"
        self.models_dir = "app/ml_models"
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        # Ensure directories exist
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
    def load_and_preprocess_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and preprocess the training data"""
        logger.info("Loading and preprocessing data...")
        
        # Try to load CIC-IDS2017 dataset
        data_files = []
        if os.path.exists(self.data_path):
            for file in os.listdir(self.data_path):
                if file.endswith('.csv'):
                    data_files.append(os.path.join(self.data_path, file))
        
        if not data_files:
            logger.warning("No CSV files found in data directory. Generating synthetic data...")
            return self._generate_synthetic_data()
        
        # Load and combine all CSV files
        dfs = []
        for file in data_files[:3]:  # Limit to first 3 files for faster training
            logger.info(f"Loading {file}...")
            df = pd.read_csv(file)
            dfs.append(df)
        
        data = pd.concat(dfs, ignore_index=True)
        logger.info(f"Loaded {len(data)} samples from {len(data_files)} files")
        
        # Clean column names
        data.columns = data.columns.str.strip()
        
        # Handle different label column names
        label_col = None
        for col in ['Label', 'label', 'Label ', ' Label']:
            if col in data.columns:
                label_col = col
                break
        
        if label_col is None:
            raise ValueError("No label column found in dataset")
        
        # Separate features and labels
        y = data[label_col]
        X = data.drop(columns=[label_col])
        
        # Convert labels to binary (normal vs attack)
        y_binary = (y != 'BENIGN').astype(int)
        
        # Select relevant features
        X = self._select_features(X)
        
        # Handle missing values
        X = X.fillna(X.median())
        
        # Remove infinite values
        X = X.replace([np.inf, -np.inf], np.nan).fillna(X.median())
        
        logger.info(f"Preprocessed data shape: {X.shape}")
        logger.info(f"Attack samples: {y_binary.sum()}, Normal samples: {(y_binary == 0).sum()}")
        
        return X, y_binary
    
    def _generate_synthetic_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Generate synthetic network traffic data for training"""
        logger.info("Generating synthetic training data...")
        
        np.random.seed(42)
        n_samples = 10000
        
        # Generate synthetic features
        data = {
            'flow_duration': np.random.exponential(1000, n_samples),
            'total_fwd_packets': np.random.poisson(10, n_samples),
            'total_bwd_packets': np.random.poisson(8, n_samples),
            'total_length_fwd_packets': np.random.exponential(500, n_samples),
            'total_length_bwd_packets': np.random.exponential(400, n_samples),
            'fwd_packet_length_max': np.random.exponential(100, n_samples),
            'fwd_packet_length_min': np.random.exponential(50, n_samples),
            'fwd_packet_length_mean': np.random.exponential(75, n_samples),
            'bwd_packet_length_max': np.random.exponential(90, n_samples),
            'bwd_packet_length_min': np.random.exponential(45, n_samples),
            'flow_bytes_per_sec': np.random.exponential(1000, n_samples),
            'flow_packets_per_sec': np.random.exponential(10, n_samples),
            'flow_iat_mean': np.random.exponential(100, n_samples),
            'flow_iat_std': np.random.exponential(50, n_samples),
            'flow_iat_max': np.random.exponential(200, n_samples),
            'flow_iat_min': np.random.exponential(10, n_samples),
            'fwd_iat_total': np.random.exponential(500, n_samples),
            'fwd_iat_mean': np.random.exponential(100, n_samples),
            'fwd_iat_std': np.random.exponential(50, n_samples),
            'fwd_iat_max': np.random.exponential(200, n_samples),
            'fwd_iat_min': np.random.exponential(10, n_samples),
        }
        
        X = pd.DataFrame(data)
        
        # Generate labels (10% attacks)
        y = np.random.choice([0, 1], n_samples, p=[0.9, 0.1])
        
        # Make attack samples more extreme
        attack_mask = y == 1
        X.loc[attack_mask, 'flow_duration'] *= 3
        X.loc[attack_mask, 'total_fwd_packets'] *= 2
        X.loc[attack_mask, 'flow_bytes_per_sec'] *= 5
        
        return X, pd.Series(y)
    
    def _select_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Select relevant features for training"""
        # Common features in network traffic datasets
        feature_candidates = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
            'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
            'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size'
        ]
        
        # Select features that exist in the dataset
        available_features = []
        for feature in feature_candidates:
            if feature in X.columns:
                available_features.append(feature)
        
        # If no standard features found, use numeric columns
        if not available_features:
            available_features = X.select_dtypes(include=[np.number]).columns.tolist()
        
        # Limit to top 20 features to avoid overfitting
        selected_features = available_features[:20]
        
        logger.info(f"Selected {len(selected_features)} features for training")
        return X[selected_features]
    
    def train_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Train multiple ML models"""
        logger.info("Training ML models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        models = {}
        
        # 1. Random Forest with SMOTE
        logger.info("Training Random Forest model...")
        rf_pipeline = ImbPipeline([
            ('scaler', StandardScaler()),
            ('smote', SMOTE(random_state=42)),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        rf_pipeline.fit(X_train, y_train)
        rf_score = rf_pipeline.score(X_test, y_test)
        models['random_forest'] = {
            'model': rf_pipeline,
            'score': rf_score,
            'type': 'supervised'
        }
        
        # 2. Isolation Forest (Anomaly Detection)
        logger.info("Training Isolation Forest model...")
        iso_pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        iso_pipeline.fit(X_train[y_train == 0])  # Train only on normal data
        iso_predictions = iso_pipeline.predict(X_test)
        iso_predictions = (iso_predictions == -1).astype(int)  # Convert to binary
        iso_score = accuracy_score(y_test, iso_predictions)
        
        models['isolation_forest'] = {
            'model': iso_pipeline,
            'score': iso_score,
            'type': 'unsupervised'
        }
        
        # Select best model
        best_model_name = max(models.keys(), key=lambda k: models[k]['score'])
        best_model = models[best_model_name]
        
        logger.info(f"Best model: {best_model_name} (score: {best_model['score']:.4f})")
        
        # Generate detailed evaluation
        if best_model['type'] == 'supervised':
            y_pred = best_model['model'].predict(X_test)
            logger.info("\nClassification Report:")
            logger.info(classification_report(y_test, y_pred))
        
        return {
            'best_model': best_model['model'],
            'best_model_name': best_model_name,
            'all_models': models,
            'feature_names': X.columns.tolist(),
            'training_score': best_model['score']
        }
    
    def save_model(self, model_info: Dict[str, Any]) -> str:
        """Save the trained model"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_filename = f"nids_model_{timestamp}.joblib"
        model_path = os.path.join(self.models_dir, model_filename)
        
        # Save model with metadata
        model_data = {
            'model': model_info['best_model'],
            'feature_names': model_info['feature_names'],
            'model_type': model_info['best_model_name'],
            'training_score': model_info['training_score'],
            'trained_at': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        joblib.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")
        
        # Also save as default model
        default_path = os.path.join(self.models_dir, "nids_model.joblib")
        joblib.dump(model_data, default_path)
        logger.info(f"Model also saved as default: {default_path}")
        
        return model_path


def main():
    """Main training function"""
    logger.info("Starting NIDS ML model training...")
    
    # Initialize trainer
    trainer = NIDSModelTrainer()
    
    try:
        # Load and preprocess data
        X, y = trainer.load_and_preprocess_data()
        
        # Train models
        model_info = trainer.train_models(X, y)
        
        # Save best model
        model_path = trainer.save_model(model_info)
        
        logger.info("✅ Model training completed successfully!")
        logger.info(f"Best model: {model_info['best_model_name']}")
        logger.info(f"Training score: {model_info['training_score']:.4f}")
        logger.info(f"Model saved to: {model_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Model training failed: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
