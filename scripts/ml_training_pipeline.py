#!/usr/bin/env python3
"""
Comprehensive ML Training Pipeline for NIDS

This script provides a complete training pipeline with:
- Data preprocessing and validation
- Multiple model training and comparison
- Model evaluation and metrics
- Automated model deployment
- Training progress visualization
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from typing import Dict, List, Tuple, Any
import logging
from pathlib import Path
import argparse

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix, 
    roc_auc_score, precision_recall_curve, roc_curve
)
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

# Configure logging
def setup_logging():
    """Setup comprehensive logging"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"ml_training_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

class NIDSTrainingPipeline:
    """Comprehensive ML training pipeline for NIDS"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.logger = setup_logging()
        self.models_dir = Path("app/ml_models")
        self.results_dir = Path("training_results")
        self.plots_dir = self.results_dir / "plots"
        
        # Create directories
        for dir_path in [self.models_dir, self.results_dir, self.plots_dir]:
            dir_path.mkdir(exist_ok=True)
        
        self.training_results = {}
        self.feature_names = []
        
    def _default_config(self) -> Dict[str, Any]:
        """Default training configuration"""
        return {
            "data_path": "data/cic-ids2017",
            "test_size": 0.2,
            "random_state": 42,
            "cv_folds": 5,
            "models": {
                "random_forest": {
                    "enabled": True,
                    "params": {
                        "n_estimators": 100,
                        "max_depth": 10,
                        "random_state": 42,
                        "n_jobs": -1
                    }
                },
                "gradient_boosting": {
                    "enabled": True,
                    "params": {
                        "n_estimators": 100,
                        "learning_rate": 0.1,
                        "max_depth": 6,
                        "random_state": 42
                    }
                },
                "isolation_forest": {
                    "enabled": True,
                    "params": {
                        "contamination": 0.1,
                        "random_state": 42,
                        "n_jobs": -1
                    }
                },
                "one_class_svm": {
                    "enabled": False,  # Disabled by default (slow)
                    "params": {
                        "kernel": "rbf",
                        "gamma": "scale",
                        "nu": 0.1
                    }
                }
            },
            "use_smote": True,
            "feature_selection": {
                "enabled": True,
                "max_features": 20
            },
            "save_plots": True,
            "auto_deploy": True
        }
    
    def load_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and preprocess training data"""
        self.logger.info("🔄 Loading training data...")
        
        data_path = Path(self.config["data_path"])
        
        # Try to load real dataset
        if data_path.exists():
            csv_files = list(data_path.glob("*.csv"))
            if csv_files:
                return self._load_real_data(csv_files)
        
        # Fallback to synthetic data
        self.logger.warning("No real dataset found. Generating synthetic data...")
        return self._generate_synthetic_data()
    
    def _load_real_data(self, csv_files: List[Path]) -> Tuple[pd.DataFrame, pd.Series]:
        """Load real CIC-IDS2017 or similar dataset"""
        self.logger.info(f"Loading {len(csv_files)} CSV files...")
        
        dfs = []
        for file_path in csv_files[:3]:  # Limit to first 3 files
            self.logger.info(f"  📁 Loading {file_path.name}...")
            try:
                df = pd.read_csv(file_path)
                dfs.append(df)
            except Exception as e:
                self.logger.warning(f"  ⚠️  Failed to load {file_path}: {e}")
        
        if not dfs:
            raise ValueError("No valid CSV files could be loaded")
        
        data = pd.concat(dfs, ignore_index=True)
        self.logger.info(f"✅ Loaded {len(data):,} samples")
        
        # Clean and process
        data.columns = data.columns.str.strip()
        
        # Find label column
        label_col = None
        for col in ['Label', 'label', 'Label ', ' Label', 'Attack']:
            if col in data.columns:
                label_col = col
                break
        
        if label_col is None:
            raise ValueError("No label column found")
        
        # Separate features and labels
        y = data[label_col]
        X = data.drop(columns=[label_col])
        
        # Convert to binary classification
        y_binary = (y != 'BENIGN').astype(int)
        
        self.logger.info(f"  🎯 Attack samples: {y_binary.sum():,}")
        self.logger.info(f"  ✅ Normal samples: {(y_binary == 0).sum():,}")
        
        return X, y_binary
    
    def _generate_synthetic_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Generate synthetic network traffic data"""
        self.logger.info("🔄 Generating synthetic training data...")
        
        np.random.seed(self.config["random_state"])
        n_samples = 50000  # Increased sample size
        
        # Network flow features
        features = {
            'flow_duration': np.random.exponential(1000, n_samples),
            'total_fwd_packets': np.random.poisson(15, n_samples),
            'total_bwd_packets': np.random.poisson(12, n_samples),
            'total_length_fwd_packets': np.random.exponential(800, n_samples),
            'total_length_bwd_packets': np.random.exponential(600, n_samples),
            'fwd_packet_length_max': np.random.exponential(150, n_samples),
            'fwd_packet_length_min': np.random.exponential(60, n_samples),
            'fwd_packet_length_mean': np.random.exponential(100, n_samples),
            'bwd_packet_length_max': np.random.exponential(140, n_samples),
            'bwd_packet_length_min': np.random.exponential(55, n_samples),
            'flow_bytes_per_sec': np.random.exponential(2000, n_samples),
            'flow_packets_per_sec': np.random.exponential(20, n_samples),
            'flow_iat_mean': np.random.exponential(150, n_samples),
            'flow_iat_std': np.random.exponential(75, n_samples),
            'flow_iat_max': np.random.exponential(300, n_samples),
            'flow_iat_min': np.random.exponential(20, n_samples),
            'fwd_iat_total': np.random.exponential(800, n_samples),
            'fwd_iat_mean': np.random.exponential(150, n_samples),
            'fwd_iat_std': np.random.exponential(75, n_samples),
            'fwd_iat_max': np.random.exponential(300, n_samples),
            'fwd_iat_min': np.random.exponential(20, n_samples),
            'bwd_iat_total': np.random.exponential(700, n_samples),
            'bwd_iat_mean': np.random.exponential(140, n_samples),
            'bwd_iat_std': np.random.exponential(70, n_samples),
            'syn_flag_count': np.random.poisson(2, n_samples),
            'rst_flag_count': np.random.poisson(1, n_samples),
            'psh_flag_count': np.random.poisson(3, n_samples),
            'ack_flag_count': np.random.poisson(5, n_samples),
            'urg_flag_count': np.random.poisson(0.1, n_samples),
            'fin_flag_count': np.random.poisson(1, n_samples),
        }
        
        X = pd.DataFrame(features)
        
        # Generate labels (15% attacks for more realistic distribution)
        y = np.random.choice([0, 1], n_samples, p=[0.85, 0.15])
        
        # Make attack samples more distinctive
        attack_mask = y == 1
        X.loc[attack_mask, 'flow_duration'] *= np.random.uniform(2, 5, attack_mask.sum())
        X.loc[attack_mask, 'total_fwd_packets'] *= np.random.uniform(1.5, 3, attack_mask.sum())
        X.loc[attack_mask, 'flow_bytes_per_sec'] *= np.random.uniform(3, 8, attack_mask.sum())
        X.loc[attack_mask, 'syn_flag_count'] *= np.random.uniform(5, 15, attack_mask.sum())
        
        self.logger.info(f"✅ Generated {n_samples:,} synthetic samples")
        self.logger.info(f"  🎯 Attack samples: {y.sum():,}")
        self.logger.info(f"  ✅ Normal samples: {(y == 0).sum():,}")
        
        return X, pd.Series(y)
    
    def preprocess_data(self, X: pd.DataFrame, y: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Preprocess the data for training"""
        self.logger.info("🔄 Preprocessing data...")
        
        # Handle missing values
        X = X.fillna(X.median())
        
        # Remove infinite values
        X = X.replace([np.inf, -np.inf], np.nan).fillna(X.median())
        
        # Feature selection
        if self.config["feature_selection"]["enabled"]:
            max_features = self.config["feature_selection"]["max_features"]
            if len(X.columns) > max_features:
                # Select features with highest variance
                feature_vars = X.var().sort_values(ascending=False)
                selected_features = feature_vars.head(max_features).index.tolist()
                X = X[selected_features]
                self.logger.info(f"  🎯 Selected top {len(selected_features)} features")
        
        self.feature_names = X.columns.tolist()
        self.logger.info(f"✅ Preprocessed data shape: {X.shape}")
        
        return X, y
    
    def train_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Train multiple ML models and compare performance"""
        self.logger.info("🔄 Training ML models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config["test_size"], 
            random_state=self.config["random_state"], 
            stratify=y
        )
        
        models = {}
        
        # Train each enabled model
        for model_name, model_config in self.config["models"].items():
            if not model_config["enabled"]:
                continue
                
            self.logger.info(f"  🤖 Training {model_name}...")
            
            try:
                model_result = self._train_single_model(
                    model_name, model_config, X_train, X_test, y_train, y_test
                )
                models[model_name] = model_result
                self.logger.info(f"    ✅ {model_name} trained successfully (score: {model_result['test_score']:.4f})")
            except Exception as e:
                self.logger.error(f"    ❌ Failed to train {model_name}: {e}")
        
        if not models:
            raise ValueError("No models were successfully trained")
        
        # Select best model
        best_model_name = max(models.keys(), key=lambda k: models[k]['test_score'])
        best_model = models[best_model_name]
        
        self.logger.info(f"🏆 Best model: {best_model_name} (score: {best_model['test_score']:.4f})")
        
        return {
            'best_model': best_model,
            'best_model_name': best_model_name,
            'all_models': models,
            'feature_names': self.feature_names,
            'test_data': (X_test, y_test)
        }
    
    def _train_single_model(self, model_name: str, model_config: Dict, 
                           X_train: pd.DataFrame, X_test: pd.DataFrame,
                           y_train: pd.Series, y_test: pd.Series) -> Dict[str, Any]:
        """Train a single model"""
        
        if model_name == "random_forest":
            pipeline = ImbPipeline([
                ('scaler', StandardScaler()),
                ('smote', SMOTE(random_state=self.config["random_state"])) if self.config["use_smote"] else ('passthrough', 'passthrough'),
                ('classifier', RandomForestClassifier(**model_config["params"]))
            ])
            pipeline.fit(X_train, y_train)
            y_pred = pipeline.predict(X_test)
            y_pred_proba = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, 'predict_proba') else None
            
        elif model_name == "gradient_boosting":
            pipeline = ImbPipeline([
                ('scaler', StandardScaler()),
                ('smote', SMOTE(random_state=self.config["random_state"])) if self.config["use_smote"] else ('passthrough', 'passthrough'),
                ('classifier', GradientBoostingClassifier(**model_config["params"]))
            ])
            pipeline.fit(X_train, y_train)
            y_pred = pipeline.predict(X_test)
            y_pred_proba = pipeline.predict_proba(X_test)[:, 1]
            
        elif model_name == "isolation_forest":
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', IsolationForest(**model_config["params"]))
            ])
            pipeline.fit(X_train[y_train == 0])  # Train only on normal data
            y_pred_raw = pipeline.predict(X_test)
            y_pred = (y_pred_raw == -1).astype(int)
            y_pred_proba = None
            
        elif model_name == "one_class_svm":
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', OneClassSVM(**model_config["params"]))
            ])
            pipeline.fit(X_train[y_train == 0])  # Train only on normal data
            y_pred_raw = pipeline.predict(X_test)
            y_pred = (y_pred_raw == -1).astype(int)
            y_pred_proba = None
            
        else:
            raise ValueError(f"Unknown model type: {model_name}")
        
        # Calculate metrics
        test_score = accuracy_score(y_test, y_pred)
        
        # Cross-validation score (for supervised models only)
        cv_score = None
        if model_name in ["random_forest", "gradient_boosting"]:
            cv_scores = cross_val_score(
                pipeline, X_train, y_train, 
                cv=StratifiedKFold(n_splits=self.config["cv_folds"], shuffle=True, random_state=self.config["random_state"]),
                scoring='accuracy'
            )
            cv_score = cv_scores.mean()
        
        return {
            'model': pipeline,
            'test_score': test_score,
            'cv_score': cv_score,
            'predictions': y_pred,
            'predictions_proba': y_pred_proba,
            'model_type': model_name
        }
    
    def evaluate_models(self, training_results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive model evaluation"""
        self.logger.info("🔄 Evaluating models...")
        
        X_test, y_test = training_results['test_data']
        evaluation_results = {}
        
        for model_name, model_result in training_results['all_models'].items():
            self.logger.info(f"  📊 Evaluating {model_name}...")
            
            y_pred = model_result['predictions']
            y_pred_proba = model_result['predictions_proba']
            
            # Basic metrics
            accuracy = accuracy_score(y_test, y_pred)
            
            # Classification report
            class_report = classification_report(y_test, y_pred, output_dict=True)
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # ROC AUC (if probabilities available)
            roc_auc = None
            if y_pred_proba is not None:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            
            evaluation_results[model_name] = {
                'accuracy': accuracy,
                'classification_report': class_report,
                'confusion_matrix': cm.tolist(),
                'roc_auc': roc_auc,
                'cv_score': model_result.get('cv_score'),
                'test_score': model_result['test_score']
            }
        
        # Generate plots
        if self.config["save_plots"]:
            self._generate_evaluation_plots(training_results, evaluation_results)
        
        return evaluation_results
    
    def _generate_evaluation_plots(self, training_results: Dict[str, Any], 
                                 evaluation_results: Dict[str, Any]):
        """Generate evaluation plots"""
        self.logger.info("📊 Generating evaluation plots...")
        
        X_test, y_test = training_results['test_data']
        
        # Model comparison plot
        plt.figure(figsize=(12, 8))
        
        # Accuracy comparison
        plt.subplot(2, 2, 1)
        models = list(evaluation_results.keys())
        accuracies = [evaluation_results[m]['accuracy'] for m in models]
        plt.bar(models, accuracies)
        plt.title('Model Accuracy Comparison')
        plt.ylabel('Accuracy')
        plt.xticks(rotation=45)
        
        # Confusion matrices
        n_models = len(models)
        for i, model_name in enumerate(models):
            plt.subplot(2, n_models, n_models + i + 1)
            cm = np.array(evaluation_results[model_name]['confusion_matrix'])
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
            plt.title(f'{model_name}\nConfusion Matrix')
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
        
        plt.tight_layout()
        plot_path = self.plots_dir / f"model_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"  💾 Saved evaluation plot: {plot_path}")
        
        # ROC curves (for models with probabilities)
        plt.figure(figsize=(10, 8))
        for model_name, model_result in training_results['all_models'].items():
            if model_result['predictions_proba'] is not None:
                fpr, tpr, _ = roc_curve(y_test, model_result['predictions_proba'])
                auc = evaluation_results[model_name]['roc_auc']
                plt.plot(fpr, tpr, label=f'{model_name} (AUC = {auc:.3f})')
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves Comparison')
        plt.legend()
        plt.grid(True)
        
        roc_plot_path = self.plots_dir / f"roc_curves_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(roc_plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"  💾 Saved ROC curves: {roc_plot_path}")
    
    def save_model(self, training_results: Dict[str, Any]) -> str:
        """Save the best trained model"""
        self.logger.info("💾 Saving best model...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_filename = f"nids_model_{timestamp}.joblib"
        model_path = self.models_dir / model_filename
        
        best_model = training_results['best_model']['model']
        best_model_name = training_results['best_model_name']
        
        # Prepare model metadata
        model_data = {
            'model': best_model,
            'feature_names': training_results['feature_names'],
            'model_type': best_model_name,
            'training_score': training_results['best_model']['test_score'],
            'cv_score': training_results['best_model'].get('cv_score'),
            'trained_at': datetime.now().isoformat(),
            'version': '2.0',
            'training_config': self.config
        }
        
        # Save timestamped model
        joblib.dump(model_data, model_path)
        self.logger.info(f"  💾 Model saved: {model_path}")
        
        # Save as default model if auto-deploy is enabled
        if self.config["auto_deploy"]:
            default_path = self.models_dir / "nids_model.joblib"
            joblib.dump(model_data, default_path)
            self.logger.info(f"  🚀 Model deployed as default: {default_path}")
        
        return str(model_path)
    
    def save_training_report(self, training_results: Dict[str, Any], 
                           evaluation_results: Dict[str, Any], 
                           model_path: str):
        """Save comprehensive training report"""
        self.logger.info("📄 Generating training report...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.results_dir / f"training_report_{timestamp}.json"
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'config': self.config,
            'best_model': {
                'name': training_results['best_model_name'],
                'path': model_path,
                'test_score': training_results['best_model']['test_score'],
                'cv_score': training_results['best_model'].get('cv_score')
            },
            'feature_names': training_results['feature_names'],
            'evaluation_results': evaluation_results,
            'model_comparison': {
                model_name: {
                    'accuracy': results['accuracy'],
                    'roc_auc': results['roc_auc']
                }
                for model_name, results in evaluation_results.items()
            }
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"  📄 Training report saved: {report_path}")
        
        # Also save a human-readable summary
        summary_path = self.results_dir / f"training_summary_{timestamp}.txt"
        with open(summary_path, 'w') as f:
            f.write("NIDS ML Training Pipeline - Summary Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Training completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Best model: {training_results['best_model_name']}\n")
            f.write(f"Test accuracy: {training_results['best_model']['test_score']:.4f}\n")
            if training_results['best_model'].get('cv_score'):
                f.write(f"Cross-validation score: {training_results['best_model']['cv_score']:.4f}\n")
            f.write(f"Model saved to: {model_path}\n\n")
            
            f.write("Model Comparison:\n")
            f.write("-" * 20 + "\n")
            for model_name, results in evaluation_results.items():
                f.write(f"{model_name}:\n")
                f.write(f"  Accuracy: {results['accuracy']:.4f}\n")
                if results['roc_auc']:
                    f.write(f"  ROC AUC: {results['roc_auc']:.4f}\n")
                f.write("\n")
        
        self.logger.info(f"  📄 Training summary saved: {summary_path}")
    
    def run_pipeline(self) -> bool:
        """Run the complete training pipeline"""
        try:
            self.logger.info("🚀 Starting NIDS ML Training Pipeline...")
            
            # Load data
            X, y = self.load_data()
            
            # Preprocess data
            X, y = self.preprocess_data(X, y)
            
            # Train models
            training_results = self.train_models(X, y)
            
            # Evaluate models
            evaluation_results = self.evaluate_models(training_results)
            
            # Save best model
            model_path = self.save_model(training_results)
            
            # Generate report
            self.save_training_report(training_results, evaluation_results, model_path)
            
            self.logger.info("🎉 Training pipeline completed successfully!")
            self.logger.info(f"🏆 Best model: {training_results['best_model_name']}")
            self.logger.info(f"📊 Test accuracy: {training_results['best_model']['test_score']:.4f}")
            self.logger.info(f"💾 Model saved: {model_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Training pipeline failed: {e}")
            return False


def main():
    """Main function with CLI support"""
    parser = argparse.ArgumentParser(description="NIDS ML Training Pipeline")
    parser.add_argument("--config", type=str, help="Path to training configuration JSON file")
    parser.add_argument("--data-path", type=str, help="Path to training data directory")
    parser.add_argument("--models", nargs="+", help="Models to train", 
                       choices=["random_forest", "gradient_boosting", "isolation_forest", "one_class_svm"])
    parser.add_argument("--no-plots", action="store_true", help="Disable plot generation")
    parser.add_argument("--no-deploy", action="store_true", help="Disable auto-deployment")
    
    args = parser.parse_args()
    
    # Load configuration
    config = None
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Create pipeline
    pipeline = NIDSTrainingPipeline(config)
    
    # Override config with CLI arguments
    if args.data_path:
        pipeline.config["data_path"] = args.data_path
    if args.models:
        for model_name in pipeline.config["models"]:
            pipeline.config["models"][model_name]["enabled"] = model_name in args.models
    if args.no_plots:
        pipeline.config["save_plots"] = False
    if args.no_deploy:
        pipeline.config["auto_deploy"] = False
    
    # Run pipeline
    success = pipeline.run_pipeline()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
