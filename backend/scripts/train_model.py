"""
Script to train and evaluate the NIDS model on the CIC-IDS2017 dataset.
"""
import os
import numpy as np
import pandas as pd
import joblib
import json
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, confusion_matrix, 
    classification_report
)
import matplotlib.pyplot as plt
import seaborn as sns

# Set up logging
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_data(data_path: str = "data/processed/cic-ids2017.npz") -> tuple:
    """Load the preprocessed dataset."""
    try:
        data = np.load(data_path)
        return data['X_train'], data['X_test'], data['y_train'], data['y_test']
    except Exception as e:
        logging.error(f"Error loading data: {str(e)}")
        raise

def train_model(X_train: np.ndarray, y_train: np.ndarray) -> dict:
    """
    Train a RandomForest classifier on the training data.
    
    Returns:
        Dictionary containing the trained model and training metrics
    """
    logging.info("Training RandomForest model...")
    
    # Initialize the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
        verbose=1
    )
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Make predictions on training set
    y_train_pred = model.predict(X_train)
    y_train_proba = model.predict_proba(X_train)[:, 1]
    
    # Calculate training metrics
    metrics = {
        'train': {
            'accuracy': accuracy_score(y_train, y_train_pred),
            'precision': precision_score(y_train, y_train_pred),
            'recall': recall_score(y_train, y_train_pred),
            'f1': f1_score(y_train, y_train_pred),
            'roc_auc': roc_auc_score(y_train, y_train_proba),
            'confusion_matrix': confusion_matrix(y_train, y_train_pred).tolist()
        }
    }
    
    return {
        'model': model,
        'metrics': metrics
    }

def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Evaluate the model on the test set and return metrics."""
    logging.info("Evaluating model on test set...")
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    metrics = {
        'test': {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
    }
    
    return metrics

def save_model(model, metrics: dict, output_dir: str = "models/nids") -> None:
    """Save the trained model and metrics."""
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save the model
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = output_path / f"nids_model_{timestamp}.joblib"
    joblib.dump(model, model_path)
    
    # Save metrics
    metrics_path = output_path / f"metrics_{timestamp}.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Save feature importances
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        # Save feature importances to CSV
        feature_importance = pd.DataFrame({
            'feature': [f"feature_{i}" for i in range(len(importances))],
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        feature_importance.to_csv(output_path / f"feature_importances_{timestamp}.csv", index=False)
    
    logging.info(f"Model saved to {model_path}")
    logging.info(f"Metrics saved to {metrics_path}")

def plot_confusion_matrix(conf_matrix: np.ndarray, output_path: str) -> None:
    """Plot and save confusion matrix."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig(output_path)
    plt.close()

def main():
    # Load data
    try:
        X_train, X_test, y_train, y_test = load_data()
        logging.info(f"Training set shape: {X_train.shape}")
        logging.info(f"Test set shape: {X_test.shape}")
    except Exception as e:
        logging.error(f"Failed to load data: {str(e)}")
        return
    
    # Train model
    try:
        result = train_model(X_train, y_train)
        model = result['model']
        metrics = result['metrics']
        
        # Evaluate on test set
        test_metrics = evaluate_model(model, X_test, y_test)
        metrics.update(test_metrics)
        
        # Print metrics
        logging.info("\n=== Model Evaluation ===")
        logging.info(f"Test Accuracy: {metrics['test']['accuracy']:.4f}")
        logging.info(f"Test Precision: {metrics['test']['precision']:.4f}")
        logging.info(f"Test Recall: {metrics['test']['recall']:.4f}")
        logging.info(f"Test F1-Score: {metrics['test']['f1']:.4f}")
        logging.info(f"Test ROC-AUC: {metrics['test']['roc_auc']:.4f}")
        
        # Save model and metrics
        save_model(model, metrics)
        
        # Plot confusion matrix
        output_dir = "models/nids"
        os.makedirs(output_dir, exist_ok=True)
        plot_confusion_matrix(
            np.array(metrics['test']['confusion_matrix']),
            f"{output_dir}/confusion_matrix.png"
        )
        
    except Exception as e:
        logging.error(f"Error during model training/evaluation: {str(e)}")
        return

if __name__ == "__main__":
    main()