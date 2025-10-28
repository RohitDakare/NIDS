# NIDS ML Training Pipeline Guide

This guide covers the comprehensive machine learning training pipeline for the NIDS (Network Intrusion Detection System).

## 🎯 Overview

The NIDS ML training pipeline provides multiple ways to train, evaluate, and deploy machine learning models for network intrusion detection:

- **Automated Pipeline**: Complete training with data preprocessing, model comparison, and evaluation
- **Web Dashboard**: Interactive training monitoring and management
- **Command Line Tools**: Flexible training options for different scenarios
- **Model Validation**: Comprehensive model testing and validation

## 🚀 Quick Start

### 1. Simple Training (Recommended for beginners)

```bash
# Quick training with default settings
python scripts/train_models.py --quick

# Train specific models
python scripts/train_models.py --models random_forest isolation_forest

# Use synthetic data (if no real dataset available)
python scripts/train_models.py --synthetic --quick
```

### 2. Web Dashboard Training (Recommended for monitoring)

```bash
# Launch the training dashboard
python scripts/train_models.py --dashboard

# Then open: http://localhost:8001
```

### 3. Advanced Training Pipeline

```bash
# Full pipeline with custom configuration
python scripts/ml_training_pipeline.py --data-path data/cic-ids2017 --models random_forest gradient_boosting
```

## 📊 Training Methods

### Method 1: Quick Training Script

**File**: `scripts/train_models.py`

**Usage**:
```bash
python scripts/train_models.py [OPTIONS]
```

**Options**:
- `--quick`: Use optimized settings for fast training
- `--dashboard`: Launch web-based training dashboard
- `--data PATH`: Specify training data directory
- `--models MODEL1 MODEL2`: Select models to train
- `--synthetic`: Generate and use synthetic training data

**Example**:
```bash
# Train Random Forest and Isolation Forest with synthetic data
python scripts/train_models.py --models random_forest isolation_forest --synthetic --quick
```

### Method 2: Web Training Dashboard

**File**: `scripts/training_dashboard.py`

**Features**:
- Real-time training progress monitoring
- Interactive configuration
- Training history and comparison
- Model deployment management
- Live training logs

**Access**: http://localhost:8001

**Usage**:
1. Launch dashboard: `python scripts/train_models.py --dashboard`
2. Configure training parameters in the web interface
3. Start training and monitor progress
4. View results and deploy models

### Method 3: Advanced Training Pipeline

**File**: `scripts/ml_training_pipeline.py`

**Features**:
- Comprehensive data preprocessing
- Multiple model training and comparison
- Advanced evaluation metrics
- Automated plot generation
- Detailed reporting

**Usage**:
```bash
python scripts/ml_training_pipeline.py [OPTIONS]
```

**Configuration File Example** (`training_config.json`):
```json
{
  "data_path": "data/cic-ids2017",
  "test_size": 0.2,
  "random_state": 42,
  "cv_folds": 5,
  "models": {
    "random_forest": {
      "enabled": true,
      "params": {
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": 42
      }
    },
    "isolation_forest": {
      "enabled": true,
      "params": {
        "contamination": 0.1,
        "random_state": 42
      }
    }
  },
  "use_smote": true,
  "save_plots": true,
  "auto_deploy": true
}
```

## 🤖 Supported Models

### 1. Random Forest (Supervised)
- **Best for**: Balanced datasets with labeled attack/normal traffic
- **Pros**: High accuracy, feature importance, robust to outliers
- **Cons**: Requires labeled data
- **Use case**: When you have a good dataset with attack labels

### 2. Gradient Boosting (Supervised)
- **Best for**: Complex patterns in labeled data
- **Pros**: Very high accuracy, handles complex relationships
- **Cons**: Slower training, requires labeled data
- **Use case**: When maximum accuracy is needed

### 3. Isolation Forest (Unsupervised)
- **Best for**: Anomaly detection without labeled attack data
- **Pros**: No need for attack labels, good for unknown attacks
- **Cons**: May have more false positives
- **Use case**: Real-world deployment where attack patterns are unknown

### 4. One-Class SVM (Unsupervised)
- **Best for**: Strict anomaly detection
- **Pros**: Very good at defining normal behavior
- **Cons**: Slow training, sensitive to parameters
- **Use case**: High-security environments with strict anomaly detection

## 📁 Data Requirements

### Real Dataset (Recommended)

**CIC-IDS2017 Dataset**:
1. Download from: https://www.unb.ca/cic/datasets/ids-2017.html
2. Extract CSV files to: `data/cic-ids2017/`
3. Files should contain network flow features and attack labels

**Expected Format**:
- CSV files with network flow features
- Label column named "Label" with values like "BENIGN", "DoS", "PortScan", etc.
- Features like "Flow Duration", "Total Fwd Packets", etc.

### Synthetic Data (Fallback)

If no real dataset is available, the pipeline automatically generates synthetic network traffic data:
- 50,000 samples with realistic network flow features
- 15% attack samples with distinctive patterns
- Suitable for testing and development

## 📊 Training Process

### 1. Data Loading and Preprocessing
- Load CSV files from specified directory
- Clean column names and handle missing values
- Convert multi-class labels to binary (normal/attack)
- Feature selection (top 20 most relevant features)
- Handle infinite values and outliers

### 2. Model Training
- Split data into training/testing sets (80/20 by default)
- Apply SMOTE for class balancing (optional)
- Train multiple models in parallel
- Perform cross-validation for supervised models

### 3. Model Evaluation
- Calculate accuracy, precision, recall, F1-score
- Generate confusion matrices
- ROC curves and AUC scores
- Feature importance analysis (for applicable models)

### 4. Model Selection and Deployment
- Compare all trained models
- Select best performing model based on test accuracy
- Save model with metadata and training information
- Optionally deploy as default model for NIDS system

## 📈 Results and Outputs

### Generated Files

**Models** (`app/ml_models/`):
- `nids_model.joblib`: Default deployed model
- `nids_model_YYYYMMDD_HHMMSS.joblib`: Timestamped model versions

**Training Results** (`training_results/`):
- `training_report_YYYYMMDD_HHMMSS.json`: Detailed training report
- `training_summary_YYYYMMDD_HHMMSS.txt`: Human-readable summary

**Plots** (`training_results/plots/`):
- `model_evaluation_YYYYMMDD_HHMMSS.png`: Model comparison charts
- `roc_curves_YYYYMMDD_HHMMSS.png`: ROC curve comparisons

**Logs** (`logs/`):
- `ml_training_YYYYMMDD_HHMMSS.log`: Detailed training logs

### Training Report Structure

```json
{
  "timestamp": "2024-01-01T12:00:00",
  "best_model": {
    "name": "random_forest",
    "test_score": 0.9542,
    "cv_score": 0.9456
  },
  "model_comparison": {
    "random_forest": {"accuracy": 0.9542, "roc_auc": 0.9823},
    "isolation_forest": {"accuracy": 0.8934, "roc_auc": null}
  },
  "feature_names": ["flow_duration", "total_fwd_packets", ...],
  "config": {...}
}
```

## 🔧 Configuration Options

### Training Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `data_path` | `data/cic-ids2017` | Path to training data directory |
| `test_size` | `0.2` | Fraction of data for testing |
| `random_state` | `42` | Random seed for reproducibility |
| `cv_folds` | `5` | Number of cross-validation folds |
| `use_smote` | `true` | Enable SMOTE for class balancing |
| `save_plots` | `true` | Generate evaluation plots |
| `auto_deploy` | `true` | Deploy best model automatically |

### Model-Specific Parameters

**Random Forest**:
```json
{
  "n_estimators": 100,
  "max_depth": 10,
  "random_state": 42,
  "n_jobs": -1
}
```

**Isolation Forest**:
```json
{
  "contamination": 0.1,
  "random_state": 42,
  "n_jobs": -1
}
```

## 🧪 Model Validation

### Validate Existing Models

```bash
# Validate all models in app/ml_models/
python scripts/validate_model.py
```

**Output**:
```json
{
  "results": [
    {
      "model": "app/ml_models/nids_model.joblib",
      "status": "ok",
      "prediction": false,
      "confidence": 0.85,
      "model_info": {...}
    }
  ]
}
```

### Test Model Performance

```bash
# Test model with synthetic packets
python scripts/test_model_performance.py
```

## 🚨 Troubleshooting

### Common Issues

**1. No training data found**
```
Solution: 
- Download CIC-IDS2017 dataset to data/cic-ids2017/
- Or use --synthetic flag for synthetic data
```

**2. Memory errors during training**
```
Solution:
- Reduce dataset size by using fewer CSV files
- Increase system memory or use cloud instance
- Use --quick flag for optimized settings
```

**3. Poor model performance**
```
Solution:
- Check data quality and feature relevance
- Adjust model parameters
- Try different models (ensemble methods work well)
- Ensure proper class balancing with SMOTE
```

**4. Training dashboard not accessible**
```
Solution:
- Check if port 8001 is available
- Verify firewall settings
- Use localhost:8001 instead of 0.0.0.0:8001
```

### Performance Optimization

**For Large Datasets**:
- Use `--quick` flag for faster training
- Reduce `cv_folds` to 3
- Limit to 2-3 CSV files for initial training
- Use feature selection to reduce dimensionality

**For Production Deployment**:
- Train with full dataset
- Use 5-fold cross-validation
- Enable all evaluation metrics
- Save comprehensive reports

## 🔄 Integration with NIDS System

### Automatic Model Loading

The NIDS system automatically loads the default model (`app/ml_models/nids_model.joblib`) when starting:

```python
# In app/core/ml_detector.py
detector = MLDetector()
detector.load_model("app/ml_models/nids_model.joblib")
```

### Manual Model Deployment

```bash
# Train and deploy new model
python scripts/train_models.py --quick

# Start NIDS with new model
python -m app.main
```

### Model Hot-Swapping

```bash
# Update model without restarting NIDS
curl -X POST http://localhost:8000/api/v1/config/ml \
  -H "Content-Type: application/json" \
  -d '{"model_path": "app/ml_models/nids_model_20240101_120000.joblib"}'
```

## 📚 Best Practices

### 1. Data Preparation
- Use recent network traffic data
- Ensure balanced representation of attack types
- Clean and validate data before training
- Use feature engineering for better performance

### 2. Model Selection
- Start with Random Forest for supervised learning
- Use Isolation Forest for unsupervised anomaly detection
- Combine multiple models for ensemble predictions
- Validate models on separate test datasets

### 3. Training Strategy
- Train regularly with new data
- Keep historical models for comparison
- Monitor model performance in production
- Retrain when performance degrades

### 4. Production Deployment
- Test models thoroughly before deployment
- Monitor false positive/negative rates
- Implement model versioning
- Have rollback procedures ready

## 🔮 Advanced Features

### Custom Feature Engineering

```python
# Add custom features in ml_training_pipeline.py
def extract_custom_features(X):
    X['packet_rate'] = X['total_fwd_packets'] / X['flow_duration']
    X['bytes_per_packet'] = X['total_length_fwd_packets'] / X['total_fwd_packets']
    return X
```

### Ensemble Models

```python
# Combine multiple models for better accuracy
from sklearn.ensemble import VotingClassifier

ensemble = VotingClassifier([
    ('rf', random_forest_model),
    ('gb', gradient_boosting_model)
], voting='soft')
```

### Real-time Model Updates

```python
# Implement online learning for continuous improvement
from sklearn.linear_model import SGDClassifier

online_model = SGDClassifier(loss='log')
# Update model with new data batches
online_model.partial_fit(new_X, new_y)
```

---

## 📞 Support

For issues or questions about the ML training pipeline:

1. Check the training logs in `logs/`
2. Review the troubleshooting section above
3. Validate your data format and quality
4. Test with synthetic data first

The ML training pipeline is designed to be robust and user-friendly, supporting both beginners and advanced users with comprehensive tooling and documentation.
