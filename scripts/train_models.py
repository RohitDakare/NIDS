#!/usr/bin/env python3
"""
Simple ML Model Training Script for NIDS

A simplified interface for training NIDS ML models with different options.
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from ml_training_pipeline import NIDSTrainingPipeline

def main():
    parser = argparse.ArgumentParser(description="Train NIDS ML Models")
    parser.add_argument("--quick", action="store_true", 
                       help="Quick training with default settings")
    parser.add_argument("--dashboard", action="store_true", 
                       help="Launch training dashboard")
    parser.add_argument("--data", type=str, default="data/cic-ids2017",
                       help="Path to training data")
    parser.add_argument("--models", nargs="+", 
                       choices=["random_forest", "gradient_boosting", "isolation_forest", "one_class_svm"],
                       default=["random_forest", "isolation_forest"],
                       help="Models to train")
    parser.add_argument("--synthetic", action="store_true",
                       help="Use synthetic data for training")
    
    args = parser.parse_args()
    
    if args.dashboard:
        print("🚀 Launching ML Training Dashboard...")
        from training_dashboard import main as dashboard_main
        dashboard_main()
        return
    
    # Configure training
    config = {
        "data_path": args.data,
        "models": {}
    }
    
    # Enable selected models
    all_models = ["random_forest", "gradient_boosting", "isolation_forest", "one_class_svm"]
    for model in all_models:
        config["models"][model] = {"enabled": model in args.models}
    
    if args.quick:
        print("🚀 Quick training mode - using optimized settings")
        config.update({
            "test_size": 0.3,
            "cv_folds": 3,
            "use_smote": True,
            "save_plots": True,
            "auto_deploy": True
        })
    
    if args.synthetic:
        print("🔬 Using synthetic data for training")
        config["data_path"] = "synthetic"
    
    # Create and run pipeline
    pipeline = NIDSTrainingPipeline(config)
    
    print("🤖 Starting NIDS ML model training...")
    print(f"📊 Training models: {', '.join(args.models)}")
    print(f"📁 Data path: {config['data_path']}")
    
    success = pipeline.run_pipeline()
    
    if success:
        print("\n🎉 Training completed successfully!")
        print("💾 Models saved to: app/ml_models/")
        print("📊 Results saved to: training_results/")
        print("\n🚀 Next steps:")
        print("  1. Start the NIDS system: python -m app.main")
        print("  2. Test the models: python scripts/validate_model.py")
        print("  3. View training dashboard: python scripts/train_models.py --dashboard")
    else:
        print("\n❌ Training failed!")
        print("📋 Check logs in: logs/")
        sys.exit(1)

if __name__ == "__main__":
    main()
