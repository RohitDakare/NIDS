import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Create directories
os.makedirs('app/ml_models', exist_ok=True)

# Create a simple dummy model
print("Creating dummy ML model...")

# Generate some dummy training data
X_train = np.random.rand(100, 10)  # 100 samples, 10 features
y_train = np.random.randint(0, 2, 100)  # Binary classification

# Create and train a simple model
model = RandomForestClassifier(n_estimators=10, random_state=42)
model.fit(X_train, y_train)

# Create a scaler
scaler = StandardScaler()
scaler.fit(X_train)

# Save the model and scaler
model_data = {
    'model': model,
    'scaler': scaler,
    'feature_names': [f'feature_{i}' for i in range(10)],
    'version': '1.0.0'
}

joblib.dump(model_data, 'app/ml_models/nids_model.joblib')
print("✅ Dummy ML model created at app/ml_models/nids_model.joblib")

# Test loading the model
loaded_model = joblib.load('app/ml_models/nids_model.joblib')
print("✅ Model loading test successful")
print(f"Model type: {type(loaded_model['model'])}")
print(f"Feature count: {len(loaded_model['feature_names'])}")
