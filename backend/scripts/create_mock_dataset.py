"""
Script to create a mock dataset for NIDS training when the original dataset is unavailable.
"""
import os
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_mock_dataset(n_samples: int = 10000, data_dir: str = "data/cic-ids2017") -> None:
    """Create a mock dataset with realistic network traffic features."""

    # Create directories
    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)

    logging.info(f"Creating mock dataset with {n_samples} samples...")

    # Set random seed for reproducibility
    np.random.seed(42)

    # Generate realistic network traffic features
    features = {
        'Destination Port': np.random.choice([80, 443, 22, 53, 25, 110, 143, 993, 995, 21, 23, 993, 995], n_samples),
        'Flow Duration': np.random.exponential(1000, n_samples).astype(int),
        'Total Fwd Packets': np.random.poisson(10, n_samples),
        'Total Backward Packets': np.random.poisson(8, n_samples),
        'Total Length of Fwd Packets': np.random.exponential(1000, n_samples).astype(int),
        'Total Length of Bwd Packets': np.random.exponential(800, n_samples).astype(int),
        'Fwd Packet Length Max': np.random.exponential(200, n_samples).astype(int),
        'Fwd Packet Length Min': np.random.exponential(20, n_samples).astype(int),
        'Fwd Packet Length Mean': np.random.exponential(100, n_samples),
        'Fwd Packet Length Std': np.random.exponential(50, n_samples),
        'Bwd Packet Length Max': np.random.exponential(150, n_samples).astype(int),
        'Bwd Packet Length Min': np.random.exponential(15, n_samples).astype(int),
        'Bwd Packet Length Mean': np.random.exponential(80, n_samples),
        'Bwd Packet Length Std': np.random.exponential(40, n_samples),
        'Flow Bytes/s': np.random.exponential(10000, n_samples),
        'Flow Packets/s': np.random.exponential(100, n_samples),
        'Flow IAT Mean': np.random.exponential(100, n_samples),
        'Flow IAT Std': np.random.exponential(50, n_samples),
        'Flow IAT Max': np.random.exponential(500, n_samples).astype(int),
        'Flow IAT Min': np.random.exponential(10, n_samples).astype(int),
        'Fwd IAT Total': np.random.exponential(1000, n_samples).astype(int),
        'Fwd IAT Mean': np.random.exponential(100, n_samples),
        'Fwd IAT Std': np.random.exponential(50, n_samples),
        'Fwd IAT Max': np.random.exponential(500, n_samples).astype(int),
        'Fwd IAT Min': np.random.exponential(10, n_samples).astype(int),
        'Bwd IAT Total': np.random.exponential(800, n_samples).astype(int),
        'Bwd IAT Mean': np.random.exponential(80, n_samples),
        'Bwd IAT Std': np.random.exponential(40, n_samples),
        'Bwd IAT Max': np.random.exponential(400, n_samples).astype(int),
        'Bwd IAT Min': np.random.exponential(8, n_samples).astype(int),
        'Fwd PSH Flags': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
        'Bwd PSH Flags': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
        'Fwd URG Flags': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
        'Bwd URG Flags': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
        'Fwd Header Length': np.random.choice([20, 40, 60], n_samples),
        'Bwd Header Length': np.random.choice([20, 40, 60], n_samples),
        'Fwd Packets/s': np.random.exponential(50, n_samples),
        'Bwd Packets/s': np.random.exponential(40, n_samples),
        'Min Packet Length': np.random.exponential(20, n_samples).astype(int),
        'Max Packet Length': np.random.exponential(300, n_samples).astype(int),
        'Packet Length Mean': np.random.exponential(150, n_samples),
        'Packet Length Std': np.random.exponential(75, n_samples),
        'Packet Length Variance': np.random.exponential(5000, n_samples),
        'FIN Flag Count': np.random.choice([0, 1], n_samples, p=[0.6, 0.4]),
        'SYN Flag Count': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
        'RST Flag Count': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
        'PSH Flag Count': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
        'ACK Flag Count': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
        'URG Flag Count': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
        'CWE Flag Count': np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
        'ECE Flag Count': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
        'Down/Up Ratio': np.random.exponential(0.5, n_samples),
        'Average Packet Size': np.random.exponential(150, n_samples),
        'Avg Fwd Segment Size': np.random.exponential(100, n_samples),
        'Avg Bwd Segment Size': np.random.exponential(80, n_samples),
        'Fwd Header Length.1': np.random.choice([20, 40, 60], n_samples),
        'Fwd Avg Bytes/Bulk': np.random.exponential(100, n_samples),
        'Fwd Avg Packets/Bulk': np.random.exponential(5, n_samples),
        'Fwd Avg Bulk Rate': np.random.exponential(1000, n_samples),
        'Bwd Avg Bytes/Bulk': np.random.exponential(80, n_samples),
        'Bwd Avg Packets/Bulk': np.random.exponential(4, n_samples),
        'Bwd Avg Bulk Rate': np.random.exponential(800, n_samples),
        'Subflow Fwd Packets': np.random.poisson(8, n_samples),
        'Subflow Fwd Bytes': np.random.exponential(800, n_samples).astype(int),
        'Subflow Bwd Packets': np.random.poisson(6, n_samples),
        'Subflow Bwd Bytes': np.random.exponential(600, n_samples).astype(int),
        'Init_Win_bytes_forward': np.random.choice([8192, 16384, 32768, 65536], n_samples),
        'Init_Win_bytes_backward': np.random.choice([8192, 16384, 32768, 65536], n_samples),
        'act_data_pkt_fwd': np.random.poisson(6, n_samples),
        'min_seg_size_forward': np.random.choice([20, 32, 40], n_samples),
        'Active Mean': np.random.exponential(50, n_samples),
        'Active Std': np.random.exponential(25, n_samples),
        'Active Max': np.random.exponential(100, n_samples).astype(int),
        'Active Min': np.random.exponential(10, n_samples).astype(int),
        'Idle Mean': np.random.exponential(1000, n_samples),
        'Idle Std': np.random.exponential(500, n_samples),
        'Idle Max': np.random.exponential(2000, n_samples).astype(int),
        'Idle Min': np.random.exponential(100, n_samples).astype(int)
    }

    # Create DataFrame
    df = pd.DataFrame(features)

    # Add Label column (mix of BENIGN and various attack types)
    attack_types = ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack', 'Brute Force', 'Heartbleed']
    attack_probs = [0.7, 0.1, 0.08, 0.05, 0.03, 0.02, 0.015, 0.005]  # 70% benign, 30% attacks

    df['Label'] = np.random.choice(attack_types, n_samples, p=attack_probs)

    # Save the dataset
    output_file = data_path / "mock_network_traffic.csv"
    df.to_csv(output_file, index=False)

    logging.info(f"Mock dataset saved to {output_file}")
    logging.info(f"Dataset shape: {df.shape}")
    logging.info(f"Attack distribution:\n{df['Label'].value_counts()}")

    return str(output_file)

def create_processed_data(data_dir: str = "data/cic-ids2017", output_dir: str = "data/processed") -> None:
    """Create processed data files for model training."""

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Load the mock dataset
    data_file = Path(data_dir) / "mock_network_traffic.csv"
    if not data_file.exists():
        logging.error(f"Mock dataset not found at {data_file}. Run create_mock_dataset() first.")
        return

    df = pd.read_csv(data_file)

    # Basic preprocessing (similar to the original script)
    df = df.dropna()

    # Convert infinite values to NaN and drop them
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    # Convert non-numeric columns to numeric, coercing errors to NaN
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            except:
                # If conversion fails, use label encoding
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))

    # Drop any remaining NaN values
    df = df.dropna()

    # Separate features and target
    X = df.drop(columns=['Label'], errors='ignore')
    y = df['Label']

    # Convert labels to binary (0 for normal, 1 for attack)
    y = (y != 'BENIGN').astype(int)

    # Split into train and test sets
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Save the preprocessed data
    np.savez_compressed(
        f"{output_dir}/mock_cic-ids2017.npz",
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test
    )

    logging.info(f"Processed data saved to {output_dir}/mock_cic-ids2017.npz")
    logging.info(f"Training set shape: {X_train.shape}")
    logging.info(f"Test set shape: {X_test.shape}")

if __name__ == "__main__":
    # Create mock dataset
    create_mock_dataset()

    # Create processed data
    create_processed_data()

    logging.info("Mock dataset creation complete!")
