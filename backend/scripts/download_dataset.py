"""
Script to download and prepare the CIC-IDS2017 dataset for NIDS training.
"""
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import requests
import zipfile
from pathlib import Path
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"  # Main page for reference
MIRROR_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"  # Will need to be updated with actual mirror

# Instead of direct download, we'll provide instructions for manual download
FILES = {
    "Monday-WorkingHours.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Wednesday-workingHours.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "https://www.unb.ca/cic/datasets/ids-2017.html"
}

def check_files_exist(data_dir: str = "data/cic-ids2017") -> bool:
    """Check if all required files exist in the data directory."""
    data_path = Path(data_dir)
    return all((data_path / filename).exists() for filename in FILES.keys())

def print_download_instructions() -> None:
    """Print instructions for manually downloading the dataset."""
    print("\n" + "="*80)
    print("CIC-IDS2017 Dataset Download Instructions")
    print("="*80)
    print("The CIC-IDS2017 dataset needs to be downloaded manually due to changes in the hosting.")
    print("Please follow these steps:")
    print("1. Visit: https://www.unb.ca/cic/datasets/ids-2017.html")
    print("2. Click on 'CSV Files' under 'Download the dataset' section")
    print("3. Download the following files and place them in the 'data/cic-ids2017' directory:")
    for filename in FILES.keys():
        print(f"   - {filename}")
    print("\n4. After downloading all files, run this script again to process the data.")
    print("="*80 + "\n")

def load_and_preprocess_data(data_dir: str = "data/cic-ids2017") -> tuple:
    """Load and preprocess the CIC-IDS2017 dataset."""
    data_path = Path(data_dir)
    dfs = []
    
    # Check if files exist
    if not check_files_exist(data_dir):
        print_download_instructions()
        raise FileNotFoundError("Required dataset files not found. Please follow the download instructions above.")
    
    # Load all CSV files
    for filename in FILES.keys():
        file_path = data_path / filename
        if file_path.exists():
            logging.info(f"Loading {filename}...")
            try:
                # Try different encodings
                try:
                    df = pd.read_csv(file_path, encoding='utf-8')
                except UnicodeDecodeError:
                    df = pd.read_csv(file_path, encoding='cp1252')
                dfs.append(df)
            except Exception as e:
                logging.error(f"Error loading {filename}: {str(e)}")
                continue
    
    if not dfs:
        raise FileNotFoundError("No valid data files found. Please check the downloaded files.")
    
    # Combine all dataframes
    df = pd.concat(dfs, ignore_index=True)
    
    # Basic preprocessing
    df = df.dropna()  # Drop rows with missing values
    df = df.replace([np.inf, -np.inf], np.nan).dropna()  # Handle infinite values
    
    # Convert non-numeric columns to numeric
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            except:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
    
    # Drop any remaining NaN values
    df = df.dropna()
    
    # Separate features and target
    X = df.drop(columns=['Label', 'Destination Port'], errors='ignore')
    y = df['Label']
    
    # Convert labels to binary (0 for normal, 1 for attack)
    y = (y != 'BENIGN').astype(int)
    
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Create a mock network traffic dataset for NIDS training')
    parser.add_argument('--samples', type=int, default=10000, help='Number of samples to generate')
    parser.add_argument('--data-dir', type=str, default="data/cic-ids2017", 
                       help='Directory to save the dataset')
    parser.add_argument('--output-dir', type=str, default="data/processed",
                      help='Directory to save processed data')
    parser.add_argument('--skip-raw', action='store_true',
                      help='Skip raw dataset creation and only process existing data')
    
    args = parser.parse_args()
    
    # Create data directories
    os.makedirs(args.data_dir, exist_ok=True)
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create and process the dataset
    try:
        if not args.skip_raw:
            logging.info("Creating mock dataset...")
            create_mock_dataset(n_samples=args.samples, data_dir=args.data_dir)
        else:
            logging.info("Skipping raw dataset creation as requested")
            
        logging.info("Processing dataset...")
        create_processed_data(data_dir=args.data_dir, output_dir=args.output_dir)
        logging.info("Done!")
        
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise