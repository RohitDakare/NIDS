
import hashlib
import json
import os

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

model_path = "app/ml_models/nids_model.joblib"
checksum_file = "config/model_checksums.json"

if os.path.exists(model_path):
    checksum = calculate_file_hash(model_path)
    print(f"Calculated checksum for {model_path}: {checksum}")
    
    data = {"nids_model.joblib": checksum}
    
    with open(checksum_file, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"Saved checksum to {checksum_file}")
else:
    print(f"Error: {model_path} does not exist.")
