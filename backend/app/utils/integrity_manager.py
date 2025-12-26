import os
import logging
from typing import List, Dict
from app.blockchain.client import BlockchainClient
from app.utils.config import settings

logger = logging.getLogger(__name__)

class IntegrityManager:
    def __init__(self, blockchain_client: BlockchainClient):
        self.blockchain_client = blockchain_client
        # Adjust paths to project root
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.files_to_check = [
            (os.path.join(project_root, settings.MODEL_PATH), "nids_model.joblib"),
            (os.path.join(project_root, "app", "rules", "default_rules.yaml"), "default_rules.yaml")
        ]

    def verify_all(self) -> bool:
        """Verify all critical files against blockchain hashes"""
        all_passed = True
        for file_path, file_name in self.files_to_check:
            if not os.path.exists(file_path):
                logger.warning(f"Integrity check skipped: File not found {file_path}")
                continue
                
            is_valid = self.blockchain_client.verify_integrity(file_path, file_name)
            if not is_valid:
                logger.error(f"INTEGRITY FAILURE: {file_name} does not match on-chain hash!")
                all_passed = False
            else:
                logger.info(f"Integrity verified for {file_name}")
        
        return all_passed

    def update_on_chain_hashes(self):
        """Helper to upload current local hashes to blockchain (Owner only)"""
        for file_path, file_name in self.files_to_check:
            if not os.path.exists(file_path):
                continue
            
            import hashlib
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).digest()
            
            tx_hash = self.blockchain_client._send_transaction('updateIntegrityHash', file_name, file_hash)
            if tx_hash:
                logger.info(f"Updated integrity hash for {file_name} on blockchain: {tx_hash}")
