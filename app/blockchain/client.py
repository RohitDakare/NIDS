import os
import json
import hashlib
from typing import Optional, Dict, Any
from web3 import Web3
from eth_account import Account
import logging

logger = logging.getLogger(__name__)

def get_secret(secret_name: str) -> Optional[str]:
    """
    Retrieves a secret from a secure location (e.g., HashiCorp Vault, AWS Secrets Manager).
    This is a placeholder and should be implemented with a proper secrets management tool.
    """
    # In a real implementation, you would query your secrets manager here.
    # For now, we'll fall back to environment variables with a warning.
    secret_value = os.getenv(secret_name)
    if not secret_value:
        logger.warning(f"Secret '{secret_name}' not found. For production, configure a proper secrets manager.")
    return secret_value

class BlockchainClient:
    def __init__(self, rpc_url: Optional[str] = None, 
                 contract_address: Optional[str] = None, 
                 private_key: Optional[str] = None):
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
        self.contract_address = contract_address or os.getenv("CONTRACT_ADDRESS")
        
        # Securely retrieve the private key
        self.private_key = private_key or get_secret("BLOCKCHAIN_PRIVATE_KEY")
        
        if not self.private_key:
            logger.warning("Blockchain private key not found. Transaction signing will be disabled.")

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.account = None
        if self.private_key:
            try:
                self.account = Account.from_key(self.private_key)
            except Exception as e:
                logger.error(f"Failed to create account from private key: {e}. The key may be invalid.")
                self.account = None # Ensure account is None if key is bad
            
        self.contract_abi = self._load_abi()
        self.contract = None
        if self.contract_address and self.contract_abi:
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.contract_abi)

    def _load_abi(self):
        # In a real scenario, this would load from a compiled JSON file
        # For simplicity, I'll provide a minimal ABI here matching the Solidity contract
        return [
            {
                "inputs": [
                    {"internalType": "string", "name": "alertId", "type": "string"},
                    {"internalType": "bytes32", "name": "alertHash", "type": "bytes32"},
                    {"internalType": "string", "name": "severity", "type": "string"}
                ],
                "name": "recordAlert",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "string", "name": "ipAddress", "type": "string"},
                    {"internalType": "string", "name": "reason", "type": "string"}
                ],
                "name": "triggerIncidentResponse",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "string", "name": "fileName", "type": "string"},
                    {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"}
                ],
                "name": "updateIntegrityHash",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "string", "name": "fileName", "type": "string"}
                ],
                "name": "getIntegrityHash",
                "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]

    def _send_transaction(self, func_name: str, *args):
        if not self.contract or not self.account:
            logger.warning(f"Blockchain client not fully configured. Skipping {func_name}")
            return None
        
        try:
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            txn = getattr(self.contract.functions, func_name)(*args).build_transaction({
                'chainId': self.w3.eth.chain_id,
                'gas': 2000000,
                'gasPrice': self.w3.to_wei('50', 'gwei'),
                'nonce': nonce,
            })
            signed_txn = self.w3.eth.account.sign_transaction(txn, private_key=self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            return self.w3.to_hex(tx_hash)
        except Exception as e:
            logger.error(f"Blockchain transaction failed ({func_name}): {e}")
            return None

    def record_alert(self, alert_id: str, alert_data: Dict[str, Any]):
        """Store alert hash on blockchain"""
        alert_json = json.dumps(alert_data, sort_keys=True)
        alert_hash = hashlib.sha256(alert_json.encode()).digest()
        severity = alert_data.get('severity', 'unknown')
        return self._send_transaction('recordAlert', alert_id, alert_hash, severity)

    def trigger_incident_response(self, ip_address: str, reason: str):
        """Trigger automated response on blockchain"""
        return self._send_transaction('triggerIncidentResponse', ip_address, reason)

    def verify_integrity(self, file_path: str, file_name: str) -> bool:
        """Verify file integrity against blockchain hash"""
        if not self.contract:
            logger.error("CRITICAL: Blockchain contract not configured for integrity check. Failing closed.")
            return False
        
        if not os.path.exists(file_path):
            logger.error(f"File not found for integrity check: {file_path}")
            return False
            
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).digest()
            
        try:
            on_chain_hash = self.contract.functions.getIntegrityHash(file_name).call()
            # If the hash is all zeros, it means it's not set on-chain.
            if on_chain_hash == b'\x00' * 32:
                logger.warning(f"No on-chain integrity hash found for {file_name}. Failing closed.")
                return False # If no hash is registered, it's not considered valid.
            return on_chain_hash == file_hash
        except Exception as e:
            logger.error(f"CRITICAL: Failed to verify integrity on-chain due to an exception: {e}. Failing closed.")
            return False
