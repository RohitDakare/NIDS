import os
import json
from web3 import Web3
from solcx import compile_standard, install_solc
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def deploy():
    # Load .env from the project root (one level up from scripts/)
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    load_dotenv(dotenv_path=env_path)
    
    # 1. Configuration
    rpc_url = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
    private_key = os.getenv("BLOCKCHAIN_PRIVATE_KEY")
    
    if not private_key:
        logger.error("No BLOCKCHAIN_PRIVATE_KEY found in .env")
        return

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    account = w3.eth.account.from_key(private_key)
    
    logger.info(f"Deploying from account: {account.address}")

    # 2. Compile Contract
    logger.info("Installing Solidity compiler...")
    install_solc("0.8.0")
    
    contract_path = "app/blockchain/contracts/NIDSRecord.sol"
    with open(contract_path, "r") as f:
        contract_source = f.read()

    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {"NIDSRecord.sol": {"content": contract_source}},
            "settings": {
                "outputSelection": {
                    "*": {"*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]}
                }
            },
        },
        solc_version="0.8.0",
    )

    # Extract bytecode and ABI
    bytecode = compiled_sol["contracts"]["NIDSRecord.sol"]["NIDSRecord"]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"]["NIDSRecord.sol"]["NIDSRecord"]["abi"]

    # 3. Deploy
    NIDSRecord = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    nonce = w3.eth.get_transaction_count(account.address)
    
    transaction = NIDSRecord.constructor().build_transaction({
        "chainId": w3.eth.chain_id,
        "gasPrice": w3.eth.gas_price,
        "from": account.address,
        "nonce": nonce,
    })

    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    
    logger.info(f"Waiting for deployment transaction {w3.to_hex(tx_hash)} to be mined...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    contract_address = tx_receipt.contractAddress
    logger.info(f"✅ Contract deployed to: {contract_address}")
    
    print(f"\nACTION REQUIRED: Update your .env file with:")
    print(f"CONTRACT_ADDRESS={contract_address}")

if __name__ == "__main__":
    deploy()
