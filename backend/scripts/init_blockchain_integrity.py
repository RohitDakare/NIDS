import os
import sys
import logging
from dotenv import load_dotenv

# Add the project root to the python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.blockchain.client import BlockchainClient
from app.utils.integrity_manager import IntegrityManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    # Load .env from the project root (one level up from scripts/)
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    load_dotenv(dotenv_path=env_path)
    
    # Check for required environment variables
    if not os.getenv("BLOCKCHAIN_PRIVATE_KEY") or not os.getenv("CONTRACT_ADDRESS"):
        logger.error("Missing BLOCKCHAIN_PRIVATE_KEY or CONTRACT_ADDRESS in environment variables.")
        print("\nPlease set the following in your .env file:")
        print("BLOCKCHAIN_RPC_URL=http://your-rpc-url")
        print("BLOCKCHAIN_PRIVATE_KEY=your-private-key")
        print("CONTRACT_ADDRESS=your-deployed-contract-address")
        return

    logger.info("Initializing blockchain-based integrity hashes...")
    
    try:
        client = BlockchainClient()
        manager = IntegrityManager(client)
        
        logger.info("Uploading current local hashes to blockchain...")
        manager.update_on_chain_hashes()
        
        logger.info("✅ Successfully updated on-chain integrity hashes.")
        
    except Exception as e:
        logger.error(f"Failed to update on-chain hashes: {e}")

if __name__ == "__main__":
    main()
