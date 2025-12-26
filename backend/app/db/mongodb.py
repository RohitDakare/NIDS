from typing import Optional, Dict, Any, List
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, PyMongoError
from app.utils.config import settings
import logging

logger = logging.getLogger(__name__)

class MongoDBManager:
    _instance = None
    _client: Optional[MongoClient] = None
    _db: Optional[Database] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDBManager, cls).__new__(cls)
            cls._instance._initialize_connection()
        return cls._instance

    def _initialize_connection(self):
        """Initialize MongoDB connection"""
        try:
            # Default connection string if not provided in environment
            mongo_uri = settings.MONGODB_URL
            self._client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                connectTimeoutMS=30000,         # 30 second connection timeout
                socketTimeoutMS=30000,           # 30 second socket timeout
                maxPoolSize=100,                 # Maximum number of connections
                minPoolSize=10,                  # Minimum number of connections
                retryWrites=True,
                w="majority"
            )
            # Test the connection
            self._client.admin.command('ping')
            logger.info("Successfully connected to MongoDB")
            
            # Get the database
            self._db = self._client.get_database(settings.MONGODB_DB_NAME)
            
            # Create indexes
            self._create_indexes()
            
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise

    def _create_indexes(self):
        """Create necessary indexes for better query performance"""
        try:
            # Indexes for alerts collection
            self.get_collection("alerts").create_index([("timestamp", -1)])
            self.get_collection("alerts").create_index([("source_ip", 1)])
            self.get_collection("alerts").create_index([("destination_ip", 1)])
            self.get_collection("alerts").create_index([("severity", 1)])
            self.get_collection("alerts").create_index([("status", 1)])
            
            # Indexes for packets collection
            self.get_collection("packets").create_index([("timestamp", -1)])
            self.get_collection("packets").create_index([
                ("source_ip", 1),
                ("destination_ip", 1),
                ("timestamp", -1)
            ])
            
            logger.info("MongoDB indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating MongoDB indexes: {e}")
            raise

    @property
    def db(self) -> Database:
        """Get the database instance"""
        if self._db is None:
            self._initialize_connection()
        return self._db

    def get_collection(self, collection_name: str) -> Collection:
        """Get a collection from the database"""
        return self.db[collection_name]

    def close_connection(self):
        """Close the MongoDB connection"""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None
            logger.info("MongoDB connection closed")

    def __del__(self):
        """Ensure connection is closed when the object is destroyed"""
        self.close_connection()

# Singleton instance
mongodb = MongoDBManager()

def get_db() -> MongoDBManager:
    """Dependency to get MongoDB instance"""
    return mongodb
