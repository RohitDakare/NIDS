#!/usr/bin/env python3
"""
Test MongoDB Connection Script

This script tests the MongoDB connection using the application's configuration.
"""
import sys
import asyncio
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError
from app.utils.config import settings

def test_mongodb_connection():
    """Test MongoDB connection synchronously"""
    print("Testing MongoDB connection...")
    
    try:
        # Create a connection using the configured settings
        client = MongoClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=5000,  # 5 second timeout
            connectTimeoutMS=30000,         # 30 second connection timeout
            socketTimeoutMS=30000,          # 30 second socket timeout
        )
        
        # The ping command is cheap and does not require auth
        print("Sending ping command to MongoDB...")
        client.admin.command('ping')
        
        # Get database info
        db = client[settings.MONGODB_DB_NAME]
        print(f"Successfully connected to MongoDB at {settings.MONGODB_URL}")
        print(f"Database name: {settings.MONGODB_DB_NAME}")
        
        # List collections in the database
        collections = db.list_collection_names()
        print(f"\nCollections in database:")
        for collection in collections:
            print(f"- {collection}")
        
        # Get server info
        server_info = client.server_info()
        print("\nMongoDB Server Info:")
        print(f"Version: {server_info.get('version')}")
        print(f"Host: {client.HOST}:{client.PORT}")
        
        return True
        
    except ConnectionFailure as e:
        print(f"\n❌ Failed to connect to MongoDB: {e}")
        print(f"Connection URL: {settings.MONGODB_URL}")
        print("\nTroubleshooting tips:")
        print("1. Make sure MongoDB is running")
        print("2. Check if the connection URL is correct")
        print("3. Verify authentication credentials if required")
        print("4. Check if your IP is whitelisted if using MongoDB Atlas")
        return False
    except ConfigurationError as e:
        print(f"\n❌ Configuration error: {e}")
        return False
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        return False
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    print("=== MongoDB Connection Tester ===\n")
    success = test_mongodb_connection()
    
    if success:
        print("\n✅ MongoDB connection test completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ MongoDB connection test failed!")
        sys.exit(1)
