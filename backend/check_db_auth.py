
import os
import pymongo
from pymongo import MongoClient
from urllib.parse import quote_plus

# Credentials from setup_mongodb.js
username = "nids_user"
password = "19fGlFYnLIcp-KEDy3CMQw"
host = "localhost"
port = "27017"
db_name = "nids"

print(f"Testing connection for user: {username} on {host}:{port}")

username_encoded = quote_plus(username)
password_encoded = quote_plus(password)

connection_string = f"mongodb://{username_encoded}:{password_encoded}@{host}:{port}/{db_name}?authSource=admin"

try:
    client = MongoClient(connection_string, serverSelectionTimeoutMS=2000)
    # The ismaster command is cheap and does not require auth.
    client.admin.command('ismaster')
    print("Server available.")
    
    # Now try an authenticated command
    client.admin.command('ping')
    print("Authentication SUCCESSFUL with setup_mongodb.js credentials!")
except Exception as e:
    print(f"Authentication FAILED with setup_mongodb.js credentials: {e}")
