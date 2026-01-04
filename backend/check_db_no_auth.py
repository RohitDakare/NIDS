
import pymongo
from pymongo import MongoClient

print("Testing connection WITHOUT credentials...")

connection_string = "mongodb://localhost:27017/"

try:
    client = MongoClient(connection_string, serverSelectionTimeoutMS=2000)
    client.admin.command('ismaster')
    print("Server available.")
    
    # Try to list databases - requires some privilege usually, but if no auth is on, it works.
    dbs = client.list_database_names()
    print(f"Connection SUCCESSFUL without credentials! DBs: {dbs}")
except Exception as e:
    print(f"Connection FAILED without credentials: {e}")
