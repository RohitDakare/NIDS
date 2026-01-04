
import pymongo
from pymongo import MongoClient

# Credentials from setup_mongodb.js
username = "nids_user"
password = "19fGlFYnLIcp-KEDy3CMQw"

print(f"Creating user {username}...")

try:
    # Connect to localhost without auth (as established that this works)
    client = MongoClient("mongodb://localhost:27017/")
    
    # Use the admin database to create the user
    admin_db = client["admin"]
    
    # Check if user exists
    user_info = admin_db.command("usersInfo", {"user": username, "db": "admin"})
    if user_info["users"]:
        print(f"User {username} already exists. Updating password...")
        admin_db.command("updateUser", username, pwd=password)
    else:
        print(f"User {username} does not exist. Creating...")
        admin_db.command("createUser", username, pwd=password, roles=[
            {"role": "readWrite", "db": "nids"},
            {"role": "dbAdmin", "db": "nids"}
        ])
        
    print("User creation/update SUCCESSFUL.")
    
except Exception as e:
    print(f"User creation FAILED: {e}")
