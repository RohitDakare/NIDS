#!/usr/bin/env python3
"""
Initialize MongoDB Collections for NIDS

This script creates the necessary collections with validation rules and indexes.
"""
import sys
from pymongo import MongoClient, ASCENDING, DESCENDING, TEXT
from pymongo.errors import CollectionInvalid, OperationFailure
from app.utils.config import settings

def create_collections():
    """Create collections with validation rules and indexes"""
    try:
        # Connect to MongoDB
        client = MongoClient(settings.MONGODB_URL)
        db = client[settings.MONGODB_DB_NAME]
        
        # Drop existing collections if they exist (for development only)
        # Comment out in production
        for collection in ["alerts", "packets", "signature_rules", "system_status"]:
            if collection in db.list_collection_names():
                db[collection].drop()
                print(f"Dropped existing collection: {collection}")
        
        # 1. Alerts Collection
        alerts_validator = {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': [
                    'timestamp', 'source_ip', 'destination_ip', 
                    'protocol', 'severity', 'message', 'status'
                ],
                'properties': {
                    'timestamp': {'bsonType': 'date'},
                    'source_ip': {'bsonType': 'string'},
                    'destination_ip': {'bsonType': 'string'},
                    'source_port': {'bsonType': 'int'},
                    'destination_port': {'bsonType': 'int'},
                    'protocol': {
                        'bsonType': 'string',
                        'enum': ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'OTHER']
                    },
                    'signature_id': {'bsonType': 'objectId'},
                    'severity': {
                        'bsonType': 'string',
                        'enum': ['low', 'medium', 'high', 'critical']
                    },
                    'message': {'bsonType': 'string'},
                    'status': {
                        'bsonType': 'string',
                        'enum': ['new', 'in_review', 'resolved', 'false_positive']
                    },
                    'resolution_notes': {'bsonType': 'string'},
                    'payload': {'bsonType': 'string'},
                    'created_at': {'bsonType': 'date'},
                    'updated_at': {'bsonType': 'date'}
                }
            }
        }
        
        db.create_collection(
            'alerts',
            validator=alerts_validator,
            validationAction='error',
            validationLevel='strict'
        )
        
        # 2. Packets Collection
        packets_validator = {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['timestamp', 'source_ip', 'destination_ip', 'protocol'],
                'properties': {
                    'timestamp': {'bsonType': 'date'},
                    'source_ip': {'bsonType': 'string'},
                    'destination_ip': {'bsonType': 'string'},
                    'source_port': {'bsonType': 'int'},
                    'destination_port': {'bsonType': 'int'},
                    'protocol': {'bsonType': 'string'},
                    'length': {'bsonType': 'int'},
                    'is_malicious': {'bsonType': 'bool'},
                    'alert_id': {'bsonType': 'objectId'},
                    'payload': {'bsonType': 'string'},
                    'headers': {'bsonType': 'object'}
                }
            }
        }
        
        db.create_collection(
            'packets',
            validator=packets_validator,
            validationAction='warn',  # More lenient for packets as they come in high volume
            validationLevel='moderate'
        )
        
        # 3. Signature Rules Collection
        signature_rules_validator = {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['name', 'description', 'pattern', 'severity', 'is_active'],
                'properties': {
                    'name': {
                        'bsonType': 'string',
                        'description': 'Unique name for the signature rule'
                    },
                    'description': {'bsonType': 'string'},
                    'pattern': {'bsonType': 'string'},
                    'severity': {
                        'bsonType': 'string',
                        'enum': ['low', 'medium', 'high', 'critical']
                    },
                    'is_active': {'bsonType': 'bool'},
                    'created_at': {'bsonType': 'date'},
                    'updated_at': {'bsonType': 'date'}
                }
            }
        }
        
        db.create_collection(
            'signature_rules',
            validator=signature_rules_validator,
            validationAction='error',
            validationLevel='strict'
        )
        
        # 4. System Status Collection
        system_status_validator = {
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['timestamp', 'cpu_usage', 'memory_usage'],
                'properties': {
                    'timestamp': {'bsonType': 'date'},
                    'cpu_usage': {'bsonType': 'double', 'minimum': 0, 'maximum': 100},
                    'memory_usage': {'bsonType': 'double', 'minimum': 0, 'maximum': 100},
                    'disk_usage': {'bsonType': 'double', 'minimum': 0, 'maximum': 100},
                    'network_in': {'bsonType': 'double', 'minimum': 0},
                    'network_out': {'bsonType': 'double', 'minimum': 0},
                    'alerts_count': {'bsonType': 'int', 'minimum': 0},
                    'packets_processed': {'bsonType': 'int', 'minimum': 0},
                    'is_running': {'bsonType': 'bool'}
                }
            }
        }
        
        db.create_collection(
            'system_status',
            validator=system_status_validator,
            validationAction='warn',
            validationLevel='moderate'
        )
        
        # Create Indexes
        # Alerts Collection Indexes
        db.alerts.create_index([('timestamp', DESCENDING)])
        db.alerts.create_index([('source_ip', ASCENDING)])
        db.alerts.create_index([('destination_ip', ASCENDING)])
        db.alerts.create_index([('severity', ASCENDING)])
        db.alerts.create_index([('status', ASCENDING)])
        db.alerts.create_index([('signature_id', ASCENDING)])
        
        # Packets Collection Indexes
        db.packets.create_index([('timestamp', DESCENDING)])
        db.packets.create_index([
            ('source_ip', ASCENDING),
            ('destination_ip', ASCENDING),
            ('timestamp', DESCENDING)
        ])
        db.packets.create_index([('is_malicious', ASCENDING)])
        db.packets.create_index([('alert_id', ASCENDING)])
        
        # Signature Rules Indexes
        db.signature_rules.create_index([('name', ASCENDING)], unique=True)
        db.signature_rules.create_index([('severity', ASCENDING)])
        db.signature_rules.create_index([('is_active', ASCENDING)])
        
        # System Status Indexes
        db.system_status.create_index([('timestamp', DESCENDING)])
        
        print("\n✅ Successfully created collections with validation rules and indexes!")
        print("\nCollections created:")
        for collection in db.list_collection_names():
            print(f"- {collection}")
        
        return True
        
    except CollectionInvalid as e:
        print(f"\n❌ Collection creation error: {e}")
        return False
    except OperationFailure as e:
        print(f"\n❌ Operation failed: {e}")
        return False
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        return False
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    print("=== NIDS MongoDB Collection Initialization ===\n")
    print("This script will create the following collections:")
    print("- alerts: Stores security alerts")
    print("- packets: Stores network packets")
    print("- signature_rules: Stores detection signatures")
    print("- system_status: Stores system monitoring data\n")
    
    confirm = input("Do you want to continue? (y/n): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        sys.exit(0)
        
    success = create_collections()
    
    if success:
        print("\n✅ Database initialization completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Database initialization failed!")
        sys.exit(1)
