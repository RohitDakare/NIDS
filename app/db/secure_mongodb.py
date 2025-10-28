"""
Secure MongoDB connection and operations for NIDS
"""

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure, ServerSelectionTimeoutError
import ssl
from urllib.parse import quote_plus

from app.utils.security import security_manager, input_validator

logger = logging.getLogger(__name__)

class SecureMongoManager:
    """Secure MongoDB connection and operations manager"""
    
    def __init__(self):
        self.client = None
        self.db = None
        self.connection_string = self._build_secure_connection_string()
        self.db_name = os.getenv("MONGODB_DB_NAME", "nids")
        
    def _build_secure_connection_string(self) -> str:
        """Build secure MongoDB connection string"""
        # Get credentials from environment
        username = os.getenv("MONGODB_USERNAME", "nids_user")
        password = os.getenv("MONGODB_PASSWORD")
        host = os.getenv("MONGODB_HOST", "localhost")
        port = os.getenv("MONGODB_PORT", "27017")
        
        if not password:
            logger.warning("No MongoDB password configured - using insecure connection")
            return f"mongodb://{host}:{port}"
        
        # URL encode credentials to handle special characters
        username_encoded = quote_plus(username)
        password_encoded = quote_plus(password)
        
        # Build secure connection string
        connection_string = f"mongodb://{username_encoded}:{password_encoded}@{host}:{port}/{self.db_name}?authSource=admin"
        
        # Add SSL options if enabled
        if os.getenv("MONGODB_SSL_ENABLED", "false").lower() == "true":
            connection_string += "&ssl=true&ssl_cert_reqs=CERT_REQUIRED"
        
        return connection_string
    
    def connect(self) -> bool:
        """Establish secure connection to MongoDB"""
        try:
            # Connection options for security
            client_options = {
                'serverSelectionTimeoutMS': 5000,  # 5 second timeout
                'connectTimeoutMS': 10000,         # 10 second connection timeout
                'socketTimeoutMS': 20000,          # 20 second socket timeout
                'maxPoolSize': 50,                 # Maximum connection pool size
                'retryWrites': True,               # Enable retryable writes
            }
            
            # Add SSL configuration if enabled
            if os.getenv("MONGODB_SSL_ENABLED", "false").lower() == "true":
                client_options['ssl'] = True
                client_options['ssl_cert_reqs'] = ssl.CERT_REQUIRED
                
                # Add certificate paths if provided
                ssl_cert_path = os.getenv("MONGODB_SSL_CERT_PATH")
                if ssl_cert_path:
                    client_options['ssl_certfile'] = ssl_cert_path
            
            # Create client with secure options
            self.client = MongoClient(self.connection_string, **client_options)
            
            # Test connection
            self.client.admin.command('ping')
            
            # Get database
            self.db = self.client[self.db_name]
            
            # Log successful connection (without credentials)
            security_manager.log_security_event(
                "database_connected",
                {"database": self.db_name, "host": os.getenv("MONGODB_HOST", "localhost")},
                "system"
            )
            
            logger.info("Secure MongoDB connection established")
            return True
            
        except OperationFailure as e:
            logger.error(f"MongoDB operation/authentication failed: {e}")
            security_manager.log_security_event(
                "database_auth_failed",
                {"error": "Authentication failed", "database": self.db_name},
                "system"
            )
            return False
            
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection failed: {e}")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected MongoDB error: {e}")
            return False
    
    def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")
    
    def create_indexes(self):
        """Create database indexes for performance and security"""
        try:
            if not self.db:
                return False
            
            # Alerts collection indexes
            alerts_collection = self.db.alerts
            alerts_collection.create_index([("timestamp", -1)])  # Most recent first
            alerts_collection.create_index([("severity", 1)])
            alerts_collection.create_index([("source_ip", 1)])
            alerts_collection.create_index([("resolved", 1)])
            alerts_collection.create_index([("detection_type", 1)])
            
            # Packets collection indexes
            packets_collection = self.db.packets
            packets_collection.create_index([("timestamp", -1)])
            packets_collection.create_index([("source_ip", 1)])
            packets_collection.create_index([("dest_ip", 1)])
            packets_collection.create_index([("protocol", 1)])
            
            # System status collection indexes
            system_status_collection = self.db.system_status
            system_status_collection.create_index([("component", 1)])
            system_status_collection.create_index([("timestamp", -1)])
            
            # Signature rules collection indexes
            signature_rules_collection = self.db.signature_rules
            signature_rules_collection.create_index([("rule_id", 1)], unique=True)
            signature_rules_collection.create_index([("enabled", 1)])
            
            logger.info("Database indexes created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
            return False
    
    def insert_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Securely insert alert with validation"""
        try:
            # Validate alert data
            if not self._validate_alert_data(alert_data):
                return None
            
            # Sanitize string fields
            sanitized_alert = self._sanitize_alert_data(alert_data)
            
            # Add security metadata
            sanitized_alert['created_at'] = datetime.utcnow()
            sanitized_alert['source'] = 'nids_system'
            
            # Insert into database
            result = self.db.alerts.insert_one(sanitized_alert)
            
            # Log security event
            security_manager.log_security_event(
                "alert_created",
                {
                    "alert_id": str(result.inserted_id),
                    "severity": sanitized_alert.get('severity'),
                    "source_ip": sanitized_alert.get('source_ip')
                },
                "system"
            )
            
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
            return None
    
    def get_alerts(self, filters: Dict[str, Any] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Securely retrieve alerts with validation"""
        try:
            # Validate and sanitize filters
            safe_filters = self._sanitize_filters(filters or {})
            
            # Limit the number of results for security
            safe_limit = min(limit, 1000)  # Maximum 1000 alerts
            
            # Query database
            cursor = self.db.alerts.find(safe_filters).sort("timestamp", -1).limit(safe_limit)
            alerts = list(cursor)
            
            # Convert ObjectId to string for JSON serialization
            for alert in alerts:
                alert['_id'] = str(alert['_id'])
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {e}")
            return []
    
    def _validate_alert_data(self, alert_data: Dict[str, Any]) -> bool:
        """Validate alert data structure and content"""
        required_fields = ['severity', 'description', 'timestamp']
        
        # Check required fields
        for field in required_fields:
            if field not in alert_data:
                logger.warning(f"Missing required field in alert: {field}")
                return False
        
        # Validate severity
        if not input_validator.validate_severity(alert_data['severity']):
            logger.warning(f"Invalid severity in alert: {alert_data['severity']}")
            return False
        
        # Validate IP addresses if present
        for ip_field in ['source_ip', 'dest_ip']:
            if ip_field in alert_data and alert_data[ip_field]:
                if not input_validator.validate_ip_address(alert_data[ip_field]):
                    logger.warning(f"Invalid IP address in alert: {alert_data[ip_field]}")
                    return False
        
        # Validate ports if present
        for port_field in ['source_port', 'dest_port']:
            if port_field in alert_data and alert_data[port_field]:
                if not input_validator.validate_port(alert_data[port_field]):
                    logger.warning(f"Invalid port in alert: {alert_data[port_field]}")
                    return False
        
        return True
    
    def _sanitize_alert_data(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize alert data to prevent injection"""
        sanitized = {}
        
        for key, value in alert_data.items():
            if isinstance(value, str):
                # Sanitize string values
                sanitized[key] = input_validator.sanitize_string(value)
            elif isinstance(value, (int, float, bool)):
                # Keep numeric and boolean values as-is
                sanitized[key] = value
            elif isinstance(value, datetime):
                # Keep datetime objects as-is
                sanitized[key] = value
            else:
                # Convert other types to string and sanitize
                sanitized[key] = input_validator.sanitize_string(str(value))
        
        return sanitized
    
    def _sanitize_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize database query filters"""
        safe_filters = {}
        
        # Allowed filter fields to prevent NoSQL injection
        allowed_fields = [
            'severity', 'detection_type', 'source_ip', 'dest_ip', 
            'resolved', 'protocol', 'source_port', 'dest_port'
        ]
        
        for key, value in filters.items():
            if key in allowed_fields:
                if isinstance(value, str):
                    # Use exact match for string values to prevent injection
                    safe_filters[key] = {"$eq": input_validator.sanitize_string(value)}
                elif isinstance(value, (int, bool)):
                    safe_filters[key] = {"$eq": value}
        
        return safe_filters
    
    def update_alert_status(self, alert_id: str, resolved: bool, resolution_notes: str = "") -> bool:
        """Securely update alert resolution status"""
        try:
            # Validate alert ID format (MongoDB ObjectId)
            from bson import ObjectId
            try:
                obj_id = ObjectId(alert_id)
            except:
                logger.warning(f"Invalid alert ID format: {alert_id}")
                return False
            
            # Sanitize resolution notes
            safe_notes = input_validator.sanitize_string(resolution_notes, 1000)
            
            # Update document
            result = self.db.alerts.update_one(
                {"_id": obj_id},
                {
                    "$set": {
                        "resolved": resolved,
                        "resolution_notes": safe_notes,
                        "resolved_at": datetime.utcnow() if resolved else None
                    }
                }
            )
            
            if result.modified_count > 0:
                # Log security event
                security_manager.log_security_event(
                    "alert_updated",
                    {
                        "alert_id": alert_id,
                        "resolved": resolved,
                        "has_notes": bool(safe_notes)
                    },
                    "system"
                )
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to update alert status: {e}")
            return False
    
    def delete_alert(self, alert_id: str) -> bool:
        """Securely delete alert"""
        try:
            # Validate alert ID format
            from bson import ObjectId
            try:
                obj_id = ObjectId(alert_id)
            except:
                logger.warning(f"Invalid alert ID format: {alert_id}")
                return False
            
            # Delete document
            result = self.db.alerts.delete_one({"_id": obj_id})
            
            if result.deleted_count > 0:
                # Log security event
                security_manager.log_security_event(
                    "alert_deleted",
                    {"alert_id": alert_id},
                    "system"
                )
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete alert: {e}")
            return False

# Global secure MongoDB manager instance
secure_mongo = SecureMongoManager()
