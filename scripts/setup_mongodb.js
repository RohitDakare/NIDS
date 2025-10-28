
use admin
db.createUser({
  user: "nids_user",
  pwd: "YWvjWV5UGnUFwc7m1I5Zng",
  roles: [
    { role: "readWrite", db: "nids" },
    { role: "dbAdmin", db: "nids" }
  ]
})

use nids
db.createCollection("alerts")
db.createCollection("packets")
db.createCollection("signature_rules")
db.createCollection("system_status")

# Create indexes for performance and security
db.alerts.createIndex({ "timestamp": -1 })
db.alerts.createIndex({ "severity": 1 })
db.alerts.createIndex({ "source_ip": 1 })
db.packets.createIndex({ "timestamp": -1 })
db.system_status.createIndex({ "component": 1 })
