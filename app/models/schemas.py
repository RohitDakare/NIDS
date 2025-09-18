from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionType(str, Enum):
    ML = "ml"
    SIGNATURE = "signature"
    HYBRID = "hybrid"

class PacketInfo(BaseModel):
    """Packet information model"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    packet_length: int
    tcp_flags: Optional[str] = None
    payload_size: int = 0

class Alert(BaseModel):
    """Alert model"""
    id: Optional[str] = None
    timestamp: datetime
    severity: AlertSeverity
    detection_type: DetectionType
    description: str
    source_ip: str
    dest_ip: str
    protocol: str
    confidence_score: Optional[float] = None
    packet_data: Optional[Dict[str, Any]] = None
    is_resolved: bool = False

class SnifferConfig(BaseModel):
    """Packet sniffer configuration"""
    interface: str = Field(default="eth0", description="Network interface to monitor")
    packet_count: int = Field(default=1000, description="Number of packets to capture")
    timeout: int = Field(default=30, description="Capture timeout in seconds")
    filter: Optional[str] = Field(default=None, description="BPF filter string")

class MLModelConfig(BaseModel):
    """ML model configuration"""
    model_path: str = Field(default="app/ml_models/nids_model.joblib")
    confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    feature_columns: List[str] = Field(default_factory=list)

class SystemStatus(BaseModel):
    """System status information"""
    is_running: bool
    uptime: float
    packets_captured: int
    alerts_generated: int
    ml_predictions: int
    signature_matches: int
    memory_usage: float
    cpu_usage: float

class StartSnifferRequest(BaseModel):
    """Request to start packet sniffing"""
    config: Optional[SnifferConfig] = None

class StopSnifferRequest(BaseModel):
    """Request to stop packet sniffing"""
    force: bool = False

class AlertResponse(BaseModel):
    """Response containing alerts"""
    alerts: List[Alert]
    total_count: int
    page: int
    page_size: int

class PacketResponse(BaseModel):
    """Response containing packet data"""
    packets: List[PacketInfo]
    total_count: int
    page: int
    page_size: int

class StatsResponse(BaseModel):
    """System statistics response"""
    total_packets: int
    total_alerts: int
    ml_detections: int
    signature_detections: int
    false_positives: int
    detection_rate: float
    average_confidence: float 