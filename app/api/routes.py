from fastapi import APIRouter, HTTPException, Query, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from typing import List, Optional, Dict, Any
import logging
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from app.models.schemas import (
    StartSnifferRequest, StopSnifferRequest, AlertResponse, PacketResponse,
    StatsResponse, SystemStatus, Alert, PacketInfo, SnifferConfig, MLModelConfig
)
from app.core.nids_orchestrator import NIDSOrchestrator
from app.utils.security import (
    verify_api_key, security_manager, input_validator, get_client_ip
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global NIDS orchestrator instance (will be set by main.py)
nids_orchestrator: Optional[NIDSOrchestrator] = None

def get_nids_orchestrator() -> NIDSOrchestrator:
    """Dependency to get NIDS orchestrator instance"""
    if nids_orchestrator is None:
        raise HTTPException(status_code=503, detail="NIDS system not initialized")
    return nids_orchestrator

async def log_api_access(request: Request, endpoint: str, user_token: str = None):
    """Log API access for audit trail"""
    client_ip = get_client_ip(request)
    
    security_manager.log_security_event(
        "api_access",
        {
            "endpoint": endpoint,
            "method": request.method,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "has_auth": bool(user_token)
        },
        client_ip
    )

@router.post("/start-sniffer", response_model=Dict[str, Any])
@limiter.limit("10/minute")
async def start_sniffer(
    request: Request,
    request_data: StartSnifferRequest,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator),
    token: str = Depends(verify_api_key)
):
    """Start packet sniffing and NIDS monitoring"""
    try:
        # Log API access
        await log_api_access(request, "start-sniffer", token)
        
        # Validate configuration if provided
        if request_data.config:
            # Validate interface name
            if hasattr(request_data.config, 'interface') and request_data.config.interface:
                if not input_validator.validate_interface_name(request_data.config.interface):
                    raise HTTPException(status_code=400, detail="Invalid interface name")
            
            success = orchestrator.update_sniffer_config(request_data.config)
            if not success:
                raise HTTPException(status_code=500, detail="Failed to update sniffer configuration")
        
        # Start the NIDS system
        success = orchestrator.start()
        if not success:
            # Wait a moment for any errors to be captured
            await asyncio.sleep(0.5)
            
            # Check for detailed error information
            detailed_stats = orchestrator.get_detailed_stats()
            sniffer_details = detailed_stats.get('component_details', {}).get('sniffer', {})
            last_error = sniffer_details.get('last_error')
            
            error_detail = "Failed to start NIDS system"
            if last_error:
                error_detail += f": {last_error}"
            
            raise HTTPException(status_code=500, detail=error_detail)
        
        # Log security event
        interface_name = getattr(request_data.config, 'interface', orchestrator.sniffer_config.interface) if request_data.config else orchestrator.sniffer_config.interface
        security_manager.log_security_event(
            "nids_started",
            {"interface": interface_name},
            get_client_ip(request)
        )
        
        # Wait a moment and check if sniffer is actually running
        await asyncio.sleep(0.5)
        system_status = orchestrator.get_system_status()
        detailed_stats = orchestrator.get_detailed_stats()
        sniffer_details = detailed_stats.get('component_details', {}).get('sniffer', {})
        
        if not system_status.is_running or not sniffer_details.get('is_running', False):
            # Sniffer failed after start attempt
            last_error = sniffer_details.get('last_error', 'Unknown error')
            raise HTTPException(
                status_code=500, 
                detail=f"Sniffer started but failed to run: {last_error}"
            )
        
        return {
            "status": "success",
            "message": "NIDS system started successfully",
            "system_status": system_status.model_dump(),
            "sniffer_info": {
                "interface": sniffer_details.get('interface'),
                "status": sniffer_details.get('status'),
                "is_running": sniffer_details.get('is_running')
            }
        }
        
    except Exception as e:
        logger.error(f"Error starting sniffer: {e}")
        security_manager.log_security_event(
            "nids_start_failed",
            {"error": str(e)},
            get_client_ip(request)
        )
        raise HTTPException(status_code=500, detail=f"Failed to start sniffer: {str(e)}")

@router.post("/stop-sniffer", response_model=Dict[str, Any])
@limiter.limit("10/minute")
async def stop_sniffer(
    request: Request,
    request_data: StopSnifferRequest,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator),
    token: str = Depends(verify_api_key)
):
    """Stop packet sniffing and NIDS monitoring"""
    try:
        success = orchestrator.stop()
        if not success:
            raise HTTPException(status_code=500, detail="Failed to stop NIDS system")
        
        return {
            "status": "success",
            "message": "NIDS system stopped successfully",
            "system_status": orchestrator.get_system_status().model_dump()
        }
        
    except Exception as e:
        logger.error(f"Error stopping sniffer: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stop sniffer: {str(e)}")

@router.get("/status", response_model=SystemStatus)
async def get_status(
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get current system status"""
    try:
        return orchestrator.get_system_status()
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get system status: {str(e)}")

@router.get("/alerts", response_model=AlertResponse)
@limiter.limit("100/minute")
async def get_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=1000, description="Number of alerts to return"),
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    detection_type: Optional[str] = Query(None, description="Filter by detection type"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator),
    token: str = Depends(verify_api_key)
):
    """Get alerts with optional filtering"""
    try:
        # Log API access
        await log_api_access(request, "get-alerts", token)
        
        # Validate inputs
        if severity and not input_validator.validate_severity(severity):
            raise HTTPException(status_code=400, detail="Invalid severity level")
        
        if source_ip and not input_validator.validate_ip_address(source_ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        # Build filters
        filters = {}
        if severity:
            filters['severity'] = severity
        if detection_type:
            filters['detection_type'] = input_validator.sanitize_string(detection_type, 50)
        if source_ip:
            filters['source_ip'] = source_ip
        if resolved is not None:
            filters['resolved'] = resolved
        
        alerts = orchestrator.get_alerts(limit=limit, **filters)
        
        return AlertResponse(
            alerts=alerts,
            total_count=len(alerts),
            page=1,
            page_size=limit
        )
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alerts: {str(e)}")

@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert_by_id(
    alert_id: str,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get a specific alert by ID"""
    try:
        alert = orchestrator.alert_manager.get_alert_by_id(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return alert
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert by ID: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alert: {str(e)}")

@router.post("/alerts/{alert_id}/resolve", response_model=Dict[str, Any])
async def resolve_alert(
    alert_id: str,
    resolution_notes: str = "",
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Resolve an alert"""
    try:
        success = orchestrator.resolve_alert(alert_id, resolution_notes)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {
            "status": "success",
            "message": f"Alert {alert_id} resolved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {str(e)}")

@router.delete("/alerts/{alert_id}", response_model=Dict[str, Any])
async def delete_alert(
    alert_id: str,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Delete an alert"""
    try:
        success = orchestrator.alert_manager.delete_alert(alert_id)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {
            "status": "success",
            "message": f"Alert {alert_id} deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete alert: {str(e)}")

@router.get("/packets", response_model=PacketResponse)
async def get_packets(
    limit: int = Query(100, ge=1, le=1000, description="Number of packets to return"),
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get recent captured packets"""
    try:
        packets = orchestrator.get_recent_packets(limit=limit)
        
        return PacketResponse(
            packets=packets,
            total_count=len(packets),
            page=1,
            page_size=limit
        )
        
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get packets: {str(e)}")

@router.get("/stats", response_model=Dict[str, Any])
async def get_stats(
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get detailed system statistics"""
    try:
        stats = orchestrator.get_detailed_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@router.get("/correlation", response_model=Dict[str, Any])
async def get_correlation_analysis(
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get alert correlation analysis"""
    try:
        correlation = orchestrator.get_correlation_analysis()
        return correlation
        
    except Exception as e:
        logger.error(f"Error getting correlation analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get correlation analysis: {str(e)}")

@router.get("/signature-rules", response_model=List[Dict[str, Any]])
async def get_signature_rules(
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Get signature rules list"""
    try:
        rules = []
        for rule in orchestrator.signature_detector.rules.values():
            rules.append({
                'id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity.value,
                'enabled': rule.enabled,
                'pattern': rule.pattern,
                'tags': rule.tags,
                'matches_count': rule.matches_count,
                'last_match': rule.last_match.isoformat() if rule.last_match else None,
                'metadata': rule.metadata
            })
        return rules
        
    except Exception as e:
        logger.error(f"Error getting signature rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get signature rules: {str(e)}")

@router.post("/signature-rules/{rule_id}/enable", response_model=Dict[str, Any])
async def enable_signature_rule(
    rule_id: str,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Enable a signature rule"""
    try:
        success = orchestrator.enable_signature_rule(rule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Signature rule not found")
        
        return {
            "status": "success",
            "message": f"Signature rule {rule_id} enabled successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error enabling signature rule: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to enable signature rule: {str(e)}")

@router.post("/signature-rules/{rule_id}/disable", response_model=Dict[str, Any])
async def disable_signature_rule(
    rule_id: str,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Disable a signature rule"""
    try:
        success = orchestrator.disable_signature_rule(rule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Signature rule not found")
        
        return {
            "status": "success",
            "message": f"Signature rule {rule_id} disabled successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disabling signature rule: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to disable signature rule: {str(e)}")

@router.post("/config/sniffer", response_model=Dict[str, Any])
async def update_sniffer_config(
    config: SnifferConfig,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Update sniffer configuration"""
    try:
        success = orchestrator.update_sniffer_config(config)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update sniffer configuration")
        
        return {
            "status": "success",
            "message": "Sniffer configuration updated successfully",
            "config": config.model_dump()
        }
        
    except Exception as e:
        logger.error(f"Error updating sniffer config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update sniffer config: {str(e)}")

@router.post("/config/ml", response_model=Dict[str, Any])
async def update_ml_config(
    config: MLModelConfig,
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Update ML model configuration"""
    try:
        success = orchestrator.update_ml_config(config)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update ML configuration")
        
        return {
            "status": "success",
            "message": "ML configuration updated successfully",
            "config": config.model_dump()
        }
        
    except Exception as e:
        logger.error(f"Error updating ML config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update ML config: {str(e)}")

@router.post("/alerts/clear", response_model=Dict[str, Any])
async def clear_alerts(
    older_than_days: Optional[int] = Query(None, description="Clear alerts older than specified days"),
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Clear alerts"""
    try:
        orchestrator.clear_alerts(older_than_days)
        
        message = "All alerts cleared successfully"
        if older_than_days:
            message = f"Alerts older than {older_than_days} days cleared successfully"
        
        return {
            "status": "success",
            "message": message
        }
        
    except Exception as e:
        logger.error(f"Error clearing alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear alerts: {str(e)}")

@router.get("/export/alerts", response_model=Dict[str, Any])
async def export_alerts(
    format: str = Query("json", description="Export format (json or csv)"),
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Export alerts"""
    try:
        if format.lower() not in ["json", "csv"]:
            raise HTTPException(status_code=400, detail="Invalid format. Use 'json' or 'csv'")
        
        exported_data = orchestrator.export_alerts(format=format)
        
        return {
            "status": "success",
            "format": format,
            "data": exported_data,
            "message": f"Alerts exported successfully in {format.upper()} format"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export alerts: {str(e)}")

@router.get("/health", response_model=Dict[str, Any])
async def health_check(
    orchestrator: NIDSOrchestrator = Depends(get_nids_orchestrator)
):
    """Health check endpoint with detailed diagnostics"""
    try:
        system_status = orchestrator.get_system_status()
        detailed_stats = orchestrator.get_detailed_stats()
        
        # Check component health
        component_health = detailed_stats.get('component_health', {})
        component_details = detailed_stats.get('component_details', {})
        all_healthy = all(component_health.values())
        
        # Get sniffer details for better diagnostics
        sniffer_details = component_details.get('sniffer', {})
        sniffer_status = sniffer_details.get('status', 'unknown')
        
        # Provide helpful messages based on sniffer status
        messages = []
        if not component_health.get('sniffer_healthy', False):
            if sniffer_status == 'not_started':
                messages.append("Sniffer is not started. Use POST /api/v1/start-sniffer to start it.")
            elif sniffer_status == 'failed':
                error_msg = sniffer_details.get('last_error', 'Unknown error')
                messages.append(f"Sniffer failed to start: {error_msg}")
                interface = sniffer_details.get('interface', 'unknown')
                messages.append(f"Configured interface: {interface}")
                if "Available interfaces" in error_msg:
                    messages.append("Check available interfaces from the error message above.")
            else:
                messages.append("Sniffer is stopped.")
        
        response = {
            "status": "healthy" if all_healthy else "degraded",
            "system_running": system_status.is_running,
            "component_health": component_health,
            "component_details": component_details,
            "uptime_seconds": system_status.uptime,
            "timestamp": system_status.uptime
        }
        
        if messages:
            response["messages"] = messages
        
        return response
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": 0
        } 