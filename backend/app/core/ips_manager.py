import logging
import subprocess
import platform
import threading
from typing import Dict, Set, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class IPSManager:
    """
    Intrusion Prevention System (IPS) Manager.
    
    Responsible for taking active preventive measures against detected threats,
    primarily by integrating with the system firewall to block malicious IPs.
    """
    
    def __init__(self, whitelist: Optional[Set[str]] = None, auto_block: bool = False):
        self.whitelist = whitelist or {"127.0.0.1", "localhost", "0.0.0.0"}
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> Expiration Time (None for permanent)
        self.lock = threading.Lock()
        self.auto_block = auto_block
        self.os_type = platform.system().lower()
        
    def block_ip(self, ip_address: str, duration_minutes: int = 60, reason: str = "Malicious activity detected") -> bool:
        """
        Block an IP address using the system firewall.
        
        Args:
            ip_address: The IP address to block.
            duration_minutes: Duration to block in minutes (default 60).
            reason: Reason for blocking.
            
        Returns:
            bool: True if blocking was successful/simulated, False otherwise.
        """
        if ip_address in self.whitelist:
            logger.warning(f"IPS: Attempted to block whitelisted IP {ip_address}. Action skipped.")
            return False
            
        with self.lock:
            if ip_address in self.blocked_ips:
                logger.debug(f"IPS: IP {ip_address} is already blocked.")
                return True
                
            expiration = datetime.now() + timedelta(minutes=duration_minutes)
            
            if self._execute_block_command(ip_address):
                self.blocked_ips[ip_address] = expiration
                logger.info(f"IPS: Blocked IP {ip_address} until {expiration} (Reason: {reason})")
                return True
            else:
                return False

    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip_address: The IP address to unblock.
            
        Returns:
            bool: True if unblocking was successful, False otherwise.
        """
        with self.lock:
            if ip_address not in self.blocked_ips:
                return False
                
            if self._execute_unblock_command(ip_address):
                del self.blocked_ips[ip_address]
                logger.info(f"IPS: Unblocked IP {ip_address}")
                return True
            else:
                return False

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked."""
        with self.lock:
            return ip_address in self.blocked_ips

    def cleanup_expired_blocks(self):
        """Remove expired IP blocks."""
        now = datetime.now()
        expired_ips = []
        
        with self.lock:
            for ip, expiration in self.blocked_ips.items():
                if expiration and now > expiration:
                    expired_ips.append(ip)
        
        for ip in expired_ips:
            try:
                self.unblock_ip(ip)
            except Exception as e:
                logger.error(f"IPS: Failed to cleanup expired block for {ip}: {e}")

    def _execute_block_command(self, ip_address: str) -> bool:
        """Execute the OS-specific command to block an IP."""
        try:
            if self.os_type == 'windows':
                # Windows Firewall (netsh)
                # Rule name convention: NIDS_Block_<IP>
                rule_name = f"NIDS_Block_{ip_address}"
                cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
                logger.info(f"IPS Executing: {cmd}")
                # subprocess.run(cmd, shell=True, check=True) # Commented out for safety/demonstration
                return True # Return True to simulate success
                
            elif self.os_type == 'linux':
                # IPTables or UFW
                cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
                logger.info(f"IPS Executing: {cmd}")
                # subprocess.run(cmd.split(), check=True)
                return True
                
            else:
                logger.warning(f"IPS: Unsupported OS {self.os_type} for automatic blocking.")
                return False
                
        except Exception as e:
            logger.error(f"IPS: System command failed for blocking {ip_address}: {e}")
            return False

    def _execute_unblock_command(self, ip_address: str) -> bool:
        """Execute the OS-specific command to unblock an IP."""
        try:
            if self.os_type == 'windows':
                rule_name = f"NIDS_Block_{ip_address}"
                cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
                logger.info(f"IPS Executing: {cmd}")
                # subprocess.run(cmd, shell=True, check=True)
                return True
            elif self.os_type == 'linux':
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
                logger.info(f"IPS Executing: {cmd}")
                # subprocess.run(cmd.split(), check=True)
                return True
            return False
        except Exception as e:
            logger.error(f"IPS: System command failed for unblocking {ip_address}: {e}")
            return False
