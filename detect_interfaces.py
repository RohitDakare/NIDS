import subprocess
import json
import re

def get_windows_interfaces():
    """Get Windows network interfaces using netsh"""
    try:
        # Get network interfaces using netsh
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                              capture_output=True, text=True, check=True)
        
        print("=== Windows Network Interfaces ===")
        print(result.stdout)
        
        # Parse the output to find active interfaces
        lines = result.stdout.split('\n')
        interfaces = []
        
        for line in lines:
            if 'Connected' in line and 'Dedicated' in line:
                # Extract interface name (last part of the line)
                parts = line.split()
                if len(parts) >= 4:
                    interface_name = ' '.join(parts[3:])
                    interfaces.append(interface_name)
                    print(f"✅ Found active interface: {interface_name}")
        
        return interfaces
        
    except subprocess.CalledProcessError as e:
        print(f"Error getting interfaces: {e}")
        return []

def get_scapy_interfaces():
    """Get interfaces that Scapy can see"""
    try:
        from scapy.all import get_if_list, get_if_addr
        
        print("\n=== Scapy Available Interfaces ===")
        interfaces = get_if_list()
        
        for iface in interfaces:
            try:
                addr = get_if_addr(iface)
                print(f"✅ {iface} - IP: {addr}")
            except:
                print(f"⚠️  {iface} - No IP address")
        
        return interfaces
        
    except ImportError:
        print("Scapy not available")
        return []

if __name__ == "__main__":
    print("🔍 Detecting Network Interfaces for NIDS...")
    
    # Get Windows interfaces
    win_interfaces = get_windows_interfaces()
    
    # Get Scapy interfaces
    scapy_interfaces = get_scapy_interfaces()
    
    print("\n=== Recommendations ===")
    
    if scapy_interfaces:
        # Recommend the first non-loopback interface
        recommended = None
        for iface in scapy_interfaces:
            if 'loopback' not in iface.lower() and 'localhost' not in iface.lower():
                recommended = iface
                break
        
        if not recommended and scapy_interfaces:
            recommended = scapy_interfaces[0]  # Fallback to first interface
            
        if recommended:
            print(f"🎯 Recommended interface for NIDS: {recommended}")
            
            # Create environment variable suggestion
            print(f"\n📝 To configure NIDS, set environment variable:")
            print(f'INTERFACE="{recommended}"')
            
            # Update .env file
            try:
                with open('.env', 'r') as f:
                    env_content = f.read()
                
                # Update or add INTERFACE line
                if 'INTERFACE=' in env_content:
                    env_content = re.sub(r'INTERFACE=.*', f'INTERFACE="{recommended}"', env_content)
                else:
                    env_content += f'\nINTERFACE="{recommended}"\n'
                
                with open('.env', 'w') as f:
                    f.write(env_content)
                
                print(f"✅ Updated .env file with INTERFACE={recommended}")
                
            except Exception as e:
                print(f"⚠️  Could not update .env file: {e}")
    
    else:
        print("❌ No suitable interfaces found for packet capture")
        print("💡 You may need to install WinPcap or Npcap for packet capture")
