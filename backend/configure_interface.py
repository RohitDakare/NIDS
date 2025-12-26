#!/usr/bin/env python3
"""
Network Interface Configuration Helper

This script helps you configure the correct network interface for the NIDS system.
"""

import os
import psutil
from pathlib import Path

def get_network_interfaces():
    """Get available network interfaces"""
    interfaces = []
    for interface, addresses in psutil.net_if_addrs().items():
        if addresses:  # Only include interfaces with addresses
            interfaces.append(interface)
    return interfaces

def update_env_file(interface):
    """Update the .env file with the selected interface"""
    env_file = Path(".env")
    
    if not env_file.exists():
        print("❌ .env file not found. Please run setup.py first.")
        return False
    
    # Read current content
    with open(env_file, 'r') as f:
        content = f.read()
    
    # Update interface setting
    lines = content.split('\n')
    updated_lines = []
    
    for line in lines:
        if line.startswith('INTERFACE='):
            updated_lines.append(f'INTERFACE={interface}')
        else:
            updated_lines.append(line)
    
    # Write updated content
    with open(env_file, 'w') as f:
        f.write('\n'.join(updated_lines))
    
    return True

def main():
    """Main configuration function"""
    print("🛡️  NIDS Network Interface Configuration")
    print("=" * 50)
    
    # Get available interfaces
    interfaces = get_network_interfaces()
    
    if not interfaces:
        print("❌ No network interfaces found!")
        return
    
    print(f"✅ Found {len(interfaces)} network interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"   {i}. {interface}")
    
    print("\n📋 Interface Recommendations:")
    print("   - 'Ethernet' or 'Wi-Fi' for real network monitoring")
    print("   - 'Loopback Pseudo-Interface 1' for testing (localhost only)")
    print("   - 'VMware Network Adapter' for virtual machine traffic")
    
    # Check current configuration
    env_file = Path(".env")
    current_interface = "Ethernet"  # Default
    
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if line.startswith('INTERFACE='):
                    current_interface = line.split('=')[1].strip()
                    break
    
    print(f"\n🔧 Current configuration: INTERFACE={current_interface}")
    
    # Ask user for selection
    while True:
        try:
            choice = input(f"\nSelect interface (1-{len(interfaces)}) or press Enter to keep current: ").strip()
            
            if not choice:  # Keep current
                print(f"✅ Keeping current interface: {current_interface}")
                return
            
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(interfaces):
                selected_interface = interfaces[choice_idx]
                break
            else:
                print("❌ Invalid selection. Please try again.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    # Update configuration
    if update_env_file(selected_interface):
        print(f"✅ Updated configuration: INTERFACE={selected_interface}")
        print("\n📝 Next steps:")
        print("   1. Restart the NIDS application: python run.py")
        print("   2. Test the interface: python demo.py")
    else:
        print("❌ Failed to update configuration")

if __name__ == "__main__":
    main() 