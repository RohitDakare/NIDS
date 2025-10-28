#!/usr/bin/env python3
"""
Test NIDS system with various attack scenarios
"""

import sys
import os
import time
import threading
import requests
from datetime import datetime

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.nids_orchestrator import NIDSOrchestrator
from app.models.schemas import SnifferConfig, MLModelConfig
from generate_attack_traffic import AttackTrafficGenerator

class NIDSAttackTester:
    """Test NIDS system with various attack scenarios"""
    
    def __init__(self):
        self.nids_orchestrator = None
        self.attack_generator = None
        self.test_results = []
        
    def setup_nids(self):
        """Setup NIDS system for testing"""
        print("Setting up NIDS system...")
        
        # Create configurations
        sniffer_config = SnifferConfig(
            interface="Wi-Fi",
            packet_count=1000,  # Capture more packets for testing
            timeout=60
        )
        
        ml_config = MLModelConfig(
            model_path="app/ml_models/nids_model.joblib",
            confidence_threshold=0.7  # Lower threshold for testing
        )
        
        # Create orchestrator
        self.nids_orchestrator = NIDSOrchestrator(
            sniffer_config=sniffer_config,
            ml_config=ml_config
        )
        
        # Start NIDS system
        success = self.nids_orchestrator.start()
        if success:
            print("NIDS system started successfully!")
            return True
        else:
            print("Failed to start NIDS system!")
            return False
    
    def run_attack_test(self, attack_type, duration=30):
        """Run a specific attack test"""
        print(f"\n{'='*60}")
        print(f"Running {attack_type} attack test for {duration} seconds")
        print(f"{'='*60}")
        
        # Record initial stats
        initial_stats = self.nids_orchestrator.get_system_status()
        initial_packets = initial_stats.packets_captured
        initial_alerts = initial_stats.alerts_generated
        
        print(f"Initial packets: {initial_packets}")
        print(f"Initial alerts: {initial_alerts}")
        
        # Start attack generator
        self.attack_generator = AttackTrafficGenerator()
        
        # Start attack in separate thread
        attack_thread = threading.Thread(
            target=self.attack_generator.start_attack,
            args=(attack_type, duration)
        )
        attack_thread.daemon = True
        attack_thread.start()
        
        # Monitor NIDS during attack
        start_time = time.time()
        while time.time() - start_time < duration + 5:  # Extra 5 seconds for processing
            time.sleep(2)
            
            # Get current stats
            current_stats = self.nids_orchestrator.get_system_status()
            current_packets = current_stats.packets_captured
            current_alerts = current_stats.alerts_generated
            
            print(f"Time: {int(time.time() - start_time)}s - Packets: {current_packets} - Alerts: {current_alerts}")
            
            # Check if attack is still running
            if not self.attack_generator.running and time.time() - start_time > duration:
                break
        
        # Record final stats
        final_stats = self.nids_orchestrator.get_system_status()
        final_packets = final_stats.packets_captured
        final_alerts = final_stats.alerts_generated
        
        # Calculate results
        packets_captured = final_packets - initial_packets
        alerts_generated = final_alerts - initial_alerts
        
        # Get recent alerts
        recent_alerts = self.nids_orchestrator.get_alerts(limit=10)
        
        # Store test results
        test_result = {
            'attack_type': attack_type,
            'duration': duration,
            'packets_captured': packets_captured,
            'alerts_generated': alerts_generated,
            'detection_rate': alerts_generated / max(packets_captured, 1),
            'timestamp': datetime.now().isoformat(),
            'recent_alerts': len(recent_alerts)
        }
        
        self.test_results.append(test_result)
        
        # Print results
        print(f"\n{attack_type.upper()} ATTACK TEST RESULTS:")
        print(f"Packets captured: {packets_captured}")
        print(f"Alerts generated: {alerts_generated}")
        print(f"Detection rate: {test_result['detection_rate']:.2%}")
        print(f"Recent alerts: {len(recent_alerts)}")
        
        # Show sample alerts
        if recent_alerts:
            print(f"\nSample alerts:")
            for i, alert in enumerate(recent_alerts[:3], 1):
                print(f"  {i}. {alert.detection_type} - {alert.severity} - {alert.description}")
        
        return test_result
    
    def run_all_tests(self):
        """Run all attack tests"""
        print("NIDS Attack Testing Suite")
        print("=" * 60)
        
        # Setup NIDS
        if not self.setup_nids():
            return False
        
        # Define test scenarios
        test_scenarios = [
            ("ddos", 30),
            ("port_scan", 20),
            ("brute_force", 25),
            ("syn_flood", 20),
            ("icmp_flood", 15),
            ("slowloris", 20)
        ]
        
        print(f"\nRunning {len(test_scenarios)} test scenarios...")
        
        # Run each test
        for attack_type, duration in test_scenarios:
            try:
                self.run_attack_test(attack_type, duration)
                time.sleep(5)  # Wait between tests
            except Exception as e:
                print(f"Error in {attack_type} test: {e}")
                continue
        
        # Print summary
        self.print_test_summary()
        
        return True
    
    def print_test_summary(self):
        """Print summary of all test results"""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")
        
        if not self.test_results:
            print("No test results available.")
            return
        
        total_packets = sum(result['packets_captured'] for result in self.test_results)
        total_alerts = sum(result['alerts_generated'] for result in self.test_results)
        overall_detection_rate = total_alerts / max(total_packets, 1)
        
        print(f"Total packets captured: {total_packets}")
        print(f"Total alerts generated: {total_alerts}")
        print(f"Overall detection rate: {overall_detection_rate:.2%}")
        print(f"Tests completed: {len(self.test_results)}")
        
        print(f"\nIndividual Test Results:")
        print(f"{'Attack Type':<15} {'Duration':<8} {'Packets':<8} {'Alerts':<8} {'Rate':<8}")
        print(f"{'-'*60}")
        
        for result in self.test_results:
            print(f"{result['attack_type']:<15} {result['duration']:<8} {result['packets_captured']:<8} {result['alerts_generated']:<8} {result['detection_rate']:<8.2%}")
    
    def cleanup(self):
        """Cleanup resources"""
        if self.nids_orchestrator:
            print("\nStopping NIDS system...")
            self.nids_orchestrator.stop()
        
        if self.attack_generator:
            self.attack_generator.stop_attack()

def main():
    """Main function"""
    tester = NIDSAttackTester()
    
    try:
        # Run all tests
        success = tester.run_all_tests()
        
        if success:
            print("\nAll tests completed successfully!")
        else:
            print("\nSome tests failed!")
    
    except KeyboardInterrupt:
        print("\nTesting interrupted by user")
    except Exception as e:
        print(f"Error during testing: {e}")
    finally:
        tester.cleanup()

if __name__ == "__main__":
    main()
