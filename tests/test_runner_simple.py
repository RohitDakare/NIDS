#!/usr/bin/env python3
"""
Simple test runner to verify the test setup
"""

import sys
import subprocess
from pathlib import Path

def run_simple_test():
    """Run a simple test to verify setup"""
    print("🧪 Running Simple Test Verification")
    print("=" * 50)
    
    try:
        # Test 1: Check if pytest is available
        print("1. Checking pytest availability...")
        result = subprocess.run([sys.executable, "-m", "pytest", "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ pytest is available")
            print(f"   Version: {result.stdout.strip()}")
        else:
            print("   ❌ pytest is not available")
            return False
        
        # Test 2: Check test discovery
        print("\n2. Checking test discovery...")
        result = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ Tests can be discovered")
            # Count tests
            test_count = result.stdout.count("test session starts")
            print(f"   Found test files")
        else:
            print("   ❌ Test discovery failed")
            print(f"   Error: {result.stderr}")
            return False
        
        # Test 3: Run a simple unit test
        print("\n3. Running a simple unit test...")
        result = subprocess.run([sys.executable, "-m", "pytest", 
                               "tests/unit/test_ml_detector.py::TestMLDetector::test_initialization", 
                               "-v"], capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✅ Unit test passed")
        else:
            print("   ❌ Unit test failed")
            print(f"   Error: {result.stderr}")
            return False
        
        # Test 4: Check test structure
        print("\n4. Checking test structure...")
        test_dirs = ["unit", "integration", "e2e", "fixtures", "mocks"]
        for test_dir in test_dirs:
            dir_path = Path(f"tests/{test_dir}")
            if dir_path.exists():
                print(f"   ✅ {test_dir}/ directory exists")
            else:
                print(f"   ❌ {test_dir}/ directory missing")
                return False
        
        print("\n🎉 All tests passed! Test setup is working correctly.")
        return True
        
    except Exception as e:
        print(f"❌ Error during test verification: {e}")
        return False

def main():
    """Main function"""
    # Change to project root
    project_root = Path(__file__).parent.parent
    import os
    os.chdir(project_root)
    
    success = run_simple_test()
    
    if not success:
        print("\n💡 Troubleshooting tips:")
        print("   1. Make sure you're in the project root directory")
        print("   2. Install test dependencies: pip install -r requirements-test.txt")
        print("   3. Check that all test files are present")
        print("   4. Verify Python path includes the project root")
        sys.exit(1)

if __name__ == "__main__":
    main()
