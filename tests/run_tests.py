#!/usr/bin/env python3
"""
Test runner script for NIDS system
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed with exit code {e.returncode}")
        print("STDOUT:", e.stdout)
        print("STDERR:", e.stderr)
        return False

def run_unit_tests():
    """Run unit tests"""
    return run_command(
        "python -m pytest tests/unit/ -v --tb=short",
        "Running Unit Tests"
    )

def run_integration_tests():
    """Run integration tests"""
    return run_command(
        "python -m pytest tests/integration/ -v --tb=short",
        "Running Integration Tests"
    )

def run_e2e_tests():
    """Run end-to-end tests"""
    return run_command(
        "python -m pytest tests/e2e/ -v --tb=short",
        "Running End-to-End Tests"
    )

def run_all_tests():
    """Run all tests"""
    return run_command(
        "python -m pytest tests/ -v --tb=short",
        "Running All Tests"
    )

def run_tests_with_coverage():
    """Run tests with coverage report"""
    return run_command(
        "python -m pytest tests/ --cov=app --cov-report=html --cov-report=term-missing -v",
        "Running Tests with Coverage"
    )

def run_specific_test(test_path):
    """Run a specific test file or test function"""
    return run_command(
        f"python -m pytest {test_path} -v --tb=short",
        f"Running Specific Test: {test_path}"
    )

def run_performance_tests():
    """Run performance tests"""
    return run_command(
        "python -m pytest tests/ -m slow -v --tb=short",
        "Running Performance Tests"
    )

def lint_code():
    """Run code linting"""
    return run_command(
        "python -m flake8 app/ tests/ --max-line-length=100 --ignore=E203,W503",
        "Running Code Linting"
    )

def format_code():
    """Format code"""
    return run_command(
        "python -m black app/ tests/ --line-length=100",
        "Formatting Code"
    )

def check_imports():
    """Check for unused imports"""
    return run_command(
        "python -m autoflake --check --recursive app/ tests/",
        "Checking for Unused Imports"
    )

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description="NIDS Test Runner")
    parser.add_argument(
        "test_type",
        choices=[
            "unit", "integration", "e2e", "all", "coverage", 
            "performance", "lint", "format", "imports", "specific"
        ],
        help="Type of tests to run"
    )
    parser.add_argument(
        "--test-path",
        help="Specific test path (for 'specific' test type)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    print("🛡️  NIDS Test Runner")
    print("=" * 60)
    
    # Change to project root directory
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    success = True
    
    if args.test_type == "unit":
        success = run_unit_tests()
    elif args.test_type == "integration":
        success = run_integration_tests()
    elif args.test_type == "e2e":
        success = run_e2e_tests()
    elif args.test_type == "all":
        success = run_all_tests()
    elif args.test_type == "coverage":
        success = run_tests_with_coverage()
    elif args.test_type == "performance":
        success = run_performance_tests()
    elif args.test_type == "lint":
        success = lint_code()
    elif args.test_type == "format":
        success = format_code()
    elif args.test_type == "imports":
        success = check_imports()
    elif args.test_type == "specific":
        if not args.test_path:
            print("❌ --test-path is required for 'specific' test type")
            sys.exit(1)
        success = run_specific_test(args.test_path)
    
    if success:
        print(f"\n✅ {args.test_type.title()} tests completed successfully!")
    else:
        print(f"\n❌ {args.test_type.title()} tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
