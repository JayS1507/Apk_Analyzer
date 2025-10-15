#!/usr/bin/env python3
"""
Test script for APK Inspector installation
This script tests all components of the APK Inspector application
"""

import subprocess
import sys
import time
import requests
import json
from pathlib import Path

def test_python_imports():
    """Test if all required Python packages can be imported"""
    print("Testing Python imports...")
    
    try:
        import fastapi
        print("✓ FastAPI imported successfully")
    except ImportError as e:
        print(f"✗ FastAPI import failed: {e}")
        return False
    
    try:
        import uvicorn
        print("✓ Uvicorn imported successfully")
    except ImportError as e:
        print(f"✗ Uvicorn import failed: {e}")
        return False
    
    try:
        import androguard
        print("✓ Androguard imported successfully")
    except ImportError as e:
        print(f"✗ Androguard import failed: {e}")
        return False
    
    try:
        import reportlab
        print("✓ ReportLab imported successfully")
    except ImportError as e:
        print(f"✗ ReportLab import failed: {e}")
        return False
    
    try:
        import jinja2
        print("✓ Jinja2 imported successfully")
    except ImportError as e:
        print(f"✗ Jinja2 import failed: {e}")
        return False
    
    return True

def test_analysis_tools():
    """Test if analysis tools are available (prefer bundled tools)"""
    print("\nTesting analysis tools...")
    project_root = Path(__file__).resolve().parent

    # Test Java
    try:
        result = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Java is available")
        else:
            print("✗ Java is not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("✗ Java is not installed or not in PATH")
        return False

    # Prefer bundled apktool.jar
    apktool_jar = project_root / 'tools' / 'apktool.jar'
    if apktool_jar.exists():
        try:
            result = subprocess.run(['java', '-jar', str(apktool_jar), '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ apktool (bundled jar) is available")
            else:
                print("✗ apktool (bundled jar) is not working properly")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"✗ apktool (bundled jar) failed: {e}")
            return False
    else:
        # Fallback to system apktool
        try:
            result = subprocess.run(['apktool', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ apktool is available")
            else:
                print("✗ apktool is not working properly")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("✗ apktool is not installed or not in PATH")
            return False

    # Prefer bundled jadx.bat
    jadx_bat = project_root / 'tools' / 'bin' / 'jadx.bat'
    if jadx_bat.exists():
        try:
            result = subprocess.run([str(jadx_bat), '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ jadx (bundled) is available")
            else:
                print("✗ jadx (bundled) is not working properly")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"✗ jadx (bundled) failed: {e}")
            return False
    else:
        # Fallback to system jadx
        try:
            result = subprocess.run(['jadx', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ jadx is available")
            else:
                print("✗ jadx is not working properly")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("✗ jadx is not installed or not in PATH")
            return False

    return True

def test_backend_api():
    """Test if backend API is running"""
    print("\nTesting backend API...")
    
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        if response.status_code == 200:
            print("✓ Backend API is running")
            return True
        else:
            print(f"✗ Backend API returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ Backend API is not running")
        return False
    except Exception as e:
        print(f"✗ Backend API test failed: {e}")
        return False

def test_frontend():
    """Test if frontend is running"""
    print("\nTesting frontend...")
    
    try:
        response = requests.get("http://localhost:3000/", timeout=5)
        if response.status_code == 200:
            print("✓ Frontend is running")
            return True
        else:
            print(f"✗ Frontend returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ Frontend is not running")
        return False
    except Exception as e:
        print(f"✗ Frontend test failed: {e}")
        return False

def test_apk_analysis():
    """Test APK analysis functionality"""
    print("\nTesting APK analysis...")
    
    # Create a simple test APK (this would normally be a real APK file)
    # For now, we'll just test the analysis module import
    try:
        sys.path.append('backend')
        from apk_analyzer import APKAnalyzer
        
        analyzer = APKAnalyzer()
        tools_available = analyzer._check_tools()
        
        print(f"Available tools: {tools_available}")
        
        if any(tools_available.values()):
            print("✓ APK analyzer can detect tools")
            return True
        else:
            print("✗ No analysis tools detected")
            return False
            
    except Exception as e:
        print(f"✗ APK analysis test failed: {e}")
        return False

def test_report_generation():
    """Test report generation functionality"""
    print("\nTesting report generation...")
    
    try:
        sys.path.append('backend')
        from report_generator import ReportGenerator
        
        report_gen = ReportGenerator()
        
        # Test with sample data
        sample_data = {
            "package_name": "com.test.app",
            "version_name": "1.0.0",
            "permissions": ["android.permission.INTERNET"],
            "activities": ["MainActivity"],
            "urls_found": [],
            "ips_found": [],
            "suspicious_strings": [],
            "certificates": [],
            "file_size": 1000000,
            "analysis_tools_used": ["apktool"]
        }
        
        # Test HTML report generation
        import asyncio
        report_path = asyncio.run(report_gen.generate_html_report(sample_data, "test"))
        if Path(report_path).exists():
            print("✓ HTML report generation works")
            Path(report_path).unlink()  # Clean up
        else:
            print("✗ HTML report generation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Report generation test failed: {e}")
        return False

def main():
    """Main test function"""
    print("APK Inspector - Installation Test")
    print("=" * 40)
    
    all_tests_passed = True
    
    # Test Python imports
    if not test_python_imports():
        all_tests_passed = False
    
    # Test analysis tools
    if not test_analysis_tools():
        all_tests_passed = False
    
    # Test backend API
    if not test_backend_api():
        print("Note: Start backend with: cd backend && python main.py")
        all_tests_passed = False
    
    # Test frontend
    if not test_frontend():
        print("Note: Start frontend with: cd frontend && npm start")
        all_tests_passed = False
    
    # Test APK analysis
    if not test_apk_analysis():
        all_tests_passed = False
    
    # Test report generation
    if not test_report_generation():
        all_tests_passed = False
    
    print("\n" + "=" * 40)
    if all_tests_passed:
        print("✓ All tests passed! APK Inspector is ready to use.")
        print("\nTo start the application:")
        print("1. Backend: cd backend && python main.py")
        print("2. Frontend: cd frontend && npm start")
        print("3. Open: http://localhost:3000")
    else:
        print("✗ Some tests failed. Please check the installation.")
    
    return all_tests_passed

if __name__ == "__main__":
    main()
