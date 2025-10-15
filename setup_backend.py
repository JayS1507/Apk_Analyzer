#!/usr/bin/env python3
"""
Setup script for APK Inspector Backend
This script helps set up the Python environment and install required tools
"""

import subprocess
import sys
import os
import platform
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"Running: {description}")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("✗ Python 3.8 or higher is required")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n=== Installing Python Dependencies ===")
    
    # Install requirements
    if not run_command("pip install -r backend/requirements.txt", "Installing Python packages"):
        return False
    
    return True

def install_analysis_tools():
    """Install APK analysis tools"""
    print("\n=== Installing Analysis Tools ===")
    
    system = platform.system().lower()
    
    if system == "windows":
        print("Windows detected. Please install the following tools manually:")
        print("1. Java JDK 8 or higher")
        print("2. apktool: Download from https://ibotpeaches.github.io/Apktool/")
        print("3. jadx: Download from https://github.com/skylot/jadx")
        print("\nAfter installation, make sure these tools are in your PATH")
        return True
    
    elif system == "darwin":  # macOS
        print("macOS detected. Installing tools with Homebrew...")
        
        # Install Java if not present
        run_command("brew install openjdk", "Installing Java")
        
        # Install apktool
        run_command("brew install apktool", "Installing apktool")
        
        # Install jadx
        run_command("brew install jadx", "Installing jadx")
        
    elif system == "linux":
        print("Linux detected. Installing tools...")
        
        # Install Java
        run_command("sudo apt-get update", "Updating package list")
        run_command("sudo apt-get install -y openjdk-11-jdk", "Installing Java")
        
        # Install apktool
        run_command("sudo apt-get install -y apktool", "Installing apktool")
        
        # Install jadx
        run_command("sudo apt-get install -y jadx", "Installing jadx")
    
    else:
        print(f"Unsupported system: {system}")
        print("Please install the following tools manually:")
        print("1. Java JDK 8 or higher")
        print("2. apktool")
        print("3. jadx")
        return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print("\n=== Creating Directories ===")
    
    directories = [
        "uploads",
        "output", 
        "reports",
        "backend/uploads",
        "backend/output",
        "backend/reports"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    return True

def verify_installation():
    """Verify that all tools are properly installed"""
    print("\n=== Verifying Installation ===")
    
    tools = {
        "apktool": "apktool --version",
        "jadx": "jadx --version",
        "java": "java -version"
    }
    
    all_good = True
    for tool, command in tools.items():
        if run_command(command, f"Checking {tool}"):
            print(f"✓ {tool} is available")
        else:
            print(f"✗ {tool} is not available")
            all_good = False
    
    # Check Python packages
    try:
        import fastapi
        import uvicorn
        import androguard
        print("✓ Python packages are installed")
    except ImportError as e:
        print(f"✗ Python packages missing: {e}")
        all_good = False
    
    return all_good

def main():
    """Main setup function"""
    print("APK Inspector Backend Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("Failed to create directories")
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("Failed to install Python dependencies")
        sys.exit(1)
    
    # Install analysis tools
    if not install_analysis_tools():
        print("Failed to install analysis tools")
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        print("\n⚠️  Some tools may not be properly installed.")
        print("Please check the installation and try again.")
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("✓ Setup completed successfully!")
    print("\nTo start the backend server, run:")
    print("cd backend && python main.py")
    print("\nThe API will be available at: http://localhost:8000")

if __name__ == "__main__":
    main()

