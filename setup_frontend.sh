#!/bin/bash

# Setup script for APK Inspector Frontend
# This script sets up the React frontend

echo "APK Inspector Frontend Setup"
echo "============================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "✗ Node.js is not installed"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 14 ]; then
    echo "✗ Node.js version 14 or higher is required"
    echo "Current version: $(node -v)"
    exit 1
fi

echo "✓ Node.js $(node -v) is compatible"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "✗ npm is not installed"
    exit 1
fi

echo "✓ npm $(npm -v) is available"

# Navigate to frontend directory
cd frontend

# Install dependencies
echo ""
echo "Installing dependencies..."
if npm install; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi

echo ""
echo "============================"
echo "✓ Frontend setup completed successfully!"
echo ""
echo "To start the frontend development server, run:"
echo "cd frontend && npm start"
echo ""
echo "The frontend will be available at: http://localhost:3000"

