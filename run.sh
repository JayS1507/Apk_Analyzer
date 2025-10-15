#!/bin/bash

echo "APK Inspector - Starting Application"
echo "===================================="

echo "Starting Backend Server..."
cd backend
python main.py &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

echo "Starting Frontend Server..."
cd ../frontend
npm start &
FRONTEND_PID=$!

echo ""
echo "Both servers are starting..."
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both servers"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM

# Wait for user to stop
wait

