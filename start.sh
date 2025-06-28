#!/bin/bash

# Clean uploads and data folders on container startup
rm -rf /app/backend/uploads/*
rm -rf /app/backend/data/*

# Startup script for Log Dashboard Application
# Runs both backend (Flask) and frontend (Next.js) services

set -e

echo "🚀 Starting Log Dashboard Application..."

# Function to handle shutdown
cleanup() {
    echo "🛑 Shutting down services..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Start backend service
echo "🔧 Starting Flask backend..."
cd /app/backend
python -m flask run --host=0.0.0.0 --port=5001 &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 3

# Start frontend service
echo "🎨 Starting Next.js frontend..."
cd /app/frontend
npm start &
FRONTEND_PID=$!

echo "✅ Both services started successfully!"
echo "📊 Backend API: http://localhost:5001"
echo "🌐 Frontend: http://localhost:3000"

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID 