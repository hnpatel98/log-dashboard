# Single-stage Dockerfile for Log Dashboard Application
# Compatible with Render and other cloud platforms

FROM python:3.11-slim

# Install system dependencies and Node.js
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy backend requirements and install Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt watchdog

# Copy backend source code
COPY backend/ ./backend/

# Copy frontend package files and install dependencies
COPY frontend/package*.json ./frontend/
WORKDIR /app/frontend
RUN npm ci

# Copy frontend source code and build
COPY frontend/ ./
RUN npm run build

# Return to app directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p backend/uploads backend/data

# Set environment variables
ENV FLASK_APP=backend/app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV NODE_ENV=production

# Copy startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Expose ports
EXPOSE 5001 3000

# Start both services
CMD ["/app/start.sh"] 