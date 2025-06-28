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

# Copy entire project context first
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt watchdog

# Install frontend dependencies and build
WORKDIR /app/frontend
RUN npm ci
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

# Copy startup script and make it executable
RUN chmod +x start.sh

# Expose ports
EXPOSE 5001 3000

# Start both services
CMD ["./start.sh"] 