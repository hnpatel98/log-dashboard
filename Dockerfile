# Multi-stage Dockerfile for Log Dashboard Application
# Builds both backend (Flask) and frontend (Next.js) in one container

# ========================================
# STAGE 1: Backend Build
# ========================================
FROM python:3.11-slim AS backend-builder

WORKDIR /app/backend

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt watchdog

# Copy backend source code
COPY backend/ .

# Create necessary directories
RUN mkdir -p uploads data

# ========================================
# STAGE 2: Frontend Build
# ========================================
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend package files
COPY frontend/package*.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source code
COPY frontend/ .

# Build the frontend for production
RUN npm run build

# ========================================
# STAGE 3: Production Runtime
# ========================================
FROM python:3.11-slim AS production

# Install system dependencies and Node.js
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python dependencies from backend stage
COPY --from=backend-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=backend-builder /usr/local/bin /usr/local/bin

# Copy backend application
COPY --from=backend-builder /app/backend ./backend

# Copy built frontend from frontend stage
COPY --from=frontend-builder /app/frontend/.next ./frontend/.next
COPY --from=frontend-builder /app/frontend/public ./frontend/public
COPY --from=frontend-builder /app/frontend/package*.json ./frontend/

# Install only production frontend dependencies
WORKDIR /app/frontend
RUN npm ci --only=production

# Create necessary directories
WORKDIR /app
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