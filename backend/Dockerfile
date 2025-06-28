FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt watchdog

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p uploads data

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5001

# Run the application with watchmedo for auto-reload
CMD ["watchmedo", "auto-restart", "--directory=.", "--pattern=*.py", "--recursive", "--", "flask", "run", "--host=0.0.0.0", "--port=5001"]

# Temporary: Run without watchmedo for debugging
# CMD ["flask", "run", "--host=0.0.0.0", "--port=5001", "--debug"] 