# Development stage
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code (will be overridden by volume mount in development)
COPY . .

# Expose port
EXPOSE 3000

# Set environment variable
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Start the application in development mode
CMD ["npm", "run", "dev"] 