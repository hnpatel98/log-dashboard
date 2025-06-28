#!/usr/bin/env python3
"""
Log Dashboard Backend Startup Script
"""

import os
import sys
from app import app
from config import config

def main():
    """Main application entry point"""
    
    # Get configuration from environment
    config_name = os.environ.get('FLASK_CONFIG', 'development')
    
    if config_name not in config:
        print(f"Error: Unknown configuration '{config_name}'")
        print(f"Available configurations: {', '.join(config.keys())}")
        sys.exit(1)
    
    # Initialize application with configuration
    config[config_name].init_app(app)
    
    # Get server settings
    host = config[config_name].HOST
    port = config[config_name].PORT
    debug = config[config_name].DEBUG
    
    print(f"Starting Log Dashboard Backend...")
    print(f"Configuration: {config_name}")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug: {debug}")
    print(f"Upload folder: {config[config_name].UPLOAD_FOLDER}")
    print(f"Data folder: {config[config_name].DATA_FOLDER}")
    print("-" * 50)
    
    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nShutting down Log Dashboard Backend...")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 