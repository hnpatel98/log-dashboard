import os
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class SecureConfig:
    def __init__(self):
        # Get encryption key from environment or generate one
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        if not self.encryption_key:
            # Generate a new key if none exists
            self.encryption_key = Fernet.generate_key().decode()
            print(f"Generated new encryption key: {self.encryption_key}")
            print("Please save this key securely and set it as ENCRYPTION_KEY environment variable")
        
        self.cipher = Fernet(self.encryption_key.encode())
    
    def encrypt(self, text):
        """Encrypt sensitive data"""
        if not text:
            return None
        return self.cipher.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted_text):
        """Decrypt sensitive data"""
        if not encrypted_text:
            return None
        try:
            return self.cipher.decrypt(encrypted_text.encode()).decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def get_api_key(self, key_name):
        """Get API key from environment or encrypted storage"""
        # First try to get from environment
        api_key = os.getenv(key_name)
        if api_key:
            return api_key
        
        # Try to get from encrypted storage
        encrypted_key = os.getenv(f"{key_name}_ENCRYPTED")
        if encrypted_key:
            return self.decrypt(encrypted_key)
        
        return None

# Initialize secure config
secure_config = SecureConfig()

class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # File upload settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB default
    ALLOWED_EXTENSIONS = {'txt', 'log', 'csv'}
    
    # Data storage settings
    DATA_FOLDER = os.environ.get('DATA_FOLDER', 'data')
    
    # Server settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # Threat detection settings
    THREAT_DETECTION_ENABLED = os.environ.get('THREAT_DETECTION_ENABLED', 'True').lower() == 'true'
    ANOMALY_DETECTION_ENABLED = os.environ.get('ANOMALY_DETECTION_ENABLED', 'True').lower() == 'true'
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')
    
    # AI API Keys (encrypted)
    GOOGLE_AI_API_KEY = secure_config.get_api_key('GOOGLE_AI_API_KEY')
    OPENAI_API_KEY = secure_config.get_api_key('OPENAI_API_KEY')
    
    # Security settings
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Ensure required directories exist
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.DATA_FOLDER, exist_ok=True)
        
        # Set Flask configuration
        app.config['SECRET_KEY'] = Config.SECRET_KEY
        app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
        app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    THREAT_DETECTION_ENABLED = True
    ANOMALY_DETECTION_ENABLED = True
    FLASK_ENV = 'development'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    FLASK_ENV = 'production'
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production-specific initialization
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug and not app.testing:
            if not os.path.exists('logs'):
                os.mkdir('logs')
            file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('Log Dashboard startup')

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    UPLOAD_FOLDER = 'test_uploads'
    DATA_FOLDER = 'test_data'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
} 