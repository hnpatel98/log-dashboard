# Log Dashboard Backend

A Flask-based RESTful API backend for log file processing, analysis, and AI-based threat detection.

## 🚀 Features

- **📁 File Upload & Storage** - Secure file upload with validation and storage
- **🔍 Log Processing** - Advanced log parsing with multiple format support
- **🤖 AI Threat Detection** - Machine learning-based security analysis
- **📊 Anomaly Detection** - Pattern recognition for unusual activities
- **🔒 Security Analysis** - Comprehensive threat assessment and risk scoring
- **📈 Analytics** - Statistical analysis and reporting
- **🌐 RESTful API** - Clean, documented API endpoints

## 🛠️ Tech Stack

- **Framework**: Flask 3.1.1
- **Language**: Python 3.8+
- **AI/ML**: scikit-learn, pandas, numpy
- **Security**: Pattern-based threat detection
- **Storage**: File-based JSON storage
- **CORS**: Cross-origin resource sharing support

## 📁 Project Structure

```
backend/
├── app.py                 # Main Flask application
├── config.py              # Configuration management
├── run.py                 # Application startup script
├── requirements.txt       # Python dependencies
├── log_processor.py       # Log parsing and processing
├── threat_detector.py     # AI-based threat detection
├── models/                # Data models
│   ├── __init__.py
│   ├── log_entry.py       # Log entry model
│   └── analysis_result.py # Analysis result model
├── uploads/               # Uploaded files storage
├── data/                  # Analysis results storage
└── README.md             # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the server:**
   ```bash
   python run.py
   ```

5. **Access the API:**
   - Health check: `http://localhost:5000/api/health`
   - API will be available at: `http://localhost:5000`

## 📚 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Endpoints

#### 1. Health Check
```http
GET /api/health
```
**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:15.123456",
  "service": "log-dashboard-backend"
}
```

#### 2. Upload Log File
```http
POST /api/upload
Content-Type: multipart/form-data
```
**Parameters:**
- `file`: Log file (.txt or .log)

**Response:**
```json
{
  "success": true,
  "file_id": "uuid-string",
  "filename": "example.log",
  "total_logs": 150,
  "threats_detected": 3,
  "message": "File uploaded and processed successfully"
}
```

#### 3. Get Analysis Results
```http
GET /api/analysis/{file_id}
```
**Response:**
```json
{
  "file_id": "uuid-string",
  "original_filename": "example.log",
  "total_logs": 150,
  "log_entries": [...],
  "threat_analysis": {
    "threats": [...],
    "anomalies": [...],
    "risk_score": 75.5,
    "summary": "HIGH RISK - Immediate attention required"
  },
  "processed_at": "2024-01-15T10:30:15.123456"
}
```

#### 4. Get All Analyses
```http
GET /api/analysis
```
**Response:**
```json
{
  "analyses": [
    {
      "file_id": "uuid-string",
      "original_filename": "example.log",
      "total_logs": 150,
      "processed_at": "2024-01-15T10:30:15.123456"
    }
  ]
}
```

#### 5. Get All Threats
```http
GET /api/threats
```
**Response:**
```json
{
  "threats": [
    {
      "type": "sql_injection",
      "severity": "high",
      "message": "Detected SQL injection attempt",
      "timestamp": "2024-01-15T10:30:15.123456",
      "source": "example.log",
      "confidence": 0.9
    }
  ],
  "total_threats": 5
}
```

#### 6. Get Statistics
```http
GET /api/stats
```
**Response:**
```json
{
  "total_files": 10,
  "total_logs": 1500,
  "total_threats": 25,
  "log_levels": {
    "ERROR": 150,
    "WARN": 300,
    "INFO": 900,
    "DEBUG": 150
  },
  "average_logs_per_file": 150
}
```

#### 7. Download File
```http
GET /api/files/{file_id}/download
```
**Response:** File download

#### 8. Delete File
```http
DELETE /api/files/{file_id}
```
**Response:**
```json
{
  "success": true,
  "message": "File and analysis deleted successfully"
}
```

## 🔍 Threat Detection Features

### Pattern-Based Detection
- **SQL Injection**: Detects common SQL injection patterns
- **XSS Attacks**: Identifies cross-site scripting attempts
- **Path Traversal**: Detects directory traversal attacks
- **Authentication Failures**: Monitors login attempts
- **Brute Force**: Identifies repeated failed attempts
- **Data Exfiltration**: Detects suspicious data transfers
- **System Intrusion**: Identifies unauthorized access
- **Network Attacks**: Detects DDoS and scanning attempts
- **File Manipulation**: Monitors suspicious file operations
- **API Abuse**: Detects rate limiting violations

### Anomaly Detection
- **Error Rate Analysis**: Monitors error frequency
- **Consecutive Errors**: Detects error bursts
- **Time-based Anomalies**: Identifies unusual activity patterns
- **Behavioral Analysis**: Analyzes user/system behavior

### Risk Scoring
- **0-100 Scale**: Normalized risk assessment
- **Weighted Scoring**: Different threat types have different weights
- **Confidence Levels**: Indicates detection reliability
- **Severity Classification**: High, Medium, Low risk levels

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# Flask Configuration
FLASK_CONFIG=development
SECRET_KEY=your-secret-key-here
FLASK_DEBUG=True

# Server Configuration
HOST=0.0.0.0
PORT=5000

# File Upload Configuration
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216
DATA_FOLDER=data

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Threat Detection Configuration
THREAT_DETECTION_ENABLED=True
ANOMALY_DETECTION_ENABLED=True

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=app.log
```

### Configuration Profiles

- **Development**: Debug mode, detailed logging
- **Production**: Optimized for performance, file logging
- **Testing**: Test-specific settings

## 🔧 Development

### Running in Development Mode
```bash
export FLASK_CONFIG=development
python run.py
```

### Running in Production Mode
```bash
export FLASK_CONFIG=production
export SECRET_KEY=your-production-secret-key
python run.py
```

### Testing
```bash
export FLASK_CONFIG=testing
python -m pytest tests/
```

## 📊 Log Format Support

The backend supports multiple log formats:

### Standard Log Format
```
2024-01-15 10:30:15 INFO Application started successfully
```

### JSON Log Format
```json
{
  "timestamp": "2024-01-15T10:30:15Z",
  "level": "INFO",
  "message": "Application started successfully"
}
```

### Apache Access Log
```
192.168.1.1 - - [15/Jan/2024:10:30:15 +0000] "GET /api/health HTTP/1.1" 200 1234
```

### Nginx Access Log
```
192.168.1.1 - - [15/Jan/2024:10:30:15 +0000] "GET /api/health HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

## 🚀 Deployment

### Using Gunicorn (Production)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

### Using Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "run.py"]
```

### Environment Setup
```bash
# Production environment
export FLASK_CONFIG=production
export SECRET_KEY=your-secure-secret-key
export HOST=0.0.0.0
export PORT=5000
```

## 🔒 Security Considerations

- **File Upload Validation**: Only .txt and .log files allowed
- **File Size Limits**: Configurable maximum file size
- **CORS Configuration**: Configurable cross-origin settings
- **Input Sanitization**: All inputs are validated and sanitized
- **Error Handling**: Comprehensive error handling without information leakage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is part of the Log Dashboard application.

## 🆘 Support

For issues and questions:
1. Check the API documentation
2. Review the logs in the `logs/` directory
3. Open an issue on GitHub 