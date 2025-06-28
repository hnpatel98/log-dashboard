from flask import Flask, request, jsonify, send_from_directory # type: ignore
from flask_cors import CORS # type: ignore
import os
import json
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename # type: ignore
from log_processor import LogProcessor
from threat_detector import ThreatDetector
from models.log_entry import LogEntry
from models.analysis_result import AnalysisResult
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import re
from openai import OpenAI
import google.generativeai as genai
from dotenv import load_dotenv
import traceback
from config import secure_config
import sys
import logging

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'log', 'csv'}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize processors
log_processor = LogProcessor()
threat_detector = ThreatDetector()

# Initialize AI clients
openai_client = None
google_ai_client = None

# Initialize OpenAI client
openai_api_key = secure_config.get_api_key('OPENAI_API_KEY')
if openai_api_key:
    openai_client = OpenAI(api_key=openai_api_key)

# Initialize Google AI Studio client
google_ai_api_key = secure_config.get_api_key('GOOGLE_AI_API_KEY')
if google_ai_api_key:
    genai.configure(api_key=google_ai_api_key)
    google_ai_client = genai.GenerativeModel('gemini-1.5-flash')

# Set up logging to console only
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    print("=== HEALTH CHECK ENDPOINT CALLED ===")
    sys.stdout.flush()
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload log file endpoint"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only .txt, .log, and .csv files are allowed'}), 400
        
        # Generate unique filename
        file_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{file_id}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Create basic analysis result without processing
        analysis_result = AnalysisResult(
            file_id=file_id,
            original_filename=filename,
            total_logs=0,  # Will be set during analysis
            log_entries=[],  # Always a list of dicts
            threat_analysis={'threats': [], 'anomalies': [], 'risk_score': 0, 'summary': 'Not analyzed yet'},  # Will be populated during analysis
            processed_at=datetime.now()
        )
        
        # Save analysis result
        analysis_result.save()
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': filename,
            'message': 'File uploaded successfully. Click "Analyze" to process the file.'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error uploading file: {str(e)}'}), 500

@app.route('/api/analysis/<file_id>', methods=['GET'])
def get_analysis(file_id):
    """Get analysis results for a specific file"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'Analysis not found'}), 404
        
        return jsonify(analysis_result.to_dict()), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving analysis: {str(e)}'}), 500

@app.route('/api/analysis', methods=['GET'])
def get_all_analyses():
    """Get all analysis results"""
    try:
        analyses = AnalysisResult.get_all()
        return jsonify({
            'analyses': [analysis.to_dict() for analysis in analyses]
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving analyses: {str(e)}'}), 500

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all detected threats across all files"""
    try:
        analyses = AnalysisResult.get_all()
        all_threats = []
        
        for analysis in analyses:
            if analysis.threat_analysis and 'threats' in analysis.threat_analysis:
                for threat in analysis.threat_analysis['threats']:
                    threat['file_id'] = analysis.file_id
                    threat['filename'] = analysis.original_filename
                    all_threats.append(threat)
        
        return jsonify({
            'threats': all_threats,
            'total_threats': len(all_threats)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving threats: {str(e)}'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics"""
    try:
        analyses = AnalysisResult.get_all()
        
        total_files = len(analyses)
        total_logs = sum(analysis.total_logs for analysis in analyses)
        total_threats = sum(
            len(analysis.threat_analysis.get('threats', [])) 
            for analysis in analyses
        )
        
        # Calculate log level distribution
        level_counts = {'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DEBUG': 0}
        for analysis in analyses:
            for entry in analysis.log_entries:
                level = entry.level.upper()
                if level in level_counts:
                    level_counts[level] += 1
        
        return jsonify({
            'total_files': total_files,
            'total_logs': total_logs,
            'total_threats': total_threats,
            'log_levels': level_counts,
            'average_logs_per_file': total_logs / total_files if total_files > 0 else 0
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving stats: {str(e)}'}), 500

@app.route('/api/files/<file_id>/download', methods=['GET'])
def download_file(file_id):
    """Download original uploaded file"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'File not found'}), 404
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.{analysis_result.original_filename.rsplit('.', 1)[1].lower()}")
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            f"{file_id}.{analysis_result.original_filename.rsplit('.', 1)[1].lower()}",
            as_attachment=True,
            download_name=analysis_result.original_filename
        )
        
    except Exception as e:
        return jsonify({'error': f'Error downloading file: {str(e)}'}), 500

@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete uploaded file and its analysis"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete file from disk
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.{analysis_result.original_filename.rsplit('.', 1)[1].lower()}")
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete analysis result
        AnalysisResult.delete(file_id)
        
        return jsonify({
            'success': True,
            'message': 'File and analysis deleted successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error deleting file: {str(e)}'}), 500

@app.route('/api/stats/<file_id>', methods=['GET'])
def get_file_stats(file_id):
    """Get statistics for a specific file"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'File not found'}), 404
        
        # Calculate log level distribution for this file
        level_counts = {'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DEBUG': 0}
        for entry in analysis_result.log_entries:
            level = entry.level.upper()
            if level in level_counts:
                level_counts[level] += 1
        
        total_threats = len(analysis_result.threat_analysis.get('threats', []))
        
        return jsonify({
            'total_files': 1,
            'total_logs': analysis_result.total_logs,
            'total_threats': total_threats,
            'log_levels': level_counts,
            'average_logs_per_file': analysis_result.total_logs
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving file stats: {str(e)}'}), 500

@app.route('/api/threats/<file_id>', methods=['GET'])
def get_file_threats(file_id):
    """Get threats for a specific file"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'File not found'}), 404
        
        threats = []
        if analysis_result.threat_analysis and 'threats' in analysis_result.threat_analysis:
            for threat in analysis_result.threat_analysis['threats']:
                threat['file_id'] = analysis_result.file_id
                threat['filename'] = analysis_result.original_filename
                threats.append(threat)
        
        return jsonify({
            'threats': threats,
            'total_threats': len(threats)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error retrieving file threats: {str(e)}'}), 500

@app.route('/api/analyze/<file_id>', methods=['POST'])
def analyze_file(file_id):
    """Analyze an uploaded file for threats"""
    try:
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            return jsonify({'error': 'File not found'}), 404
        
        # Check if file exists on disk
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}.{analysis_result.original_filename.rsplit('.', 1)[1].lower()}")
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Parse logs
        logs = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    log_entry = parse_log_line(line)
                    log_entry['line_number'] = line_num
                    logs.append(log_entry)
        
        # Convert to DataFrame
        logs_df = pd.DataFrame(logs)
        
        # Detect threats
        threats = detect_threats(logs_df)
        
        # Generate AI summary
        ai_summary = generate_ai_summary(logs_df, threats)
        
        # Update analysis result
        analysis_result.total_logs = len(logs)
        # Ensure all log entries are dicts
        analysis_result.log_entries = [dict(log) if not isinstance(log, dict) else log for log in logs]
        analysis_result.threat_analysis = {'threats': threats, 'anomalies': [], 'risk_score': 0, 'summary': ai_summary['summary']}
        analysis_result.processed_at = datetime.now()
        
        # Save updated analysis result
        analysis_result.save()
        
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': analysis_result.original_filename,
            'total_logs': len(logs),
            'threats_detected': len(threats),
            'ai_summary': ai_summary
        }), 200
        
    except Exception as e:
        print('Error analyzing file:', e)
        traceback.print_exc()
        return jsonify({'error': f'Error analyzing file: {str(e)}'}), 500

@app.route('/api/ai-summary/<file_id>', methods=['POST'])
def generate_ai_summary(file_id):
    """Generate AI-powered summary of log analysis"""
    print(f"=== AI SUMMARY ENDPOINT CALLED FOR FILE: {file_id} ===")
    sys.stdout.flush()
    try:
        logging.debug('AI summary endpoint called for file_id: %s', file_id)
        # Get the analysis result for the file
        analysis_result = AnalysisResult.load(file_id)
        if not analysis_result:
            logging.debug('AnalysisResult not found for file_id: %s', file_id)
            return jsonify({'error': 'File not found'}), 404
        
        # Get request data
        request_data = request.get_json()
        threats = request_data.get('threats', [])
        stats = request_data.get('stats', {})
        
        # Debug: Check what log entries look like
        logging.debug(f"Number of log entries: {len(analysis_result.log_entries)}")
        if analysis_result.log_entries:
            logging.debug(f"First log entry type: {type(analysis_result.log_entries[0])}")
            logging.debug(f"First log entry: {analysis_result.log_entries[0]}")
        
        # Convert log entries to dictionaries for DataFrame
        log_entries_dict = []
        for entry in analysis_result.log_entries:
            if hasattr(entry, 'to_dict'):
                log_entries_dict.append(entry.to_dict())
            elif isinstance(entry, dict):
                log_entries_dict.append(entry)
            else:
                # Fallback: try to access attributes directly
                try:
                    log_entries_dict.append({
                        'timestamp': getattr(entry, 'timestamp', ''),
                        'level': getattr(entry, 'level', ''),
                        'message': getattr(entry, 'message', ''),
                        'source': getattr(entry, 'source', ''),
                        'line_number': getattr(entry, 'line_number', ''),
                        'additional_data': getattr(entry, 'additional_data', {})
                    })
                except Exception as e:
                    logging.debug(f"Error converting entry {entry}: {e}")
                    continue
        
        logging.debug(f"Converted {len(log_entries_dict)} log entries to dict")
        if log_entries_dict:
            logging.debug(f"First dict entry keys: {list(log_entries_dict[0].keys())}")
        
        # Try to use real AI if Google AI Studio or OpenAI is configured, otherwise use mock
        if google_ai_client:
            # Use Google AI Studio for analysis
            logs_df = pd.DataFrame(log_entries_dict)
            ai_summary = generate_google_ai_summary(logs_df, threats)
        elif openai_client:
            # Fallback to OpenAI if Google AI is not available
            logs_df = pd.DataFrame(log_entries_dict)
            ai_summary = generate_ai_summary(logs_df, threats)
        else:
            # Use mock AI summary if no AI service is configured
            ai_summary = generate_mock_ai_summary(analysis_result, threats, stats)
        
        return jsonify(ai_summary), 200
        
    except Exception as e:
        logging.exception('Exception in AI summary endpoint:')
        return jsonify({'error': f'Error generating AI summary: {str(e)}'}), 500

def generate_mock_ai_summary(analysis_result, threats, stats):
    """Generate a mock AI summary (placeholder for LLM integration)"""
    total_logs = stats.get('total_logs', 0)
    total_threats = len(threats)
    
    # Determine risk level based on threats
    high_threats = len([t for t in threats if t.get('severity') == 'high'])
    medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
    
    if high_threats > 0:
        risk_level = "HIGH RISK"
        risk_description = "Critical security threats detected requiring immediate attention"
    elif medium_threats > 0 or total_threats > 0:
        risk_level = "MEDIUM RISK"
        risk_description = "Moderate security concerns that should be investigated"
    else:
        risk_level = "LOW RISK"
        risk_description = "No significant security threats detected"
    
    # Generate summary based on analysis
    if total_threats == 0:
        summary = f"This log analysis examined {total_logs} log entries and found no security threats. The system appears to be operating normally with standard logging activity."
        key_findings = [
            f"Analyzed {total_logs} log entries successfully",
            "No security threats or anomalies detected",
            "System appears to be operating within normal parameters"
        ]
        recommendations = [
            "Continue monitoring logs for any unusual activity",
            "Maintain current security practices and configurations",
            "Consider implementing additional logging for better visibility"
        ]
    else:
        threat_types = [t.get('type', 'unknown') for t in threats]
        unique_threats = list(set(threat_types))
        
        summary = f"This log analysis examined {total_logs} log entries and detected {total_threats} security threats. The analysis identified {len(unique_threats)} different types of threats, including {', '.join(unique_threats[:3])}."
        
        key_findings = [
            f"Detected {total_threats} security threats across {len(unique_threats)} categories",
            f"Found {high_threats} high-severity and {medium_threats} medium-severity threats",
            f"Analyzed {total_logs} log entries for security patterns"
        ]
        
        recommendations = [
            "Immediately investigate and remediate high-severity threats",
            "Review and strengthen security controls for identified threat types",
            "Implement additional monitoring for similar attack patterns",
            "Consider conducting a security audit of affected systems"
        ]
    
    return {
        'summary': summary,
        'recommendations': recommendations,
        'risk_assessment': f"{risk_level} - {risk_description}",
        'key_findings': key_findings,
        'generated_at': datetime.now().isoformat()
    }

def parse_log_line(line):
    """Parse a single log line and extract structured data"""
    # Common log patterns
    patterns = [
        # Standard log format: [timestamp] level message
        r'\[([^\]]+)\]\s+(\w+)\s+(.+)',
        # ISO timestamp format: 2024-01-01T12:00:00.000Z level message
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(\w+)\s+(.+)',
        # Simple format: timestamp level message
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\w+)\s+(.+)',
        # Fallback: just extract any timestamp and level
        r'([^\s]+)\s+(\w+)\s+(.+)'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, line.strip())
        if match:
            timestamp, level, message = match.groups()
            return {
                'timestamp': timestamp,
                'level': level.upper(),
                'message': message.strip(),
                'raw_line': line.strip()
            }
    
    # If no pattern matches, return basic info
    return {
        'timestamp': datetime.now().isoformat(),
        'level': 'UNKNOWN',
        'message': line.strip(),
        'raw_line': line.strip()
    }

def detect_threats(logs_df):
    """Enhanced threat detection using multiple techniques"""
    threats = []
    
    # Threat patterns to look for
    threat_patterns = {
        'authentication_failure': [
            r'failed\s+login',
            r'authentication\s+failed',
            r'login\s+failed',
            r'invalid\s+password',
            r'access\s+denied'
        ],
        'sql_injection': [
            r'(\'|")\s*(union|select|insert|update|delete|drop|create|alter)\s+',
            r'(\'|")\s*(\d+\s*=\s*\d+|\d+\s*or\s*\d+)',
            r'(\'|")\s*(\d+\s*and\s*\d+)'
        ],
        'xss_attack': [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>'
        ],
        'file_inclusion': [
            r'\.\./',
            r'\.\.\\',
            r'include\s*\([^)]*\.\.',
            r'require\s*\([^)]*\.\.'
        ],
        'command_injection': [
            r'(\||;|&|`|$)\s*\w+',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\('
        ]
    }
    
    # Check each log entry for threats
    for idx, row in logs_df.iterrows():
        message = str(row['message']).lower()
        level = str(row['level']).upper()
        
        for threat_type, patterns in threat_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    # Calculate threat severity based on type and log level
                    severity_map = {
                        'ERROR': 0.9,
                        'CRITICAL': 1.0,
                        'WARNING': 0.7,
                        'INFO': 0.5,
                        'DEBUG': 0.3
                    }
                    
                    base_severity = severity_map.get(level, 0.5)
                    
                    # Adjust severity based on threat type
                    threat_severity = {
                        'authentication_failure': 0.8,
                        'sql_injection': 1.0,
                        'xss_attack': 0.9,
                        'file_inclusion': 0.9,
                        'command_injection': 1.0
                    }
                    
                    final_severity = base_severity * threat_severity.get(threat_type, 0.7)
                    
                    threats.append({
                        'id': len(threats) + 1,
                        'timestamp': row['timestamp'],
                        'type': threat_type.replace('_', ' ').title(),
                        'severity': 'high' if final_severity >= 0.8 else 'medium' if final_severity >= 0.5 else 'low',
                        'message': row['message'],
                        'log_level': level,
                        'line_number': idx + 1,
                        'confidence': final_severity,
                        'source': 'pattern_detection',
                        'explanation': f"Pattern match detected for {threat_type.replace('_', ' ')} attack",
                        'is_anomaly': False
                    })
    
    # Enhanced anomaly detection using Isolation Forest
    if len(logs_df) > 10:
        try:
            # Create features for anomaly detection
            features = []
            feature_data = []
            
            for idx, row in logs_df.iterrows():
                message = str(row['message'])
                
                # Feature 1: Message length
                msg_length = len(message)
                # Feature 2: Number of special characters
                special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', message))
                # Feature 3: Number of numbers
                numbers = len(re.findall(r'\d+', message))
                # Feature 4: Number of uppercase letters
                uppercase = len(re.findall(r'[A-Z]', message))
                # Feature 5: Number of words
                words = len(message.split())
                # Feature 6: Average word length
                avg_word_length = sum(len(word) for word in message.split()) / max(words, 1)
                
                features.append([msg_length, special_chars, numbers, uppercase, words, avg_word_length])
                feature_data.append({
                    'msg_length': msg_length,
                    'special_chars': special_chars,
                    'numbers': numbers,
                    'uppercase': uppercase,
                    'words': words,
                    'avg_word_length': avg_word_length
                })
            
            # Detect anomalies
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomalies = iso_forest.fit_predict(features)
            
            # Calculate feature statistics for explanations
            feature_stats = {}
            for feature_name in ['msg_length', 'special_chars', 'numbers', 'uppercase', 'words', 'avg_word_length']:
                values = [data[feature_name] for data in feature_data]
                feature_stats[feature_name] = {
                    'mean': np.mean(values),
                    'std': np.std(values),
                    'min': np.min(values),
                    'max': np.max(values)
                }
            
            # Add anomaly threats with detailed explanations
            for idx, is_anomaly in enumerate(anomalies):
                if is_anomaly == -1:  # Anomaly detected
                    row = logs_df.iloc[idx]
                    feature_values = feature_data[idx]
                    
                    # Generate detailed explanation
                    explanation_parts = []
                    
                    # Check which features are anomalous
                    for feature_name, value in feature_values.items():
                        stats = feature_stats[feature_name]
                        z_score = abs((value - stats['mean']) / max(stats['std'], 0.1))
                        
                        if z_score > 2:  # Significantly different from normal
                            if feature_name == 'msg_length':
                                if value > stats['mean']:
                                    explanation_parts.append(f"Unusually long message ({value} chars vs avg {stats['mean']:.1f})")
                                else:
                                    explanation_parts.append(f"Unusually short message ({value} chars vs avg {stats['mean']:.1f})")
                            elif feature_name == 'special_chars':
                                if value > stats['mean']:
                                    explanation_parts.append(f"High number of special characters ({value} vs avg {stats['mean']:.1f})")
                            elif feature_name == 'numbers':
                                if value > stats['mean']:
                                    explanation_parts.append(f"Unusual number of numeric values ({value} vs avg {stats['mean']:.1f})")
                            elif feature_name == 'uppercase':
                                if value > stats['mean']:
                                    explanation_parts.append(f"Excessive uppercase usage ({value} vs avg {stats['mean']:.1f})")
                            elif feature_name == 'words':
                                if value > stats['mean']:
                                    explanation_parts.append(f"Unusually verbose message ({value} words vs avg {stats['mean']:.1f})")
                                else:
                                    explanation_parts.append(f"Unusually brief message ({value} words vs avg {stats['mean']:.1f})")
                            elif feature_name == 'avg_word_length':
                                if value > stats['mean']:
                                    explanation_parts.append(f"Unusually long words (avg {value:.1f} chars vs normal {stats['mean']:.1f})")
                    
                    # If no specific features stand out, provide general explanation
                    if not explanation_parts:
                        explanation_parts.append("Statistical anomaly detected - message pattern differs significantly from normal logs")
                    
                    explanation = "; ".join(explanation_parts)
                    
                    threats.append({
                        'id': len(threats) + 1,
                        'timestamp': row['timestamp'],
                        'type': 'Anomalous Activity',
                        'severity': 'high',
                        'message': row['message'],
                        'log_level': row['level'],
                        'line_number': idx + 1,
                        'confidence': 0.7,
                        'source': 'anomaly_detection',
                        'explanation': explanation,
                        'is_anomaly': True,
                        'anomaly_features': feature_values,
                        'anomaly_score': z_score if 'z_score' in locals() else 2.5
                    })
        except Exception as e:
            print(f"Anomaly detection error: {e}")
    
    # Calculate risk scores for each threat
    for threat in threats:
        # Base risk score from severity
        risk_score = threat['confidence'] * 100
        
        # Additional risk factors
        if threat['log_level'] in ['ERROR', 'CRITICAL']:
            risk_score += 20
        if 'password' in threat['message'].lower() or 'auth' in threat['message'].lower():
            risk_score += 15
        if 'admin' in threat['message'].lower() or 'root' in threat['message'].lower():
            risk_score += 10
        
        # Bonus for anomalies
        if threat.get('is_anomaly', False):
            risk_score += 10
        
        # Cap risk score at 100
        threat['risk_score'] = min(risk_score, 100)
        
        # Classify risk level
        if threat['risk_score'] >= 80:
            threat['risk_level'] = 'High'
        elif threat['risk_score'] >= 50:
            threat['risk_level'] = 'Medium'
        else:
            threat['risk_level'] = 'Low'
        
        # Update severity to match risk level
        threat['severity'] = threat['risk_level'].lower()
    
    return threats

def generate_google_ai_summary(logs_df, threats):
    """Generate AI summary using Google AI Studio (Gemini)"""
    try:
        if not google_ai_client:
            return generate_mock_ai_summary(None, threats, {
                'total_logs': len(logs_df),
                'total_threats': len(threats)
            })
        
        # Prepare log statistics
        total_logs = len(logs_df)
        total_threats = len(threats)
        
        # Separate pattern-based threats and anomalies
        pattern_threats = [t for t in threats if not t.get('is_anomaly', False)]
        anomalies = [t for t in threats if t.get('is_anomaly', False)]
        
        # Get threat type distribution
        threat_types = {}
        for threat in pattern_threats:
            threat_type = threat.get('type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Get log level distribution
        log_levels = logs_df['level'].value_counts().to_dict()
        
        # Prepare sample log messages (first 5)
        sample_logs = logs_df.head(5)['message'].tolist()
        
        # Prepare threat summaries with explanations
        threat_summaries = []
        for threat in threats[:10]:  # Limit to first 10 threats
            summary = f"- {threat.get('type', 'Unknown')} (Confidence: {threat.get('confidence', 0):.1%})"
            if threat.get('explanation'):
                summary += f" - {threat['explanation']}"
            threat_summaries.append(summary)
        
        # Prepare anomaly summaries
        anomaly_summaries = []
        for anomaly in anomalies[:5]:  # Limit to first 5 anomalies
            summary = f"- Anomaly: {anomaly.get('explanation', 'Statistical anomaly detected')}"
            if anomaly.get('anomaly_score'):
                summary += f" (Score: {anomaly['anomaly_score']:.2f})"
            anomaly_summaries.append(summary)
        
        # Construct the prompt
        prompt = f"""
You are a cybersecurity analyst reviewing log analysis results. Please provide a comprehensive summary of the findings.

LOG ANALYSIS SUMMARY REQUEST:

Total Logs Analyzed: {total_logs}
Total Threats Detected: {total_threats}
Pattern-Based Threats: {len(pattern_threats)}
Anomalies Detected: {len(anomalies)}

Log Level Distribution: {log_levels}

Threat Type Distribution: {threat_types}

Sample Log Messages:
{chr(10).join(f"- {log}" for log in sample_logs)}

Threat Details:
{chr(10).join(threat_summaries)}

Anomaly Details:
{chr(10).join(anomaly_summaries) if anomaly_summaries else "- No anomalies detected"}

Please provide a JSON response with the following structure:
{{
  "summary": "A concise 2-3 sentence summary of the overall findings",
  "key_findings": [
    "Key finding 1",
    "Key finding 2",
    "Key finding 3"
  ],
  "recommendations": [
    "Specific recommendation 1",
    "Specific recommendation 2",
    "Specific recommendation 3"
  ],
  "risk_assessment": "HIGH/MEDIUM/LOW RISK - Brief explanation"
}}

Focus on:
1. The most critical threats and their potential impact
2. Unusual patterns or anomalies that require attention
3. Specific, actionable recommendations for security teams
4. Clear risk assessment based on threat severity and frequency
"""
        
        # Generate response
        response = google_ai_client.generate_content(prompt)
        ai_response = response.text
        
        # Clean and parse the response
        cleaned_response = ai_response.strip()
        
        # Remove markdown code blocks if present
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:]
        elif cleaned_response.startswith('```'):
            cleaned_response = cleaned_response[3:]
        if cleaned_response.endswith('```'):
            cleaned_response = cleaned_response[:-3]
        
        cleaned_response = cleaned_response.strip()
        
        try:
            result = json.loads(cleaned_response)
            
            # Validate that we have the expected structure
            if isinstance(result, dict) and 'summary' in result:
                # Add debug field for troubleshooting
                result['_debug_cleaned_summary'] = cleaned_response
                return result
            else:
                # If the parsed result doesn't have the expected structure, create a structured response
                return {
                    "summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response,
                    "key_findings": ["AI analysis completed", "Review the summary for details"],
                    "recommendations": ["Implement the suggested security measures"],
                    "_debug_cleaned_summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response
                }
                
        except json.JSONDecodeError as e:
            logging.debug(f"JSON decode error: {e}")
            # If JSON parsing fails, create a structured response from the text
            return {
                "summary": ai_response[:500] + "..." if len(ai_response) > 500 else ai_response,
                "key_findings": ["AI analysis completed", "Review the summary for details"],
                "recommendations": ["Implement the suggested security measures"],
                "_debug_cleaned_summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response,
                "_debug_original_response": ai_response[:500] + "..." if len(ai_response) > 500 else ai_response,
                "_debug_error": str(e)
            }
            
    except Exception as e:
        return {
            "summary": f"Error generating AI summary: {str(e)}",
            "key_findings": ["Error occurred during AI analysis"],
            "recommendations": ["Check Google AI Studio API configuration and try again"]
        }

def generate_ai_summary(logs_df, threats):
    """Generate AI summary using OpenAI"""
    if not openai_client:
        return {
            "summary": "OpenAI API key not configured. Please add OPENAI_API_KEY to your environment variables.",
            "key_findings": [],
            "recommendations": []
        }
    
    try:
        # Check if logs_df is empty or has no data
        if logs_df.empty or len(logs_df) == 0:
            return {
                "summary": "No log data available for analysis.",
                "key_findings": ["No log entries found"],
                "recommendations": ["Upload a log file with data to generate AI analysis"]
            }
        
        # Ensure required columns exist
        required_columns = ['level', 'message']
        missing_columns = [col for col in required_columns if col not in logs_df.columns]
        
        if missing_columns:
            return {
                "summary": f"Log data missing required columns: {', '.join(missing_columns)}",
                "key_findings": ["Log data structure is incomplete"],
                "recommendations": ["Check log file format and try again"]
            }
        
        # Prepare log data for analysis
        log_levels = logs_df['level'].value_counts().to_dict()
        total_logs = len(logs_df)
        threat_count = len(threats)
        
        # Create threat summary
        threat_summary = ""
        if threats:
            high_threats = [t for t in threats if t.get('severity') == 'high']
            medium_threats = [t for t in threats if t.get('severity') == 'medium']
            low_threats = [t for t in threats if t.get('severity') == 'low']
            
            threat_summary = f"""
            Threats detected: {threat_count}
            - High risk: {len(high_threats)}
            - Medium risk: {len(medium_threats)}
            - Low risk: {len(low_threats)}
            
            Threat types found: {', '.join(set(t.get('type', 'unknown') for t in threats))}
            """
        
        # Sample of log messages for context
        sample_logs = logs_df['message'].head(10).tolist()
        
        # Create prompt for OpenAI
        prompt = f"""
        Analyze this log file and provide a comprehensive security analysis summary.
        
        Log Statistics:
        - Total logs: {total_logs}
        - Log levels: {log_levels}
        
        {threat_summary}
        
        Sample log messages:
        {chr(10).join(f"- {log}" for log in sample_logs)}
        
        Please provide:
        1. A concise executive summary of the log analysis
        2. Key security findings and patterns
        3. Specific recommendations for improving security
        
        Format your response as JSON with the following structure:
        {{
            "summary": "Brief executive summary",
            "key_findings": ["finding1", "finding2", "finding3"],
            "recommendations": ["recommendation1", "recommendation2", "recommendation3"]
        }}
        """
        
        # Call OpenAI API
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing log files for security threats and patterns."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0.3
        )
        
        # Parse the response
        ai_response = response.choices[0].message.content.strip()
        
        # Try to parse as JSON, fallback to text if needed
        try:
            # Clean up the response - remove markdown code blocks if present
            cleaned_response = ai_response.strip()
            
            # Remove markdown code blocks
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            
            cleaned_response = cleaned_response.strip()
            logging.debug(f"Cleaned OpenAI response: {cleaned_response[:200]}...")
            
            # Try to parse as JSON
            result = json.loads(cleaned_response)
            
            # If the summary field itself is a JSON string, parse it again (robust)
            if (
                isinstance(result, dict)
                and 'summary' in result
                and isinstance(result['summary'], str)
            ):
                summary_str = result['summary'].strip()
                # Remove code block if present
                if summary_str.startswith('```json'):
                    summary_str = summary_str[7:]
                elif summary_str.startswith('```'):
                    summary_str = summary_str[3:]
                if summary_str.endswith('```'):
                    summary_str = summary_str[:-3]
                summary_str = summary_str.strip()
                logging.debug(f"Cleaned nested summary: {summary_str[:200]}...")
                if summary_str.startswith('{'):
                    try:
                        nested = json.loads(summary_str)
                        # Merge fields if present
                        result['summary'] = nested.get('summary', result['summary'])
                        if 'key_findings' in nested:
                            result['key_findings'] = nested['key_findings']
                        if 'recommendations' in nested:
                            result['recommendations'] = nested['recommendations']
                        logging.debug(f"Parsed nested summary as JSON.")
                    except Exception as e:
                        logging.debug(f"Nested JSON parse error: {e}")
            
            # Validate that we have the expected structure
            if isinstance(result, dict) and 'summary' in result:
                # Add debug field for troubleshooting
                result['_debug_cleaned_summary'] = summary_str if 'summary_str' in locals() else result['summary']
                return result
            else:
                # If the parsed result doesn't have the expected structure, create a structured response
                return {
                    "summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response,
                    "key_findings": ["AI analysis completed", "Review the summary for details"],
                    "recommendations": ["Implement the suggested security measures"],
                    "_debug_cleaned_summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response
                }
                
        except json.JSONDecodeError as e:
            logging.debug(f"JSON decode error: {e}")
            # If JSON parsing fails, create a structured response from the text
            return {
                "summary": ai_response[:500] + "..." if len(ai_response) > 500 else ai_response,
                "key_findings": ["AI analysis completed", "Review the summary for details"],
                "recommendations": ["Implement the suggested security measures"],
                "_debug_cleaned_summary": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response,
                "_debug_original_response": ai_response[:500] + "..." if len(ai_response) > 500 else ai_response,
                "_debug_error": str(e)
            }
            
    except Exception as e:
        return {
            "summary": f"Error generating AI summary: {str(e)}",
            "key_findings": ["Error occurred during AI analysis"],
            "recommendations": ["Check OpenAI API configuration and try again"]
        }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 