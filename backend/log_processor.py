import re
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from models.log_entry import LogEntry

class LogProcessor:
    """Handles parsing and processing of log files"""
    
    def __init__(self):
        # Common timestamp patterns
        self.timestamp_patterns = [
            # ISO format: 2024-01-15T10:30:15
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)',
            # Standard format: 2024-01-15 10:30:15
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)',
            # US format: 01/15/2024 10:30:15
            r'(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?::\d{2})?)',
            # Unix timestamp
            r'(\d{10,13})',
        ]
        
        # Log level patterns
        self.level_patterns = [
            r'\b(ERROR|ERR)\b',
            r'\b(WARN|WARNING)\b',
            r'\b(INFO|INFORMATION)\b',
            r'\b(DEBUG|DBG)\b',
            r'\b(FATAL|CRITICAL)\b',
            r'\b(TRACE)\b'
        ]
        
        # Common log patterns for different frameworks
        self.log_patterns = {
            'standard': r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.+)$',
            'bracketed': r'^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]\s+(\w+)\s+(.+)$',
            'json': r'^\s*\{.*"timestamp".*"level".*"message".*\}\s*$',
            'apache': r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)$',
            'nginx': r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$'
        }
    
    def process_file(self, file_path: str) -> List[LogEntry]:
        """Process a log file and return list of log entries"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        log_entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = self.parse_line(line, line_number, os.path.basename(file_path))
                    if log_entry:
                        log_entries.append(log_entry)
        
        except UnicodeDecodeError:
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = self.parse_line(line, line_number, os.path.basename(file_path))
                    if log_entry:
                        log_entries.append(log_entry)
        
        return log_entries
    
    def parse_line(self, line: str, line_number: int, source: str) -> Optional[LogEntry]:
        """Parse a single log line"""
        # Try to match standard log patterns first
        for pattern_name, pattern in self.log_patterns.items():
            match = re.match(pattern, line)
            if match:
                return self._parse_with_pattern(pattern_name, match, line, line_number, source)
        
        # Fallback to generic parsing
        return self._parse_generic(line, line_number, source)
    
    def _parse_with_pattern(self, pattern_name: str, match: re.Match, line: str, line_number: int, source: str) -> Optional[LogEntry]:
        """Parse line using specific pattern"""
        try:
            if pattern_name == 'standard':
                timestamp_str, level, message = match.groups()
                timestamp = self._parse_timestamp(timestamp_str)
                return LogEntry(timestamp, level, message, source, line_number)
            
            elif pattern_name == 'bracketed':
                timestamp_str, level, message = match.groups()
                timestamp = self._parse_timestamp(timestamp_str)
                return LogEntry(timestamp, level, message, source, line_number)
            
            elif pattern_name == 'json':
                # Handle JSON logs
                return self._parse_json_log(line, line_number, source)
            
            elif pattern_name == 'apache':
                # Apache access log
                ip, _, _, timestamp_str, request, status, size = match.groups()
                timestamp = self._parse_timestamp(timestamp_str)
                level = 'INFO' if int(status) < 400 else 'WARN' if int(status) < 500 else 'ERROR'
                message = f"{ip} - {request} - {status} - {size}"
                return LogEntry(timestamp, level, message, source, line_number)
            
            elif pattern_name == 'nginx':
                # Nginx access log
                ip, timestamp_str, request, status, size, referer, user_agent = match.groups()
                timestamp = self._parse_timestamp(timestamp_str)
                level = 'INFO' if int(status) < 400 else 'WARN' if int(status) < 500 else 'ERROR'
                message = f"{ip} - {request} - {status} - {size}"
                return LogEntry(timestamp, level, message, source, line_number)
        
        except (ValueError, IndexError) as e:
            print(f"Error parsing line with pattern {pattern_name}: {e}")
        
        return None
    
    def _parse_generic(self, line: str, line_number: int, source: str) -> LogEntry:
        """Generic parsing for unknown log formats"""
        # Extract timestamp
        timestamp = self._extract_timestamp(line)
        
        # Extract log level
        level = self._extract_level(line)
        
        # Use the entire line as message if no specific pattern matched
        message = line
        
        return LogEntry(timestamp, level, message, source, line_number)
    
    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line"""
        for pattern in self.timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                parsed_timestamp = self._parse_timestamp(timestamp_str)
                if parsed_timestamp:
                    return parsed_timestamp
        
        # Return current time if no timestamp found
        return datetime.now()
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        try:
            # Try ISO format
            if 'T' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            
            # Try standard format
            if re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', timestamp_str):
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            
            # Try US format
            if re.match(r'\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}', timestamp_str):
                return datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
            
            # Try Unix timestamp
            if timestamp_str.isdigit():
                if len(timestamp_str) == 10:  # seconds
                    return datetime.fromtimestamp(int(timestamp_str))
                elif len(timestamp_str) == 13:  # milliseconds
                    return datetime.fromtimestamp(int(timestamp_str) / 1000)
        
        except (ValueError, OSError) as e:
            print(f"Error parsing timestamp '{timestamp_str}': {e}")
        
        return None
    
    def _extract_level(self, line: str) -> str:
        """Extract log level from log line"""
        line_upper = line.upper()
        
        for pattern in self.level_patterns:
            match = re.search(pattern, line_upper)
            if match:
                level = match.group(1)
                # Normalize level names
                level_mapping = {
                    'ERR': 'ERROR',
                    'WARNING': 'WARN',
                    'INFORMATION': 'INFO',
                    'DBG': 'DEBUG',
                    'FATAL': 'ERROR',
                    'CRITICAL': 'ERROR'
                }
                return level_mapping.get(level, level)
        
        # Default to INFO if no level found
        return 'INFO'
    
    def _parse_json_log(self, line: str, line_number: int, source: str) -> Optional[LogEntry]:
        """Parse JSON formatted log entry"""
        try:
            import json
            data = json.loads(line)
            
            timestamp = self._parse_timestamp(data.get('timestamp', '')) or datetime.now()
            level = data.get('level', 'INFO')
            message = data.get('message', line)
            
            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=source,
                line_number=line_number,
                additional_data=data
            )
        
        except json.JSONDecodeError:
            # If JSON parsing fails, treat as regular log
            return self._parse_generic(line, line_number, source)
    
    def get_statistics(self, log_entries: List[LogEntry]) -> Dict[str, Any]:
        """Get statistics from log entries"""
        if not log_entries:
            return {}
        
        # Count by level
        level_counts = {'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DEBUG': 0, 'TRACE': 0}
        for entry in log_entries:
            level = entry.level.upper()
            if level in level_counts:
                level_counts[level] += 1
        
        # Time range
        timestamps = [entry.timestamp for entry in log_entries if entry.timestamp]
        time_range = {}
        if timestamps:
            time_range = {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat()
            }
        
        # Sources
        sources = list(set(entry.source for entry in log_entries if entry.source))
        
        return {
            'total_entries': len(log_entries),
            'level_counts': level_counts,
            'time_range': time_range,
            'sources': sources,
            'error_rate': level_counts['ERROR'] / len(log_entries) if log_entries else 0
        } 