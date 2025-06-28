from datetime import datetime
from typing import Optional, Dict, Any

class LogEntry:
    """Represents a single log entry"""
    
    def __init__(self, 
                 timestamp: datetime,
                 level: str,
                 message: str,
                 source: Optional[str] = None,
                 line_number: Optional[int] = None,
                 additional_data: Optional[Dict[str, Any]] = None):
        self.timestamp = timestamp
        self.level = level.upper()
        self.message = message
        self.source = source
        self.line_number = line_number
        self.additional_data = additional_data or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            'level': self.level,
            'message': self.message,
            'source': self.source,
            'line_number': self.line_number,
            'additional_data': self.additional_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """Create log entry from dictionary"""
        timestamp = data.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                timestamp = datetime.now()
        
        return cls(
            timestamp=timestamp,
            level=data.get('level', 'INFO'),
            message=data.get('message', ''),
            source=data.get('source'),
            line_number=data.get('line_number'),
            additional_data=data.get('additional_data', {})
        )
    
    def __str__(self) -> str:
        return f"[{self.timestamp}] {self.level}: {self.message}"
    
    def __repr__(self) -> str:
        return f"LogEntry(timestamp={self.timestamp}, level='{self.level}', message='{self.message[:50]}...')" 