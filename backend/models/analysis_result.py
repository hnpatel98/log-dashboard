import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from .log_entry import LogEntry

class AnalysisResult:
    """Represents the analysis result of a log file"""
    
    def __init__(self,
                 file_id: str,
                 original_filename: str,
                 total_logs: int,
                 log_entries: List[LogEntry],
                 threat_analysis: Dict[str, Any],
                 processed_at: datetime):
        self.file_id = file_id
        self.original_filename = original_filename
        self.total_logs = total_logs
        self.log_entries = log_entries
        self.threat_analysis = threat_analysis
        self.processed_at = processed_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {
            'file_id': self.file_id,
            'original_filename': self.original_filename,
            'total_logs': self.total_logs,
            'log_entries': [entry.to_dict() if hasattr(entry, 'to_dict') else entry for entry in self.log_entries],
            'threat_analysis': self.threat_analysis,
            'processed_at': self.processed_at.isoformat() if isinstance(self.processed_at, datetime) else str(self.processed_at)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisResult':
        """Create analysis result from dictionary"""
        processed_at = data.get('processed_at')
        if isinstance(processed_at, str):
            try:
                processed_at = datetime.fromisoformat(processed_at.replace('Z', '+00:00'))
            except ValueError:
                processed_at = datetime.now()

        # Robustly convert log_entries to LogEntry objects if needed
        log_entries = []
        for entry_data in data.get('log_entries', []):
            if isinstance(entry_data, dict):
                try:
                    from .log_entry import LogEntry
                    log_entries.append(LogEntry.from_dict(entry_data))
                except Exception:
                    log_entries.append(entry_data)
            else:
                log_entries.append(entry_data)

        return cls(
            file_id=data.get('file_id'),
            original_filename=data.get('original_filename'),
            total_logs=data.get('total_logs', 0),
            log_entries=log_entries,
            threat_analysis=data.get('threat_analysis', {}),
            processed_at=processed_at
        )
    
    def save(self) -> None:
        """Save analysis result to file"""
        import traceback
        os.makedirs('data', exist_ok=True)
        file_path = os.path.join('data', f"{self.file_id}.json")
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving analysis result to {file_path}: {e}")
            traceback.print_exc()
    
    @classmethod
    def load(cls, file_id: str) -> Optional['AnalysisResult']:
        """Load analysis result from file"""
        file_path = os.path.join('data', f"{file_id}.json")
        
        if not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error loading analysis result: {e}")
            return None
    
    @classmethod
    def get_all(cls) -> List['AnalysisResult']:
        """Get all analysis results"""
        results = []
        data_dir = 'data'
        
        if not os.path.exists(data_dir):
            return results
        
        for filename in os.listdir(data_dir):
            if filename.endswith('.json'):
                file_id = filename[:-5]  # Remove .json extension
                result = cls.load(file_id)
                if result:
                    results.append(result)
        
        # Sort by processed_at timestamp (newest first)
        results.sort(key=lambda x: x.processed_at, reverse=True)
        return results
    
    @classmethod
    def delete(cls, file_id: str) -> bool:
        """Delete analysis result"""
        file_path = os.path.join('data', f"{file_id}.json")
        
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                return True
            except OSError:
                return False
        return False
    
    def get_log_level_counts(self) -> Dict[str, int]:
        """Get count of logs by level"""
        counts = {'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DEBUG': 0}
        for entry in self.log_entries:
            level = entry.level.upper()
            if level in counts:
                counts[level] += 1
        return counts
    
    def get_time_range(self) -> Dict[str, str]:
        """Get time range of logs"""
        if not self.log_entries:
            return {'start': '', 'end': ''}
        
        timestamps = [entry.timestamp for entry in self.log_entries if entry.timestamp]
        if not timestamps:
            return {'start': '', 'end': ''}
        
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        return {
            'start': start_time.isoformat() if isinstance(start_time, datetime) else str(start_time),
            'end': end_time.isoformat() if isinstance(end_time, datetime) else str(end_time)
        }
    
    def __str__(self) -> str:
        return f"AnalysisResult(file_id={self.file_id}, filename={self.original_filename}, logs={self.total_logs})"
    
    def __repr__(self) -> str:
        return f"AnalysisResult(file_id='{self.file_id}', original_filename='{self.original_filename}', total_logs={self.total_logs})" 