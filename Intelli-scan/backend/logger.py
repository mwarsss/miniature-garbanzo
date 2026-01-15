"""
Structured logging configuration for better observability.
"""
import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "scan_id"):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, "repo_url"):
            log_data["repo_url"] = record.repo_url
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
        if hasattr(record, "error_code"):
            log_data["error_code"] = record.error_code
            
        return json.dumps(log_data)


def setup_logging(log_level: str = "INFO", structured: bool = True):
    """Configure application logging."""
    
    # Remove existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    if structured:
        console_handler.setFormatter(StructuredFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        )
    
    root_logger.addHandler(console_handler)
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    return root_logger


# Convenience function for adding context to logs
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)
