"""
Configuration management using Pydantic Settings for validation and type safety.
"""
from pydantic_settings import BaseSettings
from typing import Optional
import logging


class Settings(BaseSettings):
    """Application settings with validation."""
    
    # Database
    database_url: str
    
    # API Keys
    google_api_key: str
    
    # Scanner Paths
    trivy_path: str = "trivy"
    semgrep_path: str = "semgrep"
    
    # Scan Configuration
    scan_timeout_minutes: int = 15
    max_concurrent_scans: int = 5
    
    # AI Configuration
    ai_model_name: str = "gemini-2.0-flash-exp"
    ai_max_retries: int = 3
    ai_retry_delay_seconds: int = 2
    
    # Performance
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    
    # Monitoring
    enable_structured_logging: bool = True
    log_level: str = "INFO"
    
    # CORS
    cors_origins: list[str] = ["*"]
    
    # Pagination
    default_page_size: int = 50
    max_page_size: int = 100
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


def get_settings() -> Settings:
    """Get validated settings instance."""
    try:
        settings = Settings()
        logging.info("✅ Configuration loaded and validated successfully")
        return settings
    except Exception as e:
        logging.error(f"❌ Configuration validation failed: {e}")
        raise


# Global settings instance
settings = get_settings()
