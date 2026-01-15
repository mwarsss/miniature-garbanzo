"""
Caching layer for scan results and AI analysis.
"""
import json
import hashlib
from typing import Optional, Any
import logging

logger = logging.getLogger(__name__)


class InMemoryCache:
    """Simple in-memory cache implementation (fallback when Redis is unavailable)."""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key in self.cache:
            data, timestamp = self.cache[key]
            import time
            if time.time() - timestamp < self.ttl:
                logger.debug(f"Cache HIT: {key}")
                return data
            else:
                del self.cache[key]
                logger.debug(f"Cache EXPIRED: {key}")
        logger.debug(f"Cache MISS: {key}")
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache."""
        import time
        self.cache[key] = (value, time.time())
        logger.debug(f"Cache SET: {key}")
    
    def delete(self, key: str):
        """Delete value from cache."""
        if key in self.cache:
            del self.cache[key]
            logger.debug(f"Cache DELETE: {key}")
    
    def clear(self):
        """Clear all cache."""
        self.cache.clear()
        logger.info("Cache cleared")


def generate_cache_key(repo_url: str, scan_type: str = "full") -> str:
    """Generate a consistent cache key for a repository scan."""
    key_string = f"{repo_url}:{scan_type}"
    return f"scan:{hashlib.sha256(key_string.encode()).hexdigest()}"


class CacheManager:
    """Unified cache manager with fallback support."""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self.redis_client = None
        self.fallback_cache = InMemoryCache(ttl_seconds)
        
        # Try to connect to Redis if available
        try:
            import redis
            # Try to connect to Redis (will use env var REDIS_URL if available)
            import os
            redis_url = os.getenv("REDIS_URL")
            if redis_url:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("✅ Connected to Redis cache")
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory cache: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache (Redis or fallback)."""
        if self.redis_client:
            try:
                value = self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis GET error: {e}")
        
        return self.fallback_cache.get(key)
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache (Redis or fallback)."""
        ttl = ttl or self.ttl
        
        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl, json.dumps(value))
                return
            except Exception as e:
                logger.error(f"Redis SET error: {e}")
        
        self.fallback_cache.set(key, value, ttl)
    
    def delete(self, key: str):
        """Delete value from cache."""
        if self.redis_client:
            try:
                self.redis_client.delete(key)
                return
            except Exception as e:
                logger.error(f"Redis DELETE error: {e}")
        
        self.fallback_cache.delete(key)
    
    def clear(self):
        """Clear all cache."""
        if self.redis_client:
            try:
                self.redis_client.flushdb()
                logger.info("Redis cache cleared")
                return
            except Exception as e:
                logger.error(f"Redis CLEAR error: {e}")
        
        self.fallback_cache.clear()


# Global cache instance
cache = None


def get_cache(ttl_seconds: int = 3600) -> CacheManager:
    """Get or create global cache instance."""
    global cache
    if cache is None:
        cache = CacheManager(ttl_seconds)
    return cache
