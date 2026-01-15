"""
Unit tests for cache module.
"""
import pytest
from cache import InMemoryCache, CacheManager, generate_cache_key


def test_in_memory_cache_set_get():
    """Test basic cache set and get operations."""
    cache = InMemoryCache(ttl_seconds=60)
    
    cache.set("test_key", "test_value")
    assert cache.get("test_key") == "test_value"


def test_in_memory_cache_expiration():
    """Test cache expiration."""
    import time
    cache = InMemoryCache(ttl_seconds=1)
    
    cache.set("test_key", "test_value")
    assert cache.get("test_key") == "test_value"
    
    time.sleep(1.1)
    assert cache.get("test_key") is None


def test_in_memory_cache_miss():
    """Test cache miss."""
    cache = InMemoryCache()
    assert cache.get("nonexistent_key") is None


def test_in_memory_cache_delete():
    """Test cache deletion."""
    cache = InMemoryCache()
    
    cache.set("test_key", "test_value")
    assert cache.get("test_key") == "test_value"
    
    cache.delete("test_key")
    assert cache.get("test_key") is None


def test_in_memory_cache_clear():
    """Test clearing all cache."""
    cache = InMemoryCache()
    
    cache.set("key1", "value1")
    cache.set("key2", "value2")
    
    cache.clear()
    
    assert cache.get("key1") is None
    assert cache.get("key2") is None


def test_generate_cache_key():
    """Test cache key generation."""
    key1 = generate_cache_key("https://github.com/user/repo")
    key2 = generate_cache_key("https://github.com/user/repo")
    key3 = generate_cache_key("https://github.com/user/other-repo")
    
    # Same URL should generate same key
    assert key1 == key2
    
    # Different URL should generate different key
    assert key1 != key3
    
    # Key should have correct prefix
    assert key1.startswith("scan:")


def test_cache_manager_fallback():
    """Test CacheManager with fallback to in-memory cache."""
    # This will use in-memory cache since Redis is not available in tests
    cache = CacheManager(ttl_seconds=60)
    
    cache.set("test_key", {"data": "test_value"})
    result = cache.get("test_key")
    
    assert result == {"data": "test_value"}


def test_cache_manager_with_ttl():
    """Test CacheManager with custom TTL."""
    cache = CacheManager(ttl_seconds=60)
    
    cache.set("test_key", "test_value", ttl=120)
    assert cache.get("test_key") == "test_value"
