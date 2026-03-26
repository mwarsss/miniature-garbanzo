"""
Unit tests for error handlers module.
"""
import pytest
from error_handlers import (
    ScanError,
    ScannerError,
    AIAnalysisError,
    CircuitBreaker,
    retry_on_failure,
    handle_errors
)
import time


def test_circuit_breaker_closed_state():
    """Test circuit breaker in closed state."""
    cb = CircuitBreaker(failure_threshold=3, timeout=1)
    
    def successful_function():
        return "success"
    
    result = cb.call(successful_function)
    assert result == "success"
    assert cb.state == "closed"


def test_circuit_breaker_opens_after_failures():
    """Test circuit breaker opens after threshold failures."""
    cb = CircuitBreaker(failure_threshold=3, timeout=1)
    
    def failing_function():
        raise Exception("Test failure")
    
    # Fail 3 times to open circuit
    for _ in range(3):
        with pytest.raises(Exception):
            cb.call(failing_function)
    
    assert cb.state == "open"
    
    # Next call should fail immediately
    with pytest.raises(Exception, match="Circuit breaker is OPEN"):
        cb.call(failing_function)


def test_circuit_breaker_half_open_recovery():
    """Test circuit breaker recovery through half-open state."""
    cb = CircuitBreaker(failure_threshold=2, timeout=1)
    
    def failing_function():
        raise Exception("Test failure")
    
    def successful_function():
        return "success"
    
    # Open the circuit
    for _ in range(2):
        with pytest.raises(Exception):
            cb.call(failing_function)
    
    assert cb.state == "open"
    
    # Wait for timeout
    time.sleep(1.1)
    
    # Should enter half-open state and succeed
    result = cb.call(successful_function)
    assert result == "success"
    assert cb.state == "closed"


@pytest.mark.asyncio
async def test_circuit_breaker_async_call():
    """Test circuit breaker async_call method."""
    cb = CircuitBreaker(failure_threshold=3, timeout=1)
    
    async def successful_async_function():
        return "success"
    
    result = await cb.async_call(successful_async_function)
    assert result == "success"
    assert cb.state == "closed"


@pytest.mark.asyncio
async def test_circuit_breaker_async_opens_after_failures():
    """Test circuit breaker opens after threshold failures using async calls."""
    cb = CircuitBreaker(failure_threshold=2, timeout=1)
    
    async def failing_async_function():
        raise Exception("Test failure")
    
    # Fail 2 times to open circuit
    for _ in range(2):
        with pytest.raises(Exception):
            await cb.async_call(failing_async_function)
    
    assert cb.state == "open"
    
    # Next call should fail immediately
    with pytest.raises(Exception, match="Circuit breaker is OPEN"):
        await cb.async_call(failing_async_function)


def test_retry_decorator_success():
    """Test retry decorator with successful function."""
    call_count = 0
    
    @retry_on_failure(max_attempts=3)
    def sometimes_failing_function():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise Exception("Temporary failure")
        return "success"
    
    result = sometimes_failing_function()
    assert result == "success"
    assert call_count == 2


def test_retry_decorator_max_attempts():
    """Test retry decorator exhausts max attempts."""
    call_count = 0
    
    @retry_on_failure(max_attempts=3, min_wait=0, max_wait=0)
    def always_failing_function():
        nonlocal call_count
        call_count += 1
        raise Exception("Always fails")
    
    with pytest.raises(Exception, match="Always fails"):
        always_failing_function()
    
    assert call_count == 3


@pytest.mark.asyncio
async def test_handle_errors_async():
    """Test error handler decorator with async function."""
    
    @handle_errors
    async def async_function_with_error():
        raise ValueError("Test error")
    
    with pytest.raises(ValueError):
        await async_function_with_error()


def test_handle_errors_sync():
    """Test error handler decorator with sync function."""
    
    @handle_errors
    def sync_function_with_error():
        raise ValueError("Test error")
    
    with pytest.raises(ValueError):
        sync_function_with_error()


def test_custom_exceptions():
    """Test custom exception classes."""
    with pytest.raises(ScanError):
        raise ScanError("Scan failed")
    
    with pytest.raises(ScannerError):
        raise ScannerError("Scanner failed")
    
    with pytest.raises(AIAnalysisError):
        raise AIAnalysisError("AI analysis failed")
    
    # ScannerError and AIAnalysisError should be subclasses of ScanError
    assert issubclass(ScannerError, ScanError)
    assert issubclass(AIAnalysisError, ScanError)
