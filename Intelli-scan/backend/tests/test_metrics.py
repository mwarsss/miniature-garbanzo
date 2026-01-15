"""
Unit tests for metrics module.
"""
import pytest
from metrics import MetricsCollector, track_scan_metrics, track_ai_metrics


def test_metrics_counter_increment():
    """Test counter increment."""
    metrics = MetricsCollector()
    
    metrics.increment("test.counter")
    metrics.increment("test.counter")
    metrics.increment("test.counter", value=3)
    
    stats = metrics.get_stats()
    assert stats["counters"]["test.counter"] == 5


def test_metrics_counter_with_tags():
    """Test counter with tags."""
    metrics = MetricsCollector()
    
    metrics.increment("requests", tags={"status": "success"})
    metrics.increment("requests", tags={"status": "failure"})
    metrics.increment("requests", tags={"status": "success"})
    
    stats = metrics.get_stats()
    assert stats["counters"]["requests[status=success]"] == 2
    assert stats["counters"]["requests[status=failure]"] == 1


def test_metrics_gauge():
    """Test gauge metric."""
    metrics = MetricsCollector()
    
    metrics.gauge("cpu.usage", 45.5)
    metrics.gauge("cpu.usage", 67.8)
    
    stats = metrics.get_stats()
    # Gauge should show latest value
    assert stats["gauges"]["cpu.usage"] == 67.8


def test_metrics_histogram():
    """Test histogram metric."""
    metrics = MetricsCollector()
    
    values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    for value in values:
        metrics.histogram("response.time", value)
    
    stats = metrics.get_stats()
    histogram = stats["histograms"]["response.time"]
    
    assert histogram["count"] == 10
    assert histogram["min"] == 10
    assert histogram["max"] == 100
    assert histogram["avg"] == 55


def test_metrics_timer():
    """Test timer context manager."""
    import time
    metrics = MetricsCollector()
    
    with metrics.timer("operation"):
        time.sleep(0.1)
    
    stats = metrics.get_stats()
    histogram = stats["histograms"]["operation.duration_ms"]
    
    assert histogram["count"] == 1
    assert histogram["min"] >= 100  # At least 100ms


def test_metrics_reset():
    """Test metrics reset."""
    metrics = MetricsCollector()
    
    metrics.increment("test.counter")
    metrics.gauge("test.gauge", 42)
    metrics.histogram("test.histogram", 100)
    
    metrics.reset()
    
    stats = metrics.get_stats()
    assert len(stats["counters"]) == 0
    assert len(stats["gauges"]) == 0
    assert len(stats["histograms"]) == 0


def test_track_scan_metrics():
    """Test scan metrics tracking."""
    from metrics import metrics
    
    metrics.reset()
    track_scan_metrics("scan-123", "completed", 1500.0)
    
    stats = metrics.get_stats()
    assert stats["counters"]["scans.total[status=completed]"] == 1


def test_track_ai_metrics():
    """Test AI metrics tracking."""
    from metrics import metrics
    
    metrics.reset()
    track_ai_metrics("analysis", True, 2500.0)
    track_ai_metrics("analysis", False, 3000.0)
    
    stats = metrics.get_stats()
    assert stats["counters"]["ai.analysis.total[status=success]"] == 1
    assert stats["counters"]["ai.analysis.total[status=failure]"] == 1
