"""
Application metrics and monitoring.
"""
import time
from typing import Dict, Any
from collections import defaultdict
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Simple metrics collector for monitoring application performance."""
    
    def __init__(self):
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(list)
        self.timers = {}
    
    def increment(self, metric_name: str, value: int = 1, tags: Dict[str, str] = None):
        """Increment a counter metric."""
        key = self._make_key(metric_name, tags)
        self.counters[key] += value
        logger.debug(f"Metric counter: {key} += {value}")
    
    def gauge(self, metric_name: str, value: float, tags: Dict[str, str] = None):
        """Set a gauge metric."""
        key = self._make_key(metric_name, tags)
        self.gauges[key] = value
        logger.debug(f"Metric gauge: {key} = {value}")
    
    def histogram(self, metric_name: str, value: float, tags: Dict[str, str] = None):
        """Record a histogram value."""
        key = self._make_key(metric_name, tags)
        self.histograms[key].append(value)
        logger.debug(f"Metric histogram: {key} <- {value}")
    
    @contextmanager
    def timer(self, metric_name: str, tags: Dict[str, str] = None):
        """Context manager for timing operations."""
        start_time = time.time()
        try:
            yield
        finally:
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            self.histogram(f"{metric_name}.duration_ms", duration, tags)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics statistics."""
        stats = {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {}
        }
        
        # Calculate histogram statistics
        for key, values in self.histograms.items():
            if values:
                stats["histograms"][key] = {
                    "count": len(values),
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                    "p50": self._percentile(values, 50),
                    "p95": self._percentile(values, 95),
                    "p99": self._percentile(values, 99),
                }
        
        return stats
    
    def reset(self):
        """Reset all metrics."""
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()
        logger.info("Metrics reset")
    
    @staticmethod
    def _make_key(metric_name: str, tags: Dict[str, str] = None) -> str:
        """Create a metric key with tags."""
        if not tags:
            return metric_name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{metric_name}[{tag_str}]"
    
    @staticmethod
    def _percentile(values: list, percentile: int) -> float:
        """Calculate percentile value."""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]


# Global metrics instance
metrics = MetricsCollector()


def track_scan_metrics(scan_id: str, status: str, duration_ms: float = None):
    """Track scan-related metrics."""
    metrics.increment("scans.total", tags={"status": status})
    
    if duration_ms:
        metrics.histogram("scans.duration_ms", duration_ms, tags={"status": status})
    
    logger.info(
        "Scan metrics tracked",
        extra={
            "scan_id": scan_id,
            "status": status,
            "duration_ms": duration_ms
        }
    )


def track_ai_metrics(operation: str, success: bool, duration_ms: float):
    """Track AI operation metrics."""
    status = "success" if success else "failure"
    metrics.increment(f"ai.{operation}.total", tags={"status": status})
    metrics.histogram(f"ai.{operation}.duration_ms", duration_ms, tags={"status": status})
