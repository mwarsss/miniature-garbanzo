"""
API endpoint tests.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
import json


@pytest.fixture
def mock_db_pool():
    """Mock database pool."""
    with patch('main.db_pool') as mock:
        yield mock


@pytest.fixture
def client(mock_db_pool): # helper to ensure pool is mocked
    """Test client fixture."""
    from main import app
    return TestClient(app)


def test_health_check(client, mock_db_pool):
    """Test health check endpoint."""
    # Mock get_cursor for health check
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "cache" in data


def test_start_scan_missing_repo_url(client, mock_db_pool):
    """Test scan endpoint with missing repo URL."""
    response = client.post("/scan", json={})
    assert response.status_code == 422  # Validation error


def test_start_scan_success(client, mock_db_pool):
    """Test successful scan initiation."""
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    
    response = client.post(
        "/scan",
        json={"repo_url": "https://github.com/test/repo"}
    )
    
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


def test_list_scans(client, mock_db_pool):
    """Test listing scans."""
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    
    mock_cursor.fetchall.return_value = []
    
    response = client.get("/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_metrics_endpoint(client):
    """Test metrics endpoint."""
    response = client.get("/metrics")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_scan_status_not_found(client, mock_db_pool):
    """Test scan status for non-existent scan."""
    import uuid
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    
    mock_cursor.fetchone.return_value = None
    
    fake_uuid = str(uuid.uuid4())
    response = client.get(f"/scan/{fake_uuid}")
    assert response.status_code == 404