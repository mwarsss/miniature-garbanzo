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


def test_remediation_scan_not_found(client, mock_db_pool):
    """Test remediation endpoint with non-existent scan."""
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = None
    
    response = client.get("/scan/999/remediation")
    assert response.status_code == 404


def test_remediation_scan_not_completed(client, mock_db_pool):
    """Test remediation endpoint with incomplete scan."""
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = {
        'status': 'processing',
        'sca_result': {},
        'sast_result': {}
    }
    
    response = client.get("/scan/1/remediation")
    assert response.status_code == 400
    assert "not completed" in response.json()["detail"].lower()


@patch('main.model')
@patch('main._perform_ai_remediation')
def test_remediation_success(mock_remediation, mock_model, client, mock_db_pool):
    """Test successful remediation generation."""
    # Mock database
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = {
        'status': 'completed',
        'sca_result': {'Results': []},
        'sast_result': {'results': []}
    }
    
    # Mock AI remediation
    from main import RemediationResult, RemediationDetail
    mock_remediation.return_value = RemediationResult(
        remediations=[
            RemediationDetail(
                issue="SQL Injection",
                fix_code="Use parameterized queries",
                explanation="Prevents SQL injection attacks"
            )
        ]
    )
    
    response = client.get("/scan/1/remediation")
    assert response.status_code == 200
    data = response.json()
    assert "remediations" in data
    assert len(data["remediations"]) == 1
    assert data["remediations"][0]["issue"] == "SQL Injection"


def test_remediation_invalid_scan_id(client, mock_db_pool):
    """Test remediation endpoint with invalid scan ID format."""
    response = client.get("/scan/invalid/remediation")
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()