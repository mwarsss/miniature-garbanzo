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
    mock_cursor.fetchone.return_value = {"id": 1}
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


@patch('main.run_remediation_pipeline')
def test_remediation_success(mock_pipeline, client, mock_db_pool):
    """Test successful agentic remediation pipeline returns per-finding list."""
    mock_cursor = Mock()
    mock_db_pool.get_cursor.return_value.__enter__.return_value = mock_cursor
    mock_cursor.fetchone.return_value = {
        'status': 'completed',
        'sca_result': {'Results': []},
        'sast_result': {'results': [
            {
                'check_id': 'python.lang.security.sqli',
                'path': 'src/db.py',
                'start': {'line': 10},
                'end': {'line': 10},
                'extra': {'message': 'SQL injection', 'severity': 'HIGH'},
            }
        ]},
        'repo_url': 'https://github.com/test/repo',
    }
    mock_pipeline.return_value = [
        {
            'finding_id': 'python.lang.security.sqli::src/db.py:10',
            'file_path': 'src/db.py',
            'vuln_type': 'sql-injection',
            'priority_score': 80,
            'skipped': False,
            'patched_code': 'cursor.execute(q, (val,))',
            'explanation': 'Use parameterized query.',
            'ris_score': 0.85,
            'verdict': 'AUTO_APPLY',
            'basic_ris': 0.72,
            'new_findings_introduced': [],
            'validation_passed': True,
            'diff_summary': None,
            'dual_scan_result': None,
            'ris_breakdown': None,
            'rigorous_ris': False,
        }
    ]

    response = client.get("/scan/1/remediation")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['finding_id'] == 'python.lang.security.sqli::src/db.py:10'
    assert data[0]['verdict'] == 'AUTO_APPLY'
    assert data[0]['ris_score'] == 0.85


def test_remediation_invalid_scan_id(client, mock_db_pool):
    """Test remediation endpoint with invalid scan ID format."""
    response = client.get("/scan/invalid/remediation")
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()