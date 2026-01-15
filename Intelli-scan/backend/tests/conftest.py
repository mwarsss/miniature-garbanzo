"""
Pytest configuration and shared fixtures.
"""
import pytest
import os


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    # os.environ["DATABASE_URL"] = "postgresql://test:test@localhost/test_db"
    os.environ["GOOGLE_API_KEY"] = "test_api_key"
    os.environ["TESTING"] = "true"


@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        "sca": {
            "Results": [{
                "Target": "package.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.20",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Command Injection in lodash"
                    }
                ]
            }]
        },
        "sast": {
            "results": [
                {
                    "check_id": "javascript.lang.security.eval-use",
                    "path": "app/utils.js",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Use of eval is dangerous",
                        "severity": "ERROR"
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_ai_analysis():
    """Sample AI analysis response."""
    return {
        "summary": "Found 2 critical vulnerabilities requiring immediate attention.",
        "top_vulnerabilities": [
            {
                "name": "Command Injection in lodash",
                "severity": "HIGH",
                "file": "package.json",
                "poc": "Attacker can inject commands via template strings"
            }
        ]
    }
