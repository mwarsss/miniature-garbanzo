"""
API Documentation

This module provides comprehensive API documentation for the Intelli-Scan backend.
All endpoints are automatically documented at /docs (Swagger UI) and /redoc (ReDoc).
"""

# API Endpoints Overview

## Health & Monitoring

### GET /health
Health check endpoint to verify API and database connectivity.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00Z",
  "database": "connected",
  "cache": "redis"
}
```

### GET /metrics
Get application performance metrics.

**Response:**
```json
{
  "counters": {
    "scans.total[status=completed]": 42,
    "scans.trivy.success": 40,
    "ai.analysis.total[status=success]": 38
  },
  "gauges": {},
  "histograms": {
    "scans.duration_ms": {
      "count": 42,
      "min": 15234,
      "max": 45678,
      "avg": 28456,
      "p50": 27000,
      "p95": 42000,
      "p99": 44000
    }
  }
}
```

## Scan Operations

### POST /scan
Initiate a new security scan for a repository.

**Request:**
```json
{
  "repo_url": "https://github.com/username/repository"
}
```

**Response (202 Accepted):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### GET /scan/{scan_id}
Get the status and results of a specific scan.

**Parameters:**
- `scan_id` (UUID): The scan identifier

**Response:**
```json
{
  "status": "completed",
  "result": {
    "sca": { ... },
    "sast": { ... },
    "ai_analysis": {
      "summary": "Found 3 critical vulnerabilities...",
      "top_vulnerabilities": [...]
    }
  }
}
```

### GET /scans
List all scans with pagination.

**Query Parameters:**
- `limit` (int, default=50): Number of scans to return

**Response:**
```json
[
  {
    "id": 1,
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "repo_url": "https://github.com/user/repo",
    "status": "completed",
    "submit_time": "2024-01-15T12:00:00Z",
    "finished_at": "2024-01-15T12:01:30Z"
  }
]
```

### GET /scan/{scan_id}/remediation
Get AI-generated remediation plan for a completed scan.

**Parameters:**
- `scan_id` (int): The scan database ID

**Response:**
```json
{
  "remediations": [
    {
      "issue": "SQL Injection in user input",
      "fix_code": "Use parameterized queries...",
      "explanation": "This prevents SQL injection by..."
    }
  ]
}
```

### GET /scan/{scan_uuid}/remediation-pdf
Download remediation plan as PDF.

**Parameters:**
- `scan_uuid` (UUID): The scan UUID

**Response:** PDF file download

## Policy Management

### POST /policies
Upload a security policy document.

**Request:**
- Content-Type: multipart/form-data
- file: PDF or TXT file

**Response:**
```json
{
  "status": "success",
  "filename": "security-policy.pdf",
  "chars_read": 15234
}
```

## Report Generation

### POST /reports/generate
Generate a report for a completed scan.

**Request:**
```json
{
  "scan_id": 1,
  "format": "markdown"
}
```

**Response:**
```json
{
  "report_content": "# Security Scan Report...",
  "filename": "report_scan_1_20240115_120000.md"
}
```

### GET /reports
List all generated reports.

**Query Parameters:**
- `limit` (int, default=50): Number of reports to return

**Response:**
```json
[
  {
    "id": 1,
    "scan_id": 1,
    "filename": "report_scan_1_20240115_120000.md",
    "format": "markdown",
    "generated_at": "2024-01-15T12:00:00Z"
  }
]
```

### GET /download/{report_id}
Download a generated report.

**Parameters:**
- `report_id` (int): The report ID

**Response:** File download

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
  "detail": "Invalid request parameters"
}
```

### 404 Not Found
```json
{
  "detail": "Scan ID not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error message"
}
```

### 503 Service Unavailable
```json
{
  "status": "unhealthy",
  "error": "Database connection failed"
}
```

## Rate Limiting

Currently, no rate limiting is implemented. This should be added before production deployment.

## Authentication

⚠️ **WARNING**: The current version has no authentication. Do not expose to public internet.

Recommended authentication methods for future implementation:
- JWT tokens
- API keys
- OAuth 2.0

## WebSocket Support (Future)

Planned WebSocket endpoint for real-time scan updates:

```
WS /ws/scan/{scan_id}
```

This will replace the current polling mechanism.
