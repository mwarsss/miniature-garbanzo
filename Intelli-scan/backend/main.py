import subprocess
import tempfile
import json
import os
import shutil
import time
import asyncio
import hmac
import hashlib
from starlette.concurrency import run_in_threadpool
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Request
from fastapi.responses import Response, StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from git import Repo, GitCommandError
from typing import Dict, List, Optional
import uuid
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
import datetime
from pypdf import PdfReader
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from psycopg2.extras import RealDictCursor

# Import new modules
from config import settings
from logger import setup_logging, get_logger
from database import DatabasePool, create_tables
from error_handlers import (
    retry_on_failure,
    handle_errors,
    ScanError,
    ScannerError,
    AIAnalysisError,
    gemini_circuit_breaker
)
from cache import get_cache, generate_cache_key
from metrics import metrics, track_scan_metrics, track_ai_metrics
from agents.remediation_agent import run_remediation_pipeline

# --- Setup Logging ---
setup_logging(settings.log_level, settings.enable_structured_logging)
logger = get_logger(__name__)

# --- Initialize Database Pool ---
db_pool = DatabasePool(settings.database_url, min_conn=2, max_conn=10)

# --- Initialize Cache ---
cache = get_cache(settings.cache_ttl_seconds)

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Intelli-Scan API",
    description="AI-Augmented SAST Agent for intelligent vulnerability analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

@app.get("/health")
def health_check():
    """Health check endpoint."""
    try:
        # Check database connectivity
        with db_pool.get_cursor() as cur:
            cur.execute("SELECT 1")
        
        return {
            "status": "healthy",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "database": "connected",
            "cache": "redis" if cache.redis_client else "memory"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Google Generative AI Configuration ---
# Pre-create one model instance per API key to avoid race conditions.
# genai.configure() sets a global key, which is unsafe in async contexts
# where concurrent requests could overwrite each other's configured key.
ai_models: list[genai.GenerativeModel] = []
if settings.google_api_keys:
    model_name = settings.ai_model_name
    for key in settings.google_api_keys:
        genai.configure(api_key=key)
        ai_models.append(genai.GenerativeModel(model_name))
    logger.info(f"✅ Gemini AI configured with {len(ai_models)} model instances and model: {model_name}")
else:
    logger.warning("⚠️ GOOGLE_API_KEY not set. AI features will be disabled.")
    model_name = None

# --- Pydantic Models ---
class Vulnerability(BaseModel):
    name: str
    severity: str
    file: str
    poc: str

class AIAnalysisResult(BaseModel):
    summary: str
    top_vulnerabilities: List[Vulnerability]

class RemediationDetail(BaseModel):
    issue: str
    fix_code: str
    explanation: str

class LegacyRemediationResult(BaseModel):
    """Legacy one-shot remediation result — used by /trivy_remediation endpoint."""
    remediations: List[RemediationDetail]

class RemediationResult(BaseModel):
    """Per-finding result from the agentic remediation pipeline."""
    finding_id: str
    file_path: str
    vuln_type: str
    priority_score: int
    skipped: bool
    patched_code: Optional[str] = None
    explanation: Optional[str] = None
    ris_score: Optional[float] = None
    verdict: str
    new_findings_introduced: List = []
    validation_passed: Optional[bool] = None
    basic_ris: Optional[float] = None
    diff_summary: Optional[dict] = None
    dual_scan_result: Optional[dict] = None
    ris_breakdown: Optional[dict] = None
    rigorous_ris: bool = False

class ScanRequest(BaseModel):
    repo_url: str

class ScanResultData(BaseModel):
    sca: Optional[Dict] = None
    sast: Optional[Dict] = None
    ai_analysis: Optional[AIAnalysisResult] = None

class ScanStatus(BaseModel):
    status: str
    message: Optional[str] = None
    result: Optional[ScanResultData] = None

class ReportRequest(BaseModel):
    scan_id: int
    format: str = Field("markdown", description="The desired report format.")

class ReportResponse(BaseModel):
    report_content: str
    filename: str

class ReportInfo(BaseModel):
    id: int
    scan_id: int
    filename: str
    format: str
    generated_at: datetime.datetime


class ScanSummary(BaseModel):
    id: int
    uuid: uuid.UUID
    repo_url: str
    status: str
    submit_time: datetime.datetime
    finished_at: Optional[datetime.datetime] = None


class Scan(BaseModel):
    id: int
    uuid: uuid.UUID
    repo_url: str
    status: str
    submit_time: datetime.datetime
    finished_at: Optional[datetime.datetime] = None

# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 (2021) mapping
# ─────────────────────────────────────────────────────────────────────────────

OWASP_TOP10_2021: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

_VULN_TO_OWASP: dict[str, str] = {
    "sql-injection": "A03",
    "sqli": "A03",
    "command-injection": "A03",
    "code-injection": "A03",
    "xss": "A03",
    "xxe": "A03",
    "ldap-injection": "A03",
    "path-traversal": "A01",
    "directory-traversal": "A01",
    "broken-access-control": "A01",
    "csrf": "A01",
    "open-redirect": "A01",
    "idor": "A01",
    "hardcoded-secret": "A02",
    "hardcoded-password": "A07",
    "weak-crypto": "A02",
    "insecure-tls": "A02",
    "sensitive-data-exposure": "A02",
    "ssrf": "A10",
    "server-side-request-forgery": "A10",
    "missing-auth": "A07",
    "broken-authentication": "A07",
    "insecure-deserialization": "A08",
    "prototype-pollution": "A08",
    "supply-chain": "A06",
    "outdated-dependency": "A06",
    "security-misconfiguration": "A05",
    "debug-enabled": "A05",
    "missing-security-header": "A05",
}


def _map_to_owasp(vuln_type: str, check_id: str = "") -> Optional[str]:
    """Return OWASP Top 10 category code for a given vuln type or check_id."""
    combined = f"{vuln_type} {check_id}".lower()
    for keyword, code in _VULN_TO_OWASP.items():
        if keyword in combined:
            return code
    return None


def _extract_cvss_cve_summary(sca_result: dict) -> list[dict]:
    """
    Pull CVE IDs, CVSS v3 scores, severity, and fix version from Trivy SCA JSON.
    Returns list sorted by CVSS score descending.
    """
    entries: list[dict] = []
    for target in sca_result.get("Results", []):
        for vuln in target.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id:
                continue
            cvss_score: Optional[float] = None
            for _source, scores in (vuln.get("CVSS") or {}).items():
                v3 = scores.get("V3Score")
                if v3 is not None:
                    cvss_score = float(v3)
                    break
            entries.append({
                "cve_id": cve_id,
                "package": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", "—"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "cvss_score": cvss_score,
                "title": vuln.get("Title", ""),
                "owasp": "A06 — Vulnerable and Outdated Components",
            })
    return sorted(entries, key=lambda x: (x.get("cvss_score") or 0), reverse=True)


def _log_audit_event(entity_type: str, entity_id: int, action: str, changes: Optional[dict] = None) -> None:
    """Write a row to audit_logs. Silently swallows errors to never block the main flow."""
    try:
        with db_pool.get_cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs (entity_type, entity_id, action, changes) VALUES (%s, %s, %s, %s)",
                (entity_type, entity_id, action, json.dumps(changes) if changes else None),
            )
    except Exception as audit_err:
        logger.warning(f"Audit log write failed (non-fatal): {audit_err}")


# ─────────────────────────────────────────────────────────────────────────────
# Database Table Creation (on startup)
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup_event():
    """Initialize database tables and log startup info."""
    logger.info("🚀 Starting Intelli-Scan API...")
    logger.info(f"📊 Configuration: cache={settings.enable_caching}, log_level={settings.log_level}")
    
    try:
        create_tables(settings.database_url)
        logger.info("✅ Database tables initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        raise

@app.on_event("shutdown")
def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("🛑 Shutting down Intelli-Scan API...")
    db_pool.close_all()
    logger.info("✅ Cleanup complete")

# --- Metrics Endpoint ---
@app.get("/metrics")
def get_metrics():
    """Get application metrics."""
    return metrics.get_stats()

# --- AI Helper Functions ---
def get_policy_context() -> str:
    """Retrieves all policy documents from the database to form a context string."""
    try:
        with db_pool.get_cursor() as cur:
            cur.execute("SELECT filename, content FROM policy_documents ORDER BY uploaded_at DESC")
            policies = cur.fetchall()
        
        if not policies:
            return "No security policies provided."

        context = "### Internal Security Policies ###\n\n"
        for policy in policies:
            context += f"--- Document: {policy['filename']} ---\n"
            context += f"{policy['content']}\n\n"
        return context[:15000] # Limit to 15,000 chars to avoid hitting token limits
    except Exception as e:
        logger.error(f"Could not retrieve policy context: {e}")
        return "Error retrieving security policies."

@retry_on_failure(max_attempts=settings.ai_max_retries)
@handle_errors
async def _perform_ai_analysis(sca_result: dict, sast_result: dict) -> Optional[AIAnalysisResult]:
    """Perform AI analysis with retry logic and multi-key rotation using older SDK."""
    if not ai_models:
        logger.warning("AI model not configured, skipping analysis")
        return None
    
    start_time = time.time()
    policy_context = await run_in_threadpool(get_policy_context)
    # Build CVE/CVSS context for the prompt
    cve_entries = _extract_cvss_cve_summary(sca_result)
    cve_context = ""
    if cve_entries:
        cve_context = "\n### Top CVEs by CVSS Score ###\n"
        for e in cve_entries[:10]:
            score_str = f"CVSS {e['cvss_score']:.1f}" if e['cvss_score'] else "No CVSS"
            cve_context += (
                f"- [{e['cve_id']}] {e['package']} {e['installed_version']} "
                f"({e['severity']}, {score_str}) → fix: {e['fixed_version']} — {e['title']}\n"
            )

    # Build OWASP context for SAST findings
    sast_findings = sast_result.get("results", [])
    owasp_hits: dict[str, list[str]] = {}
    for f in sast_findings:
        check_id = f.get("check_id", "")
        vuln_type = check_id.split(".")[-1].lower()
        category = _map_to_owasp(vuln_type, check_id)
        if category:
            label = f"{category} — {OWASP_TOP10_2021.get(category, '')}"
            owasp_hits.setdefault(label, []).append(check_id)
    owasp_context = ""
    if owasp_hits:
        owasp_context = "\n### OWASP Top 10 (2021) Coverage ###\n"
        for label, rules in owasp_hits.items():
            owasp_context += f"- {label}: {len(rules)} finding(s) [{', '.join(rules[:3])}]\n"

    prompt = f"""
As an expert security analyst, analyze the following scan results.
Your response MUST be contextualized by the internal security policies provided.
Instead of generic advice, reference specific policy documents or sections where applicable.
Map each vulnerability to its OWASP Top 10 (2021) category where possible.

{policy_context}

### Security Scan Results ###
SCA Results: {json.dumps(sca_result, indent=2)[:4000]}
SAST Results: {json.dumps(sast_result, indent=2)[:4000]}
{cve_context}
{owasp_context}

Generate a JSON response with an executive summary and the top 3 vulnerabilities.
For each vulnerability include its OWASP category and any relevant CVE ID.
Reference specific internal policy sections where applicable.

Format your response as a single JSON object with this exact structure:
{{
    "summary": "Executive summary here",
    "top_vulnerabilities": [
        {{
            "name": "Vulnerability name",
            "severity": "HIGH",
            "file": "filename.js",
            "poc": "Proof of concept or CVE reference"
        }}
    ]
}}
"""
    
    last_error = None
    for i, model in enumerate(ai_models):
        try:
            # Use circuit breaker for AI calls
            async def call_ai(m=model):
                return await m.generate_content_async(prompt)

            response = await gemini_circuit_breaker.async_call(call_ai)

            # Clean and parse response
            response_text = response.text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            parsed_output = json.loads(response_text)
            result = AIAnalysisResult(**parsed_output)

            # Track metrics
            duration_ms = (time.time() - start_time) * 1000
            track_ai_metrics("analysis", True, duration_ms)

            logger.info(f"AI analysis completed in {duration_ms:.2f}ms using model instance #{i+1}")
            return result

        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            if "429" in error_str or "resource_exhausted" in error_str:
                logger.warning(f"Quota exceeded for model instance #{i+1}, trying next...")
                continue
            else:
                break
    
    duration_ms = (time.time() - start_time) * 1000
    track_ai_metrics("analysis", False, duration_ms)
    logger.error(f"AI analysis failed after trying all available keys: {last_error}")
    raise AIAnalysisError(f"AI analysis failed: {str(last_error)}")


@retry_on_failure(max_attempts=settings.ai_max_retries)
@handle_errors
async def _perform_ai_remediation(sca_result: dict, sast_result: dict) -> Optional[LegacyRemediationResult]:
    """Generate remediation plan with retry logic and multi-key rotation using older SDK."""
    if not ai_models:
        logger.warning("AI model not configured, skipping remediation")
        return None
    
    start_time = time.time()
    policy_context = await run_in_threadpool(get_policy_context)
    prompt = f"""
As a senior software security engineer, create a remediation plan based on the scan results.
Your fixes and explanations MUST align with the provided internal security policies.
Reference the policies to justify your proposed code changes.

{policy_context}

### Security Scan Results ###
SCA Results: {json.dumps(sca_result, indent=2)[:5000]}
SAST Results: {json.dumps(sast_result, indent=2)[:5000]}

Generate a JSON object containing a list of remediation steps. Each step must include
the issue, the exact code fix, and an explanation that references the relevant internal policy.

Format your response as a single JSON object with this exact structure:
{{
    "remediations": [
        {{
            "issue": "Issue name",
            "fix_code": "Code fix here",
            "explanation": "Why this fixes it"
        }}
    ]
}}
"""
    
    last_error = None
    for i, model in enumerate(ai_models):
        try:
            async def call_ai(m=model):
                return await m.generate_content_async(prompt)

            response = await gemini_circuit_breaker.async_call(call_ai)

            # Clean and parse response
            response_text = response.text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()

            parsed_output = json.loads(response_text)
            result = LegacyRemediationResult(**parsed_output)

            # Track metrics
            duration_ms = (time.time() - start_time) * 1000
            track_ai_metrics("remediation", True, duration_ms)

            logger.info(f"AI remediation completed in {duration_ms:.2f}ms using model instance #{i+1}")
            return result

        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            if "429" in error_str or "resource_exhausted" in error_str:
                logger.warning(f"Quota exceeded for model instance #{i+1}, trying next...")
                continue
            else:
                break
                
    duration_ms = (time.time() - start_time) * 1000
    track_ai_metrics("remediation", False, duration_ms)
    logger.error(f"AI remediation failed after trying all available keys: {last_error}")
    raise AIAnalysisError(f"AI remediation failed: {str(last_error)}")


# --- Scanner Helper Functions ---
@handle_errors
async def _run_trivy_scan(directory: str) -> dict:
    """Runs Trivy filesystem scan with optimizations and error handling."""
    start_time = time.time()
    
    try:
        logger.info(f"Starting Trivy scan in {directory}")
        trivy_cmd = [
            settings.trivy_path, "fs", directory,
            "--format", "json",
            "--quiet",
            "--timeout", f"{settings.scan_timeout_minutes}m",
            "--skip-dirs", os.path.join(directory, "node_modules"),
            "--skip-dirs", os.path.join(directory, ".git"),
        ]
        
        process = await asyncio.create_subprocess_exec(
            *trivy_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=settings.scan_timeout_minutes * 60
            )
            stdout = stdout_data.decode() if stdout_data else ""
            stderr = stderr_data.decode() if stderr_data else ""
            returncode = process.returncode
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise subprocess.TimeoutExpired(trivy_cmd, settings.scan_timeout_minutes * 60)

        duration_ms = (time.time() - start_time) * 1000
        
        if returncode != 0:
            logger.error(f"Trivy scan failed. Stderr: {stderr}")
            metrics.increment("scans.trivy.failures")
            
            # Try to parse stdout anyway, it might contain partial results
            try:
                result = json.loads(stdout) if stdout else {
                    "error": f"Trivy scan failed. Stderr: {stderr}"
                }
                metrics.histogram("scans.trivy.duration_ms", duration_ms, {"status": "partial"})
                return result
            except json.JSONDecodeError:
                metrics.histogram("scans.trivy.duration_ms", duration_ms, {"status": "failed"})
                raise ScannerError(f"Trivy scan failed and output was not valid JSON. Stderr: {stderr}")
        
        result = json.loads(stdout) if stdout else {}
        metrics.increment("scans.trivy.success")
        metrics.histogram("scans.trivy.duration_ms", duration_ms, {"status": "success"})
        logger.info(f"Trivy scan completed in {duration_ms:.2f}ms")
        
        return result
        
    except subprocess.TimeoutExpired:
        duration_ms = (time.time() - start_time) * 1000
        metrics.increment("scans.trivy.timeouts")
        metrics.histogram("scans.trivy.duration_ms", duration_ms, {"status": "timeout"})
        logger.error(f"Trivy scan timed out after {duration_ms:.2f}ms")
        raise ScannerError(f"Trivy scan timed out after {settings.scan_timeout_minutes} minutes")
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        metrics.increment("scans.trivy.errors")
        metrics.histogram("scans.trivy.duration_ms", duration_ms, {"status": "error"})
        logger.error(f"Exception during Trivy scan: {e}")
        raise ScannerError(f"Trivy scan error: {str(e)}")

@handle_errors
async def _run_semgrep_scan(directory: str) -> dict:
    """Runs Semgrep scan with optimizations and error handling."""
    start_time = time.time()
    
    try:
        logger.info(f"Starting Semgrep scan in {directory}")
        semgrep_cmd = [
            settings.semgrep_path, "scan",
            "--config=p/security-audit",
            "--json",
            "--timeout", "5",
            "--jobs", "2",
            "--exclude", "*.min.js",
            "--exclude", "package-lock.json",
            directory
        ]
        
        process = await asyncio.create_subprocess_exec(
            *semgrep_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=settings.scan_timeout_minutes * 60
            )
            stdout = stdout_data.decode() if stdout_data else ""
            stderr = stderr_data.decode() if stderr_data else ""
            returncode = process.returncode
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise subprocess.TimeoutExpired(semgrep_cmd, settings.scan_timeout_minutes * 60)

        duration_ms = (time.time() - start_time) * 1000

        if returncode != 0:
            logger.warning(f"Semgrep scan returned non-zero exit code. Stderr: {stderr}")
            metrics.increment("scans.semgrep.warnings")

        result = json.loads(stdout) if stdout else {
            "error": stderr or "Semgrep returned no output."
        }
        
        metrics.increment("scans.semgrep.success")
        metrics.histogram("scans.semgrep.duration_ms", duration_ms, {"status": "success"})
        logger.info(f"Semgrep scan completed in {duration_ms:.2f}ms")
        
        return result
        
    except subprocess.TimeoutExpired:
        duration_ms = (time.time() - start_time) * 1000
        metrics.increment("scans.semgrep.timeouts")
        metrics.histogram("scans.semgrep.duration_ms", duration_ms, {"status": "timeout"})
        logger.error(f"Semgrep scan timed out after {duration_ms:.2f}ms")
        raise ScannerError(f"Semgrep scan timed out after {settings.scan_timeout_minutes} minutes")
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        metrics.increment("scans.semgrep.errors")
        metrics.histogram("scans.semgrep.duration_ms", duration_ms, {"status": "error"})
        logger.error(f"Exception during Semgrep scan: {e}")
        raise ScannerError(f"Semgrep scan error: {str(e)}")


# --- Report Generation Helper ---
def generate_markdown_report(scan: dict) -> str:
    """Generates a Markdown report from completed scan data."""
    repo_url = scan.get('repo_url', 'N/A')
    finished_at = scan.get('finished_at', 'N/A')
    
    content = f"# Security Scan Report for {repo_url}\n\n"
    content += f"**Scan completed on:** {finished_at}\n\n"
    content += "---\n\n"

    # AI Analysis Section
    ai_analysis = scan.get('ai_analysis')
    if ai_analysis:
        content += "##  Inteligencia Artificial (IA) Security Analyst Summary\n\n"
        content += f"**Executive Summary:** {ai_analysis.get('summary', 'Not available.')}\n\n"
        content += "### Top Vulnerabilities Identified:\n\n"
        
        vulns = ai_analysis.get('top_vulnerabilities', [])
        if vulns:
            content += "| Severity | Vulnerability | File Location | Proof of Concept |\n"
            content += "|----------|---------------|---------------|------------------|\n"
            for v in vulns:
                content += f"| {v.get('severity', 'N/A')} | {v.get('name', 'N/A')} | `{v.get('file', 'N/A')}` | `{v.get('poc', 'N/A')}` |\n"
            content += "\n"
        else:
            content += "No major vulnerabilities highlighted by the AI analyst.\n\n"
    
    # OWASP Coverage Section
    sast_results = scan.get('sast_result', {}).get('results', [])
    owasp_hits: dict[str, list[str]] = {}
    for f in sast_results:
        check_id = f.get('check_id', '')
        vuln_type = check_id.split('.')[-1].lower()
        category = _map_to_owasp(vuln_type, check_id)
        if category:
            label = f"{category} — {OWASP_TOP10_2021.get(category, '')}"
            owasp_hits.setdefault(label, []).append(check_id)
    if owasp_hits:
        content += "---\n\n## OWASP Top 10 (2021) Mapping\n\n"
        content += "| OWASP Category | Findings |\n"
        content += "|----------------|----------|\n"
        for label, rules in sorted(owasp_hits.items()):
            content += f"| {label} | {len(rules)} ({', '.join(rules[:2])}{'…' if len(rules) > 2 else ''}) |\n"
        content += "\n"

    # SAST Results Section
    content += "---\n\n## SAST (Static Analysis) Results\n\n"
    if sast_results:
        content += f"Found **{len(sast_results)}** potential issues.\n\n"
        content += "| Severity | OWASP | Rule ID | File:Line | Message |\n"
        content += "|----------|-------|---------|-----------|----------|\n"
        for finding in sast_results:
            extra = finding.get('extra', {})
            severity = extra.get('severity', 'INFO')
            message = extra.get('message', '').replace('\n', ' ')[:120]
            path = finding.get('path', 'N/A')
            line = finding.get('start', {}).get('line', 'N/A')
            check_id = finding.get('check_id', 'N/A')
            vuln_type = check_id.split('.')[-1].lower()
            owasp_code = _map_to_owasp(vuln_type, check_id) or '—'
            content += f"| {severity} | {owasp_code} | {check_id} | `{path}:{line}` | {message} |\n"
        content += "\n"
    else:
        content += "No SAST findings.\n\n"

    # SCA Results Section — with CVE IDs and CVSS scores
    sca_result_raw = scan.get('sca_result', {}) or {}
    sca_results = sca_result_raw.get('Results', [])
    cve_entries = _extract_cvss_cve_summary(sca_result_raw)
    content += "---\n\n## SCA (Dependency) Results\n\n"
    if cve_entries:
        content += f"Found **{len(cve_entries)}** CVEs across dependencies.\n\n"
        content += "| CVSS | CVE ID | Package | Severity | OWASP | Fix Version | Title |\n"
        content += "|------|--------|---------|----------|-------|-------------|-------|\n"
        for e in cve_entries:
            score = f"{e['cvss_score']:.1f}" if e['cvss_score'] else "N/A"
            content += (
                f"| {score} | {e['cve_id']} | {e['package']} {e['installed_version']} "
                f"| {e['severity']} | A06 | {e['fixed_version']} | {e['title'][:60]} |\n"
            )
        content += "\n"

    if sca_results:
        total_vulns = 0
        for res in sca_results:
            total_vulns += len(res.get('Vulnerabilities', []))
        if not cve_entries:
            content += f"Found **{total_vulns}** potential vulnerabilities in dependencies.\n\n"

        for res in sca_results:
            target = res.get('Target')
            vulns = res.get('Vulnerabilities', [])
            if not vulns: continue
            
            content += f"### Target: `{target}`\n\n"
            content += "| Severity | Package | Version | Vulnerability ID | Title |\n"
            content += "|----------|---------|---------|------------------|-------|\n"
            for v in vulns:
                content += f"| {v.get('Severity', 'N/A')} | {v.get('PkgName', 'N/A')} | {v.get('InstalledVersion', 'N/A')} | `{v.get('VulnerabilityID', 'N/A')}` | {v.get('Title', 'N/A')} |\n"
            content += "\n"
    else:
        content += "No SCA findings.\n\n"
        
    return content

# --- Background Scan Task ---
async def _perform_scan(scan_uuid: str, repo_url: str):
    async def update_status(status: str, message: Optional[str] = None):
        def _update():
            with db_pool.get_cursor() as cur:
                if message:
                    cur.execute("UPDATE scans SET status = %s, error_message = %s WHERE uuid = %s", (status, message, scan_uuid))
                else:
                    cur.execute("UPDATE scans SET status = %s WHERE uuid = %s", (status, scan_uuid))
        await run_in_threadpool(_update)

    await update_status("processing")

    # Use run_in_threadpool for blocking git operations
    def clone_repo(url, path):
        return Repo.clone_from(url, path, depth=1)

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            await run_in_threadpool(clone_repo, repo_url, temp_dir)
        except Exception as e:
            logger.error(f"[{scan_uuid}] Git clone error: {e}")
            await update_status("failed", f"Git clone error: {str(e)}")
            return

        try:
            sca_result = await _run_trivy_scan(temp_dir)
            sast_result = await _run_semgrep_scan(temp_dir)
            
            # AI analysis is now optional - don't fail the whole scan if it hits a quota/error
            ai_analysis_result = None
            try:
                ai_analysis_result = await _perform_ai_analysis(sca_result, sast_result)
            except Exception as ai_err:
                logger.warning(f"[{scan_uuid}] AI analysis skipped due to error (likely quota): {ai_err}")

            def save_results():
                with db_pool.get_cursor() as cur:
                    cur.execute(
                        """
                        UPDATE scans
                        SET status = %s, sca_result = %s, sast_result = %s, ai_analysis = %s, finished_at = %s
                        WHERE uuid = %s
                        RETURNING id
                        """,
                        (
                            "completed",
                            json.dumps(sca_result),
                            json.dumps(sast_result),
                            ai_analysis_result.model_dump_json() if ai_analysis_result else None,
                            datetime.datetime.now(datetime.timezone.utc),
                            scan_uuid
                        )
                    )
                    row = cur.fetchone()
                    return row["id"] if row else None
            scan_db_id = await run_in_threadpool(save_results)
            if scan_db_id:
                sast_count = len((sast_result or {}).get("results", []))
                sca_count = len(((sca_result or {}).get("Results") or [{}])[0].get("Vulnerabilities") or [])
                _log_audit_event("scan", scan_db_id, "scan_completed", {
                    "uuid": scan_uuid,
                    "sast_findings": sast_count,
                    "sca_findings": sca_count,
                })
        except Exception as e:
            logger.error(f"[{scan_uuid}] Core scan logic failed: {e}")
            await update_status("failed", f"Scan error: {str(e)}")
            return

    logger.info(f"[{scan_uuid}] Scan completed and saved to database.")

# --- API Endpoints ---
@app.post("/scan", status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_uuid = uuid.uuid4()
    with db_pool.get_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (uuid, repo_url, status) VALUES (%s, %s, %s) RETURNING id",
            (str(scan_uuid), request.repo_url, "queued")
        )
        row = cur.fetchone()
        scan_db_id = row["id"] if row else None

    if scan_db_id:
        _log_audit_event("scan", scan_db_id, "scan_queued", {"repo_url": request.repo_url, "uuid": str(scan_uuid)})

    background_tasks.add_task(_perform_scan, str(scan_uuid), request.repo_url)
    return {"scan_id": str(scan_uuid), "status": "queued"}

@app.get("/scans", response_model=List[ScanSummary])
def list_scans(limit: int = 50):
    """Fetch the history of scans for the dashboard list."""
    try:
        with db_pool.get_cursor() as cur:
            cur.execute (
                """
                SELECT id, uuid, repo_url, status, submit_time, finished_at
                FROM scans
                ORDER BY submit_time DESC
                LIMIT %s
                """, (limit,))
            scans = cur.fetchall()
        return scans
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail="Database error while fetching scans.")

@app.get("/scan/{scan_id}/remediation", response_model=List[RemediationResult])
async def get_remediation_plan(scan_id: str):
    """
    Run the agentic 5-step remediation pipeline over every finding in the scan.

    The repo is re-cloned into a temp directory for context extraction and
    Semgrep re-validation, then cleaned up automatically.  Results are cached
    for 24 hours to avoid redundant re-clones.
    """
    cache_key = f"agentic_remediation_{scan_id}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        scan_id_int = int(scan_id)
        def fetch_scan():
            with db_pool.get_cursor() as cur:
                cur.execute(
                    "SELECT status, sast_result, repo_url FROM scans WHERE id = %s",
                    (scan_id_int,),
                )
                return cur.fetchone()
        scan = await run_in_threadpool(fetch_scan)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format. Must be an integer.")
    except Exception as e:
        logger.error(f"Error fetching scan for remediation: {e}")
        raise HTTPException(status_code=500, detail="Database error.")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed.")

    # Normalise raw Semgrep JSON into the findings format expected by the pipeline
    sast_raw = scan["sast_result"] or {}
    raw_findings = sast_raw.get("results", [])
    findings = [
        {
            "id": f.get("check_id", f"finding-{i}"),
            "severity": (f.get("extra", {}).get("severity") or "LOW").upper(),
            "file_path": f.get("path", ""),
            "line_start": f.get("start", {}).get("line", 1),
            "line_end": f.get("end", {}).get("line", 1),
            "vuln_type": f.get("check_id", "").split(".")[-1].lower().replace("-", "_"),
            "message": f.get("extra", {}).get("message", ""),
            "raw_code_snippet": f.get("extra", {}).get("lines", ""),
        }
        for i, f in enumerate(raw_findings)
    ]

    # Re-clone repo so Context Agent and Semgrep Validator have file access
    repo_url: str = scan.get("repo_url", "")
    gemini_model = ai_models[0] if ai_models else None

    async def _run_pipeline():
        """Clone repo, run pipeline, clean up — executed in a thread."""
        def _blocking():
            with tempfile.TemporaryDirectory() as tmp_dir:
                if repo_url:
                    try:
                        from git import Repo as _Repo
                        _Repo.clone_from(repo_url, tmp_dir, depth=1)
                        logger.info(f"Re-cloned {repo_url} for remediation scan_id={scan_id}")
                    except Exception as clone_err:
                        logger.warning(f"Re-clone failed ({clone_err}); context agent will use snippets only")
                scan_output = {
                    "tool": "semgrep",
                    "findings": findings,
                    "repo_local_path": tmp_dir,
                }
                return run_remediation_pipeline(
                    scan_output,
                    gemini_model=gemini_model,
                    semgrep_path=settings.semgrep_path,
                )
        return await run_in_threadpool(_blocking)

    try:
        results = await _run_pipeline()
    except Exception as e:
        logger.error(f"Agentic remediation pipeline failed for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Remediation pipeline failed.")

    cache.set(cache_key, results, ttl=86400)
    return results

@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: uuid.UUID):
    try:
        with db_pool.get_cursor() as cur:
            cur.execute("SELECT status, sca_result, sast_result, ai_analysis, error_message FROM scans WHERE uuid = %s", (str(scan_id),))
            scan = cur.fetchone()
    except Exception as e:
        logger.error(f"Error fetching scan status: {e}")
        raise HTTPException(status_code=500, detail="Database error.")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    return ScanStatus(
        status=scan['status'],
        message=scan.get('error_message'),
        result=ScanResultData(
            sca=scan['sca_result'],
            sast=scan['sast_result'],
            ai_analysis=scan['ai_analysis']
        ) if scan['status'] == 'completed' else None
    )

@app.post("/policies")
async def upload_policy_document(file: UploadFile = File(...)):
    """Uploads a policy document (PDF or TXT) and stores its content."""
    filename = file.filename
    
    try:
        if filename.lower().endswith(".pdf"):
            pdf_content = await file.read()
            def extract_pdf_content(data):
                content = ""
                pdf_file = io.BytesIO(data)
                reader = PdfReader(pdf_file)
                for page in reader.pages:
                    content += page.extract_text()
                return content
            content = await run_in_threadpool(extract_pdf_content, pdf_content)
        elif filename.lower().endswith(".txt"):
            content_bytes = await file.read()
            content = content_bytes.decode("utf-8")
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type. Please upload a PDF or TXT file.")
        
        if not content.strip():
            raise HTTPException(status_code=400, detail="The uploaded document is empty or could not be read.")

        def save_policy():
            with db_pool.get_cursor() as cur:
                cur.execute("DELETE FROM policy_documents WHERE filename = %s", (filename,))
                cur.execute(
                    "INSERT INTO policy_documents (filename, content) VALUES (%s, %s) RETURNING id",
                    (filename, content)
                )
                row = cur.fetchone()
                return row["id"] if row else None
        policy_id = await run_in_threadpool(save_policy)
        if policy_id:
            _log_audit_event("policy_document", policy_id, "policy_uploaded", {"filename": filename, "chars": len(content)})

        return {"status": "success", "filename": filename, "chars_read": len(content)}
    
    except Exception as e:
        logger.error(f"Failed to upload or process policy document '{filename}': {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")


@app.get("/policies")
async def list_scan_policies():
    """Return enforcement rules / scan policies."""
    try:
        def fetch():
            with db_pool.get_cursor() as cur:
                cur.execute(
                    "SELECT id, name, description, enabled, severity_threshold, block_on_failure FROM scan_policies ORDER BY id"
                )
                return cur.fetchall()
        rows = await run_in_threadpool(fetch)
        return [dict(r) for r in (rows or [])]
    except Exception as e:
        logger.error(f"Error listing scan policies: {e}")
        raise HTTPException(status_code=500, detail="Database error while fetching policies.")


@app.patch("/policies/{policy_id}")
async def update_scan_policy(policy_id: int, body: dict):
    """Toggle or update a scan policy rule."""
    allowed = {"enabled", "severity_threshold", "block_on_failure"}
    update = {k: v for k, v in body.items() if k in allowed}
    if not update:
        raise HTTPException(status_code=400, detail="No valid fields to update.")
    set_clause = ", ".join(f"{k} = %s" for k in update)
    try:
        def do_update():
            with db_pool.get_cursor() as cur:
                cur.execute(
                    f"UPDATE scan_policies SET {set_clause} WHERE id = %s RETURNING id",
                    (*update.values(), policy_id)
                )
                return cur.fetchone()
        row = await run_in_threadpool(do_update)
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found.")
        return {"status": "updated", "id": policy_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating policy {policy_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error.")


@app.get("/policies/documents")
async def list_policy_documents():
    """Return uploaded policy document metadata (no content)."""
    try:
        def fetch():
            with db_pool.get_cursor() as cur:
                cur.execute(
                    "SELECT id, filename, uploaded_at FROM policy_documents ORDER BY uploaded_at DESC"
                )
                return cur.fetchall()
        rows = await run_in_threadpool(fetch)
        return [
            {
                "id": r["id"],
                "filename": r["filename"],
                "uploaded_at": r["uploaded_at"].isoformat() if r["uploaded_at"] else None,
            }
            for r in (rows or [])
        ]
    except Exception as e:
        logger.error(f"Error listing policy documents: {e}")
        raise HTTPException(status_code=500, detail="Database error while fetching policy documents.")


@app.delete("/policies/documents/{doc_id}", status_code=204)
async def delete_policy_document(doc_id: int):
    """Delete an uploaded policy document."""
    try:
        def do_delete():
            with db_pool.get_cursor() as cur:
                cur.execute("DELETE FROM policy_documents WHERE id = %s RETURNING id", (doc_id,))
                return cur.fetchone()
        row = await run_in_threadpool(do_delete)
        if not row:
            raise HTTPException(status_code=404, detail="Document not found.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting policy document {doc_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error.")


@app.post("/github/webhook", status_code=202)
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives GitHub push webhook events and auto-triggers a scan.
    Validates the HMAC-SHA256 signature when GITHUB_WEBHOOK_SECRET is set.
    """
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    body = await request.body()

    if secret:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_header):
            raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    event = request.headers.get("X-GitHub-Event", "")
    if event != "push":
        return {"status": "ignored", "event": event}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    repo_url = payload.get("repository", {}).get("clone_url", "")
    if not repo_url:
        raise HTTPException(status_code=400, detail="No repository clone_url in payload.")

    scan_uuid = uuid.uuid4()
    with db_pool.get_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (uuid, repo_url, status) VALUES (%s, %s, %s) RETURNING id",
            (str(scan_uuid), repo_url, "queued")
        )
        row = cur.fetchone()
        scan_db_id = row["id"] if row else None

    pusher = payload.get("pusher", {}).get("name", "unknown")
    ref = payload.get("ref", "")
    if scan_db_id:
        _log_audit_event("scan", scan_db_id, "webhook_triggered", {
            "repo_url": repo_url, "ref": ref, "pusher": pusher, "uuid": str(scan_uuid)
        })

    background_tasks.add_task(_perform_scan, str(scan_uuid), repo_url)
    logger.info(f"GitHub webhook triggered scan {scan_uuid} for {repo_url} (ref={ref}, pusher={pusher})")
    return {"status": "queued", "scan_id": str(scan_uuid)}


# --- Report Endpoints ---
@app.post("/reports/generate", response_model=ReportResponse)
def generate_report(request: ReportRequest):
    """Generates a new report for a completed scan."""
    if request.format != 'markdown':
        raise HTTPException(status_code=400, detail="Unsupported format. Only 'markdown' is available.")

    try:
        with db_pool.get_cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id = %s", (request.scan_id,))
            scan = cur.fetchone()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan ID not found.")
        
        if scan['status'] != 'completed':
            raise HTTPException(status_code=400, detail="Cannot generate report for a scan that is not completed.")

        report_content = generate_markdown_report(scan)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_scan_{request.scan_id}_{timestamp}.md"

        # Save report to the database
        with db_pool.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (scan_id, format, filename, content)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (request.scan_id, request.format, filename, report_content)
            )
            row = cur.fetchone()
            report_id = row["id"] if row else None

        if report_id:
            _log_audit_event("report", report_id, "report_generated", {
                "scan_id": request.scan_id, "format": request.format, "filename": filename
            })

        return ReportResponse(report_content=report_content, filename=filename)

    except HTTPException as e:
        raise e  # Re-raise HTTPException to preserve status code and detail
    except Exception as e:
        logger.error(f"Failed to generate report for scan_id {request.scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report.")

@app.get("/reports", response_model=List[ReportInfo])
def list_reports(limit: int = 50):
    """Lists previously generated reports."""
    try:
        with db_pool.get_cursor() as cur:
            cur.execute (
                """
                SELECT id, scan_id, filename, format, generated_at
                FROM reports
                ORDER BY generated_at DESC
                LIMIT %s
                """, (limit,))
            reports = cur.fetchall()
        return reports
    except Exception as e:
                logger.error(f"Database error in /reports: {e}")
                raise HTTPException(status_code=500, detail="Database error.")
        
@app.get("/scan/{scan_uuid}/remediation-pdf")
def generate_remediation_pdf(scan_uuid: str):
    # 1. Fetch Raw Data from DB (The "Neat" Source)
    try:
        with db_pool.get_cursor() as cur:
            # Note: We check both UUID and ID to be safe, but sticking to UUID is cleaner
            cur.execute("SELECT repo_url, sca_result, sast_result FROM scans WHERE uuid = %s", (scan_uuid,))
            scan = cur.fetchone()
    except Exception as e:
        logger.error(f"Error fetching scan for PDF: {e}")
        raise HTTPException(status_code=500, detail="Database error.")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 2. Ask Gemini for the Patching Plan
    # (We are skipping the intermediate 'Markdown' step and going straight to the solution)
    cache_key = f"remediation_pdf_text_{scan_uuid}"
    cached_text = cache.get(cache_key)
    
    if cached_text:
        ai_text = cached_text
    else:
        prompt = f"""
        You are a DevSecOps Lead. Create a formal Remediation Patching Plan for: {scan['repo_url']}    
        DATA SOURCES:
        - SCA (Dependencies): {json.dumps(scan['sca_result'])[:10000]} 
        - SAST (Code): {json.dumps(scan['sast_result'])[:10000]}

        OUTPUT FORMAT:
        Provide a professional, step-by-step patching guide. 
        Focus ONLY on High/Critical severities.
        Do not use Markdown formatting (like **bold**), just plain text with clear headers.
        """
        
        # Check if model is loaded (from your existing code)
        if not model_name:
            ai_text = "AI Module not configured. Showing raw data summary."
        else:
            try:
                # Use the first pre-created model instance for synchronous report generation
                response = ai_models[0].generate_content(prompt)
                ai_text = response.text
                cache.set(cache_key, ai_text, ttl=86400)
            except Exception as e:
                ai_text = f"AI Generation Failed: {str(e)}"

    # 3. Generate PDF in Memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"Remediation Plan: {scan['repo_url']}", styles['Title']))
    story.append(Spacer(1, 12))

    # AI Content (Split by newlines to keep it readable)
    for line in ai_text.split('\n'):
        if line.strip():
            story.append(Paragraph(line, styles['BodyText']))
            story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)

    # 4. Stream it back to the browser
    return StreamingResponse(
        buffer, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=remediation_{scan_uuid}.pdf"}
    )

@app.get("/download/{report_id}")
def download_report(report_id: int):
    try:
        with db_pool.get_cursor() as cur:
            # ✅ CORRECT: Fetch the content string from the DB
            cur.execute("SELECT content, filename FROM reports WHERE id = %s", (report_id,))
            report = cur.fetchone()
    except Exception as e:
        logger.error(f"Error fetching report for download: {e}")
        raise HTTPException(status_code=500, detail="Database error.")
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    # Force the browser to download it as a file
    return Response(
        content=report['content'],
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={report['filename']}"}
    )

async def _perform_trivy_remediation(trivy_json: dict) -> Optional[LegacyRemediationResult]:
    """
    Performs AI-powered remediation analysis on a Trivy JSON report with multi-key rotation using older SDK.
    """
    if not ai_models:
        logger.warning("AI model not configured. Skipping Trivy remediation.")
        return None

    policy_context = await run_in_threadpool(get_policy_context)
    prompt = f"""
    As a senior software security engineer, create a prioritized, actionable remediation plan 
    based on the provided Trivy vulnerability scan report. Your response MUST be tailored for 
    an analyst who needs to quickly address the most critical issues.

    Your task is to:
    1.  Identify the top 3 most critical vulnerabilities from the report based on severity.
    2.  For each of these top vulnerabilities, provide a clear, step-by-step remediation guide.
    3.  The remediation advice should be practical and easy to follow.
    4.  Align your recommendations with the internal security policies provided below.

    {policy_context}

    ### Trivy SCA Scan Report ###
    {json.dumps(trivy_json, indent=2)}

    Generate a JSON object containing a list of the top 3 remediation steps. Each step must include
    the issue, the exact code fix or command to run, and a clear explanation.

    Format your response as a single JSON object under a 'remediations' key.
    """
    
    for i, model in enumerate(ai_models):
        try:
            response = await model.generate_content_async(prompt)

            # It's common for the model to wrap its JSON in markdown, so we strip it.
            cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
            parsed_output = json.loads(cleaned_response)
            logger.info(f"Trivy remediation completed using model instance #{i+1}")
            return LegacyRemediationResult(**parsed_output)
        except Exception as e:
            error_str = str(e).lower()
            if "429" in error_str or "resource_exhausted" in error_str:
                logger.warning(f"Quota exceeded for model instance #{i+1} during Trivy remediation, trying next...")
                continue
            else:
                logger.error(f"AI Trivy remediation failed: {e}")
                break
    
    return None

@app.get("/trivy_remediation", response_model=Optional[LegacyRemediationResult])
async def get_trivy_remediation_plan():
    """
    Reads the Trivy report, generates a remediation plan via AI, and returns it.
    """
    try:
        def load_trivy_report():
            with open("report_trivy.json", "r") as f:
                return json.load(f)
        trivy_data = await run_in_threadpool(load_trivy_report)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="report_trivy.json not found in the backend directory.")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse report_trivy.json.")

    remediation_plan = await _perform_trivy_remediation(trivy_data)
    
    if not remediation_plan:
        raise HTTPException(status_code=500, detail="Failed to generate AI remediation plan for Trivy report.")
        
    return remediation_plan
