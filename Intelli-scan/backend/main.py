import subprocess
import tempfile
import json
import os
import shutil
import time
import asyncio
from starlette.concurrency import run_in_threadpool
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.responses import Response, StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from git import Repo, GitCommandError
from typing import Dict, List, Optional
import uuid
from fastapi.middleware.cors import CORSMiddleware
from google import genai
from google.genai import types as genai_types
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
if settings.google_api_key:
    genai_client = genai.Client(api_key=settings.google_api_key)
    model = settings.ai_model_name  # model name string, used in client calls
    logger.info(f"✅ Gemini AI configured with model: {settings.ai_model_name}")
else:
    logger.warning("⚠️ GOOGLE_API_KEY not set. AI features will be disabled.")
    genai_client = None
    model = None

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

class RemediationResult(BaseModel):
    remediations: List[RemediationDetail]

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

# --- Database Table Creation (on startup) ---
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
        return context
    except Exception as e:
        logger.error(f"Could not retrieve policy context: {e}")
        return "Error retrieving security policies."

@retry_on_failure(max_attempts=settings.ai_max_retries)
@handle_errors
async def _perform_ai_analysis(sca_result: dict, sast_result: dict) -> Optional[AIAnalysisResult]:
    """Perform AI analysis with retry logic and circuit breaker."""
    if not model:
        logger.warning("AI model not configured, skipping analysis")
        return None
    
    start_time = time.time()
    
    try:
        policy_context = await run_in_threadpool(get_policy_context)
        prompt = f"""
    As an expert security analyst, analyze the following scan results.
    Your response MUST be contextualized by the internal security policies provided.
    Instead of generic advice, reference specific policy documents or sections where applicable.

    {policy_context}

    ### Security Scan Results ###
    SCA Results: {json.dumps(sca_result, indent=2)[:5000]}
    SAST Results: {json.dumps(sast_result, indent=2)[:5000]}

    Generate a JSON response with an executive summary and the top 3 vulnerabilities,
    linking them to the policies. For example, if a policy requires MFA, and a finding
    relates to weak authentication, your POC should mention the specific policy.
    
    Format your response as a single JSON object with this exact structure:
    {{
        "summary": "Executive summary here",
        "top_vulnerabilities": [
            {{
                "name": "Vulnerability name",
                "severity": "HIGH",
                "file": "filename.js",
                "poc": "Proof of concept"
            }}
        ]
    }}
    """
        
        # Use circuit breaker for AI calls
        async def call_ai():
            return await genai_client.aio.models.generate_content(
                model=model,
                contents=prompt
            )
        
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
        
        logger.info(f"AI analysis completed in {duration_ms:.2f}ms")
        return result
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        track_ai_metrics("analysis", False, duration_ms)
        logger.error(f"AI analysis failed after {duration_ms:.2f}ms: {e}")
        raise AIAnalysisError(f"AI analysis failed: {str(e)}")


@retry_on_failure(max_attempts=settings.ai_max_retries)
@handle_errors
async def _perform_ai_remediation(sca_result: dict, sast_result: dict) -> Optional[RemediationResult]:
    """Generate remediation plan with retry logic and circuit breaker."""
    if not model:
        logger.warning("AI model not configured, skipping remediation")
        return None
    
    start_time = time.time()
    
    try:
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
        
        async def call_ai():
            return await genai_client.aio.models.generate_content(
                model=model,
                contents=prompt
            )
        
        response = await gemini_circuit_breaker.async_call(call_ai)
        
        # Clean and parse response
        response_text = response.text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        parsed_output = json.loads(response_text)
        result = RemediationResult(**parsed_output)
        
        # Track metrics
        duration_ms = (time.time() - start_time) * 1000
        track_ai_metrics("remediation", True, duration_ms)
        
        logger.info(f"AI remediation completed in {duration_ms:.2f}ms")
        return result
        
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        track_ai_metrics("remediation", False, duration_ms)
        logger.error(f"AI remediation failed after {duration_ms:.2f}ms: {e}")
        raise AIAnalysisError(f"AI remediation failed: {str(e)}")


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
    
    # SAST Results Section
    sast_results = scan.get('sast_result', {}).get('results', [])
    content += "---\n\n## SAST (Static Analysis) Results\n\n"
    if sast_results:
        content += f"Found **{len(sast_results)}** potential issues.\n\n"
        content += "| Severity | Rule ID | File:Line | Message |\n"
        content += "|----------|---------|-----------|---------|\n"
        for finding in sast_results:
            extra = finding.get('extra', {})
            severity = extra.get('severity', 'INFO')
            message = extra.get('message', '').replace('\n', ' ')
            path = finding.get('path', 'N/A')
            line = finding.get('start', {}).get('line', 'N/A')
            check_id = finding.get('check_id', 'N/A')
            content += f"| {severity} | {check_id} | `{path}:{line}` | {message} |\n"
        content += "\n"
    else:
        content += "No SAST findings.\n\n"

    # SCA Results Section
    sca_results = scan.get('sca_result', {}).get('Results', [])
    content += "---\n\n## SCA (Dependency) Results\n\n"
    if sca_results:
        total_vulns = 0
        for res in sca_results:
            total_vulns += len(res.get('Vulnerabilities', []))
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
            ai_analysis_result = await _perform_ai_analysis(sca_result, sast_result)

            def save_results():
                with db_pool.get_cursor() as cur:
                    cur.execute(
                        """
                        UPDATE scans
                        SET status = %s, sca_result = %s, sast_result = %s, ai_analysis = %s, finished_at = %s
                        WHERE uuid = %s
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
            await run_in_threadpool(save_results)
        except Exception as e:
            logger.error(f"[{scan_uuid}] Scan failed: {e}")
            await update_status("failed", f"Scan error: {str(e)}")
            return

    logger.info(f"[{scan_uuid}] Scan completed and saved to database.")

# --- API Endpoints ---
@app.post("/scan", status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_uuid = uuid.uuid4()
    with db_pool.get_cursor() as cur:
        cur.execute(
            "INSERT INTO scans (uuid, repo_url, status) VALUES (%s, %s, %s)",
            (str(scan_uuid), request.repo_url, "queued")
        )

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

@app.get("/scan/{scan_id}/remediation", response_model=RemediationResult)
async def get_remediation_plan(scan_id: str):
    if not model:
        raise HTTPException(status_code=500, detail="AI model is not configured. GOOGLE_API_KEY may be missing.")
        
    try:
        scan_id_int = int(scan_id)
        def fetch_scan():
            with db_pool.get_cursor() as cur:
                cur.execute("SELECT status, sca_result, sast_result FROM scans WHERE id = %s", (scan_id_int,))
                return cur.fetchone()
        scan = await run_in_threadpool(fetch_scan)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format. Must be an integer.")
    except Exception as e:
        logger.error(f"Error fetching scan for remediation: {e}")
        raise HTTPException(status_code=500, detail="Database error.")

    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    if scan['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed.")

    remediation_plan = await _perform_ai_remediation(scan['sca_result'], scan['sast_result'])
    if not remediation_plan:
        raise HTTPException(status_code=500, detail="Failed to generate remediation plan.")
    return remediation_plan

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
                # Simple approach: replace the document if it already exists to avoid duplicates
                cur.execute("DELETE FROM policy_documents WHERE filename = %s", (filename,))
                cur.execute(
                    "INSERT INTO policy_documents (filename, content) VALUES (%s, %s)",
                    (filename, content)
                )
        await run_in_threadpool(save_policy)

        return {"status": "success", "filename": filename, "chars_read": len(content)}
    
    except Exception as e:
        logger.error(f"Failed to upload or process policy document '{filename}': {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

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
                """,
                (request.scan_id, request.format, filename, report_content)
            )

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
    if not genai_client or not model:
        ai_text = "AI Module not configured. Showing raw data summary."
    else:
        try:
            response = genai_client.models.generate_content(
                model=model,
                contents=prompt
            )
            ai_text = response.text
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

async def _perform_trivy_remediation(trivy_json: dict) -> Optional[RemediationResult]:
    """
    Performs AI-powered remediation analysis on a Trivy JSON report.
    """
    if not model:
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
    try:
        response = await genai_client.aio.models.generate_content(
            model=model,
            contents=prompt
        )
        # It's common for the model to wrap its JSON in markdown, so we strip it.
        cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
        parsed_output = json.loads(cleaned_response)
        return RemediationResult(**parsed_output)
    except Exception as e:
        logger.error(f"AI Trivy remediation failed: {e}")
        logger.error(f"Raw AI response that caused error: {response.text if 'response' in locals() else 'N/A'}")
        return None

@app.get("/trivy_remediation", response_model=Optional[RemediationResult])
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
