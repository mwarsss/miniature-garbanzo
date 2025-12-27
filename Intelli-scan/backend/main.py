import subprocess
import tempfile
import json
import logging
import os
import shutil
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel, Field
from git import Repo, GitCommandError
from typing import Dict, List, Optional
import uuid
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
from pypdf import PdfReader
import io

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Environment Variables ---
DATABASE_URL = os.getenv("DATABASE_URL")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
TRIVY_PATH = shutil.which("trivy") or "trivy"
SEMGREP_PATH = shutil.which("semgrep") or "semgrep"

# --- Database Connection ---
def get_db_connection():
    if not DATABASE_URL:
        logging.error("DATABASE_URL environment variable not set.")
        raise HTTPException(status_code=500, detail="Database is not configured.")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        logging.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database connection error: {e}")

# --- FastAPI App Initialization ---
app = FastAPI()

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Google Generative AI Configuration ---
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel('gemini-1.0-pro')
else:
    logging.warning("GOOGLE_API_KEY not set. AI features will be disabled.")
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
    sca: Optional[Dict]
    sast: Optional[Dict]
    ai_analysis: Optional[AIAnalysisResult]

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

# --- Database Table Creation (on startup) ---
@app.on_event("startup")
def startup_event():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            uuid UUID UNIQUE NOT NULL,
            repo_url VARCHAR(255) NOT NULL,
            status VARCHAR(50) NOT NULL,
            submit_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at TIMESTAMPTZ,
            sca_result JSONB,
            sast_result JSONB,
            ai_analysis JSONB
        );
    """)
    logging.info("Database table 'scans' is ready.")

    # Policy documents table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS policy_documents (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)
    logging.info("Database table 'policy_documents' is ready.")

    # Reports table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            format VARCHAR(50) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)
    logging.info("Database table 'reports' is ready.")

    conn.commit()
    cur.close()
    conn.close()

# --- AI Helper Functions ---
def get_policy_context() -> str:
    """Retrieves all policy documents from the database to form a context string."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT filename, content FROM policy_documents ORDER BY uploaded_at DESC")
        policies = cur.fetchall()
        cur.close()
        conn.close()
        
        if not policies:
            return "No security policies provided."

        context = "### Internal Security Policies ###\n\n"
        for policy in policies:
            context += f"--- Document: {policy['filename']} ---\n"
            context += f"{policy['content']}\n\n"
        return context
    except Exception as e:
        logging.error(f"Could not retrieve policy context: {e}")
        return "Error retrieving security policies."

async def _perform_ai_analysis(sca_result: dict, sast_result: dict) -> Optional[AIAnalysisResult]:
    if not model: return None
    
    policy_context = get_policy_context()
    prompt = f"""
    As an expert security analyst, analyze the following scan results.
    Your response MUST be contextualized by the internal security policies provided.
    Instead of generic advice, reference specific policy documents or sections where applicable.

    {policy_context}

    ### Security Scan Results ###
    SCA Results: {json.dumps(sca_result, indent=2)}
    SAST Results: {json.dumps(sast_result, indent=2)}

    Generate a JSON response with an executive summary and the top 3 vulnerabilities,
    linking them to the policies. For example, if a policy requires MFA, and a finding
    relates to weak authentication, your POC should mention the specific policy.
    
    Format your response as a single JSON object.
    """
    try:
        response = await model.generate_content_async(prompt)
        parsed_output = json.loads(response.text.strip())
        return AIAnalysisResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI analysis failed: {e}")
        return None


async def _perform_ai_remediation(sca_result: dict, sast_result: dict) -> Optional[RemediationResult]:
    if not model: return None
    
    policy_context = get_policy_context()
    prompt = f"""
    As a senior software security engineer, create a remediation plan based on the scan results.
    Your fixes and explanations MUST align with the provided internal security policies.
    Reference the policies to justify your proposed code changes.

    {policy_context}

    ### Security Scan Results ###
    SCA Results: {json.dumps(sca_result, indent=2)}
    SAST Results: {json.dumps(sast_result, indent=2)}

    Generate a JSON object containing a list of remediation steps. Each step must include
    the issue, the exact code fix, and an explanation that references the relevant internal policy.

    Format your response as a single JSON object.
    """
    try:
        logging.info(f"AI remediation prompt: {prompt}")
        response = await model.generate_content_async(prompt)
        logging.info(f"AI remediation response: {response.text}")
        parsed_output = json.loads(response.text.strip())
        return RemediationResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI remediation failed: {e}")
        return None

# --- Scanner Helper Functions ---
def _run_trivy_scan(directory: str) -> dict:
    """Runs Trivy filesystem scan with optimizations."""
    try:
        logging.info(f"[{datetime.datetime.now()}] Running Trivy scan in {directory}...")
        trivy_cmd = [
            TRIVY_PATH, "fs", directory,
            "--format", "json",
            "--quiet",
            "--timeout", "15m",
            "--skip-dirs", os.path.join(directory, "node_modules"),
            "--skip-dirs", os.path.join(directory, ".git"),
        ]
        process = subprocess.run(trivy_cmd, capture_output=True, text=True, check=False)

        if process.returncode != 0:
            logging.error(f"Trivy scan failed. Stderr: {process.stderr}")
            # Try to parse stdout anyway, it might contain partial results
            try:
                return json.loads(process.stdout) if process.stdout else {"error": f"Trivy scan failed. Stderr: {process.stderr}"}
            except json.JSONDecodeError:
                return {"error": f"Trivy scan failed and output was not valid JSON. Stderr: {process.stderr}"}
        
        return json.loads(process.stdout) if process.stdout else {}
    except Exception as e:
        logging.error(f"Exception during Trivy scan: {e}")
        return {"error": str(e)}

def _run_semgrep_scan(directory: str) -> dict:
    """Runs Semgrep scan with optimizations."""
    try:
        logging.info(f"[{datetime.datetime.now()}] Running Semgrep scan in {directory}...")
        semgrep_cmd = [
            SEMGREP_PATH, "scan",
            "--config=p/security-audit",
            "--json",
            "--timeout", "5",
            "--jobs", "2",
            "--exclude", "*.min.js",
            "--exclude", "package-lock.json",
            directory
        ]
        process = subprocess.run(semgrep_cmd, capture_output=True, text=True, check=False)

        if process.returncode != 0:
            logging.error(f"Semgrep scan failed. Stderr: {process.stderr}")

        return json.loads(process.stdout) if process.stdout else {"error": process.stderr or "Semgrep returned no output."}
    except Exception as e:
        logging.error(f"Exception during Semgrep scan: {e}")
        return {"error": str(e)}

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
    conn = get_db_connection()
    cur = conn.cursor()

    def update_status(status: str, message: Optional[str] = None):
        cur.execute("UPDATE scans SET status = %s WHERE uuid = %s", (status, scan_uuid))
        conn.commit()

    update_status("processing")

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            Repo.clone_from(repo_url, temp_dir, depth=1)
        except GitCommandError as e:
            logging.error(f"[{scan_uuid}] Git clone error: {e}")
            update_status("failed")
            return

        sca_result = _run_trivy_scan(temp_dir)
        sast_result = _run_semgrep_scan(temp_dir)
        ai_analysis_result = await _perform_ai_analysis(sca_result, sast_result)

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
        conn.commit()

    cur.close()
    conn.close()
    logging.info(f"[{scan_uuid}] Scan completed and saved to database.")

# --- API Endpoints ---
@app.post("/scan", status_code=202)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_uuid = uuid.uuid4()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (uuid, repo_url, status) VALUES (%s, %s, %s)",
        (str(scan_uuid), request.repo_url, "queued")
    )
    conn.commit()
    cur.close()
    conn.close()

    background_tasks.add_task(_perform_scan, str(scan_uuid), request.repo_url)
    return {"scan_id": str(scan_uuid), "status": "queued"}

@app.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT status, sca_result, sast_result, ai_analysis FROM scans WHERE uuid = %s", (scan_id,))
    scan = cur.fetchone()
    cur.close()
    conn.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    return ScanStatus(
        status=scan['status'],
        result=ScanResultData(
            sca=scan['sca_result'],
            sast=scan['sast_result'],
            ai_analysis=scan['ai_analysis']
        ) if scan['status'] == 'completed' else None
    )

@app.get("/scans")
def list_scans(limit: int = 50):
    """Fetch the history of scans for the dashboard list."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, uuid, repo_url, status, submit_time, finished_at
            FROM scans
            ORDER BY id DESC
            LIMIT %s
        """, (limit,))
        scans = cur.fetchall()
        cur.close()
        conn.close()
        for scan in scans:
            # Convert UUID and datetime objects to strings for JSON compatibility
            if scan.get('uuid'):
                scan['uuid'] = str(scan['uuid'])
            if scan.get('submit_time'):
                scan['submit_time'] = scan['submit_time'].isoformat()
            if scan.get('finished_at'):
                scan['finished_at'] = scan['finished_at'].isoformat()
        return scans
    except Exception as e:
        logging.error(f"Database error in /scans: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

@app.get("/scan/{scan_id}/remediation", response_model=RemediationResult)
async def get_remediation_plan(scan_id: str):
    if not model:
        raise HTTPException(status_code=500, detail="AI model is not configured. GOOGLE_API_KEY may be missing.")
        
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT status, sca_result, sast_result FROM scans WHERE uuid = %s", (scan_id,))
    scan = cur.fetchone()
    cur.close()
    conn.close()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    if scan['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Scan not completed.")

    remediation_plan = await _perform_ai_remediation(scan['sca_result'], scan['sast_result'])
    if not remediation_plan:
        raise HTTPException(status_code=500, detail="Failed to generate remediation plan.")
    return remediation_plan

@app.post("/policies")
async def upload_policy_document(file: UploadFile = File(...)):
    """Uploads a policy document (PDF or TXT) and stores its content."""
    filename = file.filename
    content = ""
    
    try:
        if filename.lower().endswith(".pdf"):
            pdf_content = await file.read()
            pdf_file = io.BytesIO(pdf_content)
            reader = PdfReader(pdf_file)
            for page in reader.pages:
                content += page.extract_text()
        elif filename.lower().endswith(".txt"):
            content_bytes = await file.read()
            content = content_bytes.decode("utf-8")
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type. Please upload a PDF or TXT file.")
        
        if not content.strip():
            raise HTTPException(status_code=400, detail="The uploaded document is empty or could not be read.")

        conn = get_db_connection()
        cur = conn.cursor()
        # Simple approach: replace the document if it already exists to avoid duplicates
        cur.execute("DELETE FROM policy_documents WHERE filename = %s", (filename,))
        cur.execute(
            "INSERT INTO policy_documents (filename, content) VALUES (%s, %s)",
            (filename, content)
        )
        conn.commit()
        cur.close()
        conn.close()

        return {"status": "success", "filename": filename, "chars_read": len(content)}
    
    except Exception as e:
        logging.error(f"Failed to upload or process policy document '{filename}': {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

# --- Report Endpoints ---
@app.post("/reports/generate", response_model=ReportResponse)
def generate_report(request: ReportRequest):
    """Generates a new report for a completed scan."""
    if request.format != 'markdown':
        raise HTTPException(status_code=400, detail="Unsupported format. Only 'markdown' is available.")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM scans WHERE id = %s", (request.scan_id,))
        scan = cur.fetchone()
        
        if not scan:
            cur.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Scan ID not found.")
        
        if scan['status'] != 'completed':
            cur.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot generate report for a scan that is not completed.")

        report_content = generate_markdown_report(scan)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_scan_{request.scan_id}_{timestamp}.md"

        # Save report to the database
        cur.execute(
            """
            INSERT INTO reports (scan_id, format, filename, content)
            VALUES (%s, %s, %s, %s)
            """,
            (request.scan_id, request.format, filename, report_content)
        )
        conn.commit()
        cur.close()
        conn.close()

        return ReportResponse(report_content=report_content, filename=filename)

    except HTTPException as e:
        raise e  # Re-raise HTTPException to preserve status code and detail
    except Exception as e:
        logging.error(f"Failed to generate report for scan_id {request.scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report.")

@app.get("/reports", response_model=List[ReportInfo])
def list_reports(limit: int = 50):
    """Lists previously generated reports."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, scan_id, filename, format, generated_at
            FROM reports
            ORDER BY generated_at DESC
            LIMIT %s
        """, (limit,))
        reports = cur.fetchall()
        cur.close()
        conn.close()
        return reports
    except Exception as e:
                logging.error(f"Database error in /reports: {e}")
                raise HTTPException(status_code=500, detail="Database error.")
        
        async def _perform_trivy_remediation(trivy_json: dict) -> Optional[RemediationResult]:
            """
            Performs AI-powered remediation analysis on a Trivy JSON report.
            """
            if not model:
                logging.warning("AI model not configured. Skipping Trivy remediation.")
                return None
        
            policy_context = get_policy_context()
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
                response = await model.generate_content_async(prompt)
                # It's common for the model to wrap its JSON in markdown, so we strip it.
                cleaned_response = response.text.strip().replace("```json", "").replace("```", "")
                parsed_output = json.loads(cleaned_response)
                return RemediationResult(**parsed_output)
            except Exception as e:
                logging.error(f"AI Trivy remediation failed: {e}")
                logging.error(f"Raw AI response that caused error: {response.text if 'response' in locals() else 'N/A'}")
                return None
        
        @app.get("/trivy_remediation", response_model=Optional[RemediationResult])
        async def get_trivy_remediation_plan():
            """
            Reads the Trivy report, generates a remediation plan via AI, and returns it.
            """
            try:
                # Assuming report_trivy.json is in the same directory as main.py
                with open("report_trivy.json", "r") as f:
                    trivy_data = json.load(f)
            except FileNotFoundError:
                raise HTTPException(status_code=404, detail="report_trivy.json not found in the backend directory.")
            except json.JSONDecodeError:
                raise HTTPException(status_code=500, detail="Failed to parse report_trivy.json.")
        
            remediation_plan = await _perform_trivy_remediation(trivy_data)
            
            if not remediation_plan:
                raise HTTPException(status_code=500, detail="Failed to generate AI remediation plan for Trivy report.")
                
            return remediation_plan
        