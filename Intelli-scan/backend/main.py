import subprocess
import tempfile
import json
import logging
import os
import shutil
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from git import Repo, GitCommandError
from typing import Dict, List, Optional
import uuid
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime

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
    allow_origins=["http://localhost:3000", "http://192.168.100.58:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Google Generative AI Configuration ---
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel('gemini-pro')
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

# --- Database Table Creation (on startup) ---
@app.on_event("startup")
def startup_event():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
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
        conn.commit()
        cur.close()
        conn.close()
        logging.info("Database table 'scans' is ready.")
    except Exception as e:
        logging.error(f"Failed to create database table: {e}")

# --- AI Helper Functions ---
async def _perform_ai_analysis(sca_result: dict, sast_result: dict) -> Optional[AIAnalysisResult]:
    # ... (implementation remains the same, but check for model)
    if not model: return None
    # ... same prompt and logic
    try:
        prompt = f"""
        Analyze the following security scan results...
        SCA Results: {json.dumps(sca_result, indent=2)}
        SAST Results: {json.dumps(sast_result, indent=2)}
        ...
        """
        response = await model.generate_content_async(prompt)
        parsed_output = json.loads(response.text.strip())
        return AIAnalysisResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI analysis failed: {e}")
        return None


async def _perform_ai_remediation(sca_result: dict, sast_result: dict) -> Optional[RemediationResult]:
    # ... (implementation remains the same, but check for model)
    if not model: return None
    # ... same prompt and logic
    try:
        prompt = f"""
        You are a senior software security engineer...
        Scan Data:
        SCA Results: {json.dumps(sca_result, indent=2)}
        SAST Results: {json.dumps(sast_result, indent=2)}
        ...
        """
        response = await model.generate_content_async(prompt)
        parsed_output = json.loads(response.text.strip())
        return RemediationResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI remediation failed: {e}")
        return None

# --- Scanner Helper Functions ---
def _run_trivy_scan(directory: str) -> dict:
    # ... (implementation remains the same)
    try:
        process = subprocess.run([TRIVY_PATH, "fs", "--format", "json", "--quiet", directory], capture_output=True, text=True, check=False)
        return json.loads(process.stdout) if process.stdout and process.returncode == 0 else {"error": process.stderr}
    except Exception as e:
        return {"error": str(e)}

def _run_semgrep_scan(directory: str) -> dict:
    # ... (implementation remains the same)
    try:
        process = subprocess.run([SEMGREP_PATH, "--config", "p/security-audit", "--json", directory], capture_output=True, text=True, check=False)
        return json.loads(process.stdout) if process.stdout else {"error": process.stderr}
    except Exception as e:
        return {"error": str(e)}

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
            # In a real app, you might store the error message in the DB
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
    # Use RealDictCursor to get results as dictionaries
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
            SELECT id, repo_url, status, submit_time, finished_at
            FROM scans
            ORDER BY id DESC
            LIMIT %s
        """, (limit,))
        scans = cur.fetchall()
        cur.close()
        conn.close()
        # Ensure datetimes are serialized to strings
        for scan in scans:
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
    # ... (this endpoint can remain similar, just fetching from DB)
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