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

# Configure structured logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

# Add CORS middleware
origins = [
    "http://localhost:3000",  # Allow your Next.js frontend to access the API
    "http://192.168.100.58:3000", # Allow access from network IP as well
    # You can add other origins as needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Google Generative AI
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    logging.error("GOOGLE_API_KEY environment variable not set. AI analysis will not be available.")
else:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel('gemini-pro') # Using gemini-pro for text analysis

# Attempt to find trivy and semgrep in the system path
TRIVY_PATH = shutil.which("trivy") or "trivy"
SEMGREP_PATH = shutil.which("semgrep") or "semgrep"

# In-memory store for scan results (for demonstration purposes)
# In a production environment, you would use a persistent store like a database
SCAN_RESULTS: Dict[str, Dict] = {}

class Vulnerability(BaseModel):
    name: str
    severity: str # 'HIGH' | 'MEDIUM' | 'LOW' | 'CRITICAL'
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
    message: str | None = None
    result: Optional[ScanResultData] = None

# --- AI Analysis Function ---
async def _perform_ai_analysis(sca_result: dict, sast_result: dict) -> AIAnalysisResult:
    if not GOOGLE_API_KEY:
        logging.warning("GOOGLE_API_KEY not set, skipping AI analysis.")
        return AIAnalysisResult(summary="AI analysis skipped: API key not configured.", top_vulnerabilities=[])

    prompt = f"""
    Analyze the following security scan results (Software Composition Analysis and Static Application Security Testing).
    Provide a concise summary of the overall security posture and identify the top 3 critical/high vulnerabilities.
    For each top vulnerability, include its name, severity (CRITICAL, HIGH, MEDIUM, LOW), affected file, and a concise Proof of Concept (PoC).

    SCA Results (Trivy): {json.dumps(sca_result, indent=2)}

    SAST Results (Semgrep): {json.dumps(sast_result, indent=2)}

    Ensure the output is a JSON object with two keys: "summary" (string) and "top_vulnerabilities" (array of objects with "name", "severity", "file", "poc").
    Example for top_vulnerabilities:
    {{"name": "Hardcoded Private Key", "severity": "CRITICAL", "file": "lib/insecurity.ts", "poc": "Attacker extracts key from repo and signs JWTs."}}
    """
    try:
        response = await model.generate_content_async(prompt)
        ai_output = response.text
        logging.info(f"AI Raw Output: {ai_output}")
        # Attempt to parse the JSON output from the model
        parsed_output = json.loads(ai_output)
        return AIAnalysisResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI analysis failed: {e}")
        return AIAnalysisResult(summary=f"AI analysis failed: {e}", top_vulnerabilities=[])

async def _perform_ai_remediation(sca_result: dict, sast_result: dict) -> RemediationResult:
    if not GOOGLE_API_KEY:
        logging.warning("GOOGLE_API_KEY not set, skipping AI remediation.")
        return RemediationResult(remediations=[])

    prompt = f"""
    You are a senior software security engineer. Your task is to provide a
    remediation plan for the following security scan results. For each finding,
    provide the exact code change required to fix the issue.

    Scan Data:
    SCA Results (Trivy): {json.dumps(sca_result, indent=2)}
    SAST Results (Semgrep): {json.dumps(sast_result, indent=2)}

    Generate a JSON object that strictly adheres to the following schema.
    Do not include any explanations or markdown formatting outside of the JSON object.

    Schema:
    {{
      "remediations": [
        {{
          "issue": "Vuln Name",
          "fix_code": "The actual code snippet to fix it",
          "explanation": "Why this fix works"
        }}
      ]
    }}
    """
    try:
        response = await model.generate_content_async(prompt)
        ai_output = response.text
        logging.info(f"AI Raw Remediation Output: {ai_output}")
        # Attempt to parse the JSON output from the model
        parsed_output = json.loads(ai_output)
        return RemediationResult(**parsed_output)
    except Exception as e:
        logging.error(f"AI remediation failed: {e}")
        return RemediationResult(remediations=[])

# --- Background Task Logic ---
async def _perform_scan(scan_id: str, repo_url: str):
    """
    Performs the Trivy and Semgrep scans and AI analysis in a background task.
    """
    SCAN_RESULTS[scan_id] = {"status": "processing", "result": {}}
    sca_result = {}
    sast_result = {}

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            logging.info(f"[{scan_id}] Cloning repository: {repo_url}...")
            Repo.clone_from(repo_url, temp_dir, depth=1)
            logging.info(f"[{scan_id}] Clone successful.")
        except GitCommandError as e:
            logging.error(f"[{scan_id}] Git clone error: {e}")
            SCAN_RESULTS[scan_id] = {
                "status": "failed",
                "message": f"Could not clone repository. Is the URL '{repo_url}' correct and the repo public?"
            }
            return

        logging.info(f"[{scan_id}] Running Trivy (SCA)...")
        sca_result = _run_trivy_scan(temp_dir)
        logging.info(f"[{scan_id}] Running Semgrep (SAST)...")
        sast_result = _run_semgrep_scan(temp_dir)

        logging.info(f"[{scan_id}] Performing AI analysis...")
        ai_analysis_result = await _perform_ai_analysis(sca_result, sast_result)
        logging.info(f"[{scan_id}] AI analysis completed.")

        SCAN_RESULTS[scan_id] = {
            "status": "completed",
            "result": {
                "sca": sca_result,
                "sast": sast_result,
                "ai_analysis": ai_analysis_result.dict()
            }
        }
        logging.info(f"[{scan_id}] Full scan and analysis completed.")

def _run_trivy_scan(directory: str) -> dict:
    """Helper function to run Trivy scan."""
    try:
        process_trivy = subprocess.run(
            [TRIVY_PATH, "fs", "--format", "json", "--quiet", directory],
            capture_output=True, text=True, check=False
        )
        if process_trivy.returncode != 0 and process_trivy.stderr:
            logging.error(f"Trivy error: {process_trivy.stderr}")
            return {"error": process_trivy.stderr}
        return json.loads(process_trivy.stdout) if process_trivy.stdout else {}
    except Exception as e:
        logging.error(f"Exception during Trivy scan: {e}")
        return {"error": str(e)}

def _run_semgrep_scan(directory: str) -> dict:
    """Helper function to run Semgrep scan with lighter rules."""
    try:
        # Changed config to p/security-audit for lighter rules
        process_semgrep = subprocess.run(
            [SEMGREP_PATH, "--config", "p/security-audit", "--json", directory],
            capture_output=True, text=True, check=False
        )
        if process_semgrep.returncode != 0 and not process_semgrep.stdout:
            logging.error(f"Semgrep error: {process_semgrep.stderr}")
            return {"error": process_semgrep.stderr}
        return json.loads(process_semgrep.stdout) if process_semgrep.stdout else {}
    except Exception as e:
        logging.error(f"Exception during Semgrep scan: {e}")
        return {"error": str(e)}

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "API is running. Send a POST to /scan to start a scan."}

@app.post("/scan", response_model=ScanStatus)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Starts a new scan in the background and returns a scan ID.
    """
    scan_id = str(uuid.uuid4())
    SCAN_RESULTS[scan_id] = {"status": "queued"}
    background_tasks.add_task(_perform_scan, scan_id, request.repo_url)
    return ScanStatus(status="queued", message="Scan started in background.", result=ScanResultData(sca={}, sast={}, ai_analysis=AIAnalysisResult(summary="", top_vulnerabilities=[])))

@app.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Retrieves the status and results of a scan.
    """
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    status_data = SCAN_RESULTS[scan_id]
    return ScanStatus(
        status=status_data.get("status", "unknown"),
        message=status_data.get("message"),
        result=ScanResultData(**status_data.get("result")) if status_data.get("result") else None
    )

@app.get("/scan/{scan_id}/remediation", response_model=RemediationResult)
async def get_remediation_plan(scan_id: str):
    """
    Generates and retrieves the remediation plan for a completed scan.
    """
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan ID not found.")

    scan_data = SCAN_RESULTS[scan_id]
    if scan_data.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan is not yet completed.")

    sca_result = scan_data.get("result", {}).get("sca", {})
    sast_result = scan_data.get("result", {}).get("sast", {})

    remediation_plan = await _perform_ai_remediation(sca_result, sast_result)
    return remediation_plan