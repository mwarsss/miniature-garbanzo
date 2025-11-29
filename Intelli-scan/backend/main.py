import subprocess
import tempfile
import json
import logging
import os
import shutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from git import Repo, GitCommandError
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from redis import Redis
from starlette.responses import JSONResponse

# --- Configuration ---
# Configure structured logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Attempt to find trivy and semgrep in the system path
TRIVY_PATH = shutil.which("trivy") or "trivy"
SEMGREP_PATH = shutil.which("semgrep") or "semgrep"

# --- Redis & Dramatiq ---
# Use the REDIS_URL from Heroku environment or default to local Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = Redis.from_url(REDIS_URL)
redis_broker = RedisBroker(url=REDIS_URL)
dramatiq.set_broker(redis_broker)

# --- FastAPI App ---
app = FastAPI()

# --- Pydantic Models ---
class ScanRequest(BaseModel):
    repo_url: str

class ScanResponse(BaseModel):
    task_id: str
    status: str
    message: str

# --- Dramatiq Actor (Background Task) ---
@dramatiq.actor(max_retries=0, store_results=True)
def run_full_scan(repo_url: str):
    """
    Dramatiq actor to run Trivy and Semgrep scans in the background.
    The result is stored in the Dramatiq backend (Redis).
    """
    results = {"sca": {}, "sast": {}}
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            logging.info(f"Cloning repository: {repo_url}...")
            Repo.clone_from(repo_url, temp_dir, depth=1)
            logging.info("Clone successful.")
        except GitCommandError as e:
            logging.error(f"Git clone error: {e}")
            # Store error in result and return
            error_message = f"Could not clone repository. Is the URL '{repo_url}' correct and the repo public?"
            results["error"] = error_message
            return results

        # Run Trivy and Semgrep
        results["sca"] = _run_trivy_scan(temp_dir)
        results["sast"] = _run_semgrep_scan(temp_dir)

        return results

def _run_trivy_scan(directory: str) -> dict:
    """Helper function to run Trivy scan."""
    try:
        process_trivy = subprocess.run(
            [TRIVY_PATH, "fs", "--format", "json", "--quiet", directory],
            capture_output=True, text=True, check=False
        )
        if process_trivy.returncode != 0 and process_trivy.stderr:
            return {"error": process_trivy.stderr}
        return json.loads(process_trivy.stdout) if process_trivy.stdout else {}
    except Exception as e:
        return {"error": str(e)}

def _run_semgrep_scan(directory: str) -> dict:
    """Helper function to run Semgrep scan."""
    try:
        process_semgrep = subprocess.run(
            [SEMGREP_PATH, "--config", "auto", "--json", directory],
            capture_output=True, text=True, check=False
        )
        if process_semgrep.returncode != 0 and not process_semgrep.stdout:
            return {"error": process_semgrep.stderr}
        return json.loads(process_semgrep.stdout) if process_semgrep.stdout else {}
    except Exception as e:
        return {"error": str(e)}

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "API is running. Send a POST to /scan to start a scan."}

@app.post("/scan", response_model=ScanResponse)
async def scan_repository(request: ScanRequest):
    """
    Enqueues a background task to scan a Git repository.
    Returns a task ID to track the scan's progress.
    """
    try:
        # Send the task to the Dramatiq worker
        task = run_full_scan.send(request.repo_url)
        return ScanResponse(
            task_id=task.message_id,
            status="queued",
            message="Scan has been queued successfully."
        )
    except Exception as e:
        logging.error(f"Failed to enqueue scan task: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue scan task.")

@app.get("/scan-results/{task_id}")
async def get_scan_results(task_id: str):
    """
    Retrieves the results of a completed scan task.
    If the task is not yet complete, it returns the current status.
    """
    try:
        # Get the result from the Dramatiq backend
        result = dramatiq.get_result(run_full_scan, message_id=task_id)

        if result is None:
            # The result is not yet available, which means the task is still processing
            return JSONResponse(content={"status": "processing"}, status_code=202)

        return JSONResponse(content={"status": "completed", "result": result})
    except dramatiq.errors.ResultMissing:
        # This exception is raised if the task does not exist
        raise HTTPException(status_code=404, detail="Scan task not found.")
    except Exception as e:
        logging.error(f"Error retrieving scan result for task {task_id}: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving scan result.")

