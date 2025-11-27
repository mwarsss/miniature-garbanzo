import subprocess
import tempfile
import json
import logging
import os
import shutil
from fastapi.concurrency import run_in_threadpool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from git import Repo, GitCommandError

# Configure structured logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

# Attempt to find trivy and semgrep in the system path
TRIVY_PATH = shutil.which("trivy") or "trivy"
SEMGREP_PATH = shutil.which("semgrep") or "semgrep"

# Pydantic model to define the structure of the request body


class ScanRequest(BaseModel):
    repo_url: str


@app.get("/")
def read_root():
    return {"message": "API is running. Send a POST to /scan to start."}


@app.post("/scan")
async def scan_repository(request: ScanRequest):
    """
    Clones a Git repository, scans it with Trivy (SCA) and Semgrep (SAST),
    and returns the combined vulnerability report.
    """
    results = {"sca": {}, "sast": {}}

    # Create a temporary directory that will be automatically cleaned up
    with tempfile.TemporaryDirectory() as temp_dir:
        # --- 1. Clone Repository ---
        try:
            logging.info(f"Cloning repository: {request.repo_url}...")
            await run_in_threadpool(Repo.clone_from, request.repo_url, temp_dir, depth=1)
            logging.info("Clone successful.")
        except GitCommandError as e:
            logging.error(f"Git clone error: {e}")
            raise HTTPException(
                status_code=400, detail=f"Could not clone repository. Is the URL '{request.repo_url}' correct and the repo public?")

        # --- 2. Run Trivy (SCA) ---
        logging.info("Running Trivy (SCA)...")
        try:
            # Run Trivy to scan the filesystem (fs) of the cloned repo
            # --format json: Output in JSON format
            # --quiet: Suppress progress bar and other non-JSON output
            process_trivy = await run_in_threadpool(
                subprocess.run,
                [TRIVY_PATH, "fs", "--format", "json", "--quiet", temp_dir],
                capture_output=True,
                text=True,
                check=False
            )
            
            if process_trivy.returncode != 0 and process_trivy.stderr:
                logging.error(f"Trivy error: {process_trivy.stderr}")
                results["sca"] = {"error": process_trivy.stderr}
            elif not process_trivy.stdout:
                logging.warning("Trivy produced no output.")
                results["sca"] = {"message": "No dependencies found or no output produced."}
            else:
                try:
                    results["sca"] = json.loads(process_trivy.stdout)
                except json.JSONDecodeError:
                    logging.error("Failed to decode JSON from Trivy output.")
                    results["sca"] = {"error": "Failed to parse JSON output"}
        except FileNotFoundError:
            logging.error("trivy command not found.")
            results["sca"] = {"error": "Trivy not installed or not in PATH"}
        except Exception as e:
            logging.error(f"Unexpected error running Trivy: {e}")
            results["sca"] = {"error": str(e)}

        # --- 3. Run Semgrep (SAST) ---
        logging.info("Running Semgrep (SAST)...")
        try:
            process_semgrep = await run_in_threadpool(
                subprocess.run,
                [SEMGREP_PATH, "--config", "auto", "--json", temp_dir],
                capture_output=True,
                text=True,
                check=False
            )
            # Semgrep returns exit code 0 on success (clean or issues found), 1 on fatal error.
            # However, it writes JSON to stdout even if issues are found.
            if process_semgrep.returncode != 0 and not process_semgrep.stdout:
                 logging.error(f"Semgrep error: {process_semgrep.stderr}")
                 results["sast"] = {"error": process_semgrep.stderr}
            else:
                try:
                    results["sast"] = json.loads(process_semgrep.stdout)
                except json.JSONDecodeError:
                    logging.error("Failed to decode JSON from Semgrep output.")
                    results["sast"] = {"error": "Failed to parse JSON output"}
        except FileNotFoundError:
            logging.error("semgrep command not found.")
            results["sast"] = {"error": "Semgrep not installed or not in PATH"}
        except Exception as e:
            logging.error(f"Unexpected error running Semgrep: {e}")
            results["sast"] = {"error": str(e)}

        return results
