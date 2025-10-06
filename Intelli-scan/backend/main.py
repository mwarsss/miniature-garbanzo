import subprocess
import tempfile
import json
import logging
from fastapi.concurrency import run_in_threadpool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from git import Repo, GitCommandError

# Configure structured logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI()

# Pydantic model to define the structure of the request body


class ScanRequest(BaseModel):
    repo_url: str


@app.get("/")
def read_root():
    return {"message": "API is running. Send a POST to /scan to start."}


@app.post("/scan")
async def scan_repository(request: ScanRequest):
    """
    Clones a Git repository, scans it with OSV-Scanner,
    and returns the raw vulnerability report.
    """
    # Create a temporary directory that will be automatically cleaned up
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            logging.info(f"Cloning repository: {request.repo_url}...")
            # Clone the repo into the temporary directory
            # Run blocking I/O in a thread pool to avoid blocking the event loop
            await run_in_threadpool(Repo.clone_from, request.repo_url, temp_dir)
            logging.info("Clone successful.")

        except GitCommandError as e:
            # If the repo is private, invalid, or can't be cloned
            logging.error(f"Git clone error: {e}")
            raise HTTPException(
                status_code=400, detail=f"Could not clone repository. Is the URL '{request.repo_url}' correct and the repo public?")

        logging.info("Running OSV-Scanner...")
        try:
            # Run the OSV-Scanner command as a subprocess in a thread pool
            process = await run_in_threadpool(
                subprocess.run,
                ["osv-scanner", "--json", temp_dir],
                capture_output=True,
                text=True,
                check=False  # We will check the return code manually
            )
        except FileNotFoundError:
            logging.error("osv-scanner command not found.")
            raise HTTPException(
                status_code=500, detail="OSV-Scanner is not installed or not in PATH."
            )

        if process.returncode != 0 and process.stderr:
            # If the scanner itself fails
            logging.error(f"OSV-Scanner error: {process.stderr}")
            raise HTTPException(
                status_code=500, detail=f"OSV-Scanner failed to run: {process.stderr}")

        # Handle cases where OSV-Scanner produces no output
        if not process.stdout:
            logging.warning(
                "OSV-Scanner produced no output. The repository might not have dependencies to scan.")
            return {"results": []}

        logging.info("Scan complete. Parsing results...")
        try:
            # Parse the JSON output from the scanner
            results = json.loads(process.stdout)
            return results
        except json.JSONDecodeError:
            # If the output isn't valid JSON for some reason
            logging.error("Failed to decode JSON from OSV-Scanner output.")
            raise HTTPException(
                status_code=500, detail="Failed to parse scanner output.")
