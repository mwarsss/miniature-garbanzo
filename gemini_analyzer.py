"""
This module provides functions to analyze security scan data using an LLM
and generate structured JSON responses for vulnerability analysis and
remediation plans.
"""

import json
import logging
import os
from typing import List, Dict, Any, Union

import google.generativeai as genai
from pydantic import BaseModel, ValidationError, Field

# --- Configure Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Configure the Gemini API ---
# Make sure to set the GOOGLE_API_KEY environment variable
try:
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    llm = genai.GenerativeModel('gemini-2.0-flash')
except KeyError:
    logging.error("GOOGLE_API_KEY environment variable not set.")
    llm = None
except Exception as e:
    logging.error(f"Failed to configure Gemini API: {e}")
    llm = None


# ==============================================================================
# 1. Pydantic Models for Strict JSON Schema Validation
# ==============================================================================

class VulnerabilityDetail(BaseModel):
    """Defines the schema for a single top vulnerability."""
    name: str = Field(...,
                      description="The name of the vulnerability or security issue.")
    severity: str = Field(...,
                          description="The severity level (e.g., HIGH, CRITICAL).")
    file: str = Field(...,
                      description="The file path where the vulnerability was found.")
    poc: str = Field(..., description="A brief, specific proof-of-concept or exploitation explanation.")


class AnalysisResult(BaseModel):
    """Defines the schema for the vulnerability analysis response."""
    summary: str = Field(...,
                         description="A single, executive-level summary sentence.")
    top_vulnerabilities: List[VulnerabilityDetail]


class RemediationDetail(BaseModel):
    """Defines the schema for a single remediation item."""
    issue: str = Field(...,
                       description="The name of the vulnerability being addressed.")
    fix_code: str = Field(...,
                          description="The actual code snippet to apply the fix.")
    explanation: str = Field(
        ..., description="A clear explanation of why this code fixes the issue.")


class RemediationResult(BaseModel):
    """Defines the schema for the remediation plan response."""
    remediations: List[RemediationDetail]


# ==============================================================================
# 2. Helper Functions
# ==============================================================================

def _truncate_scan_data(scan_data: Dict[str, Any], max_items: int = 10) -> str:
    """
    Truncates raw scan data to prioritize high-severity findings,
    fitting it within the LLM's context window.

    Args:
        scan_data: The raw JSON data from Trivy and Semgrep.
        max_items: The maximum number of high-priority items to include.

    Returns:
        A condensed JSON string of the most critical vulnerabilities.
    """
    truncated_results = {
        "sca_vulnerabilities": [],
        "sast_findings": []
    }

    # Prioritize Trivy vulnerabilities by severity
    if scan_data.get("sca") and "Results" in scan_data["sca"]:
        all_vulns = []
        for result in scan_data["sca"]["Results"]:
            if "Vulnerabilities" in result:
                all_vulns.extend(result["Vulnerabilities"])

        # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_vulns.sort(key=lambda v: severity_order.get(
            v.get("Severity", "LOW"), 4))
        truncated_results["sca_vulnerabilities"] = all_vulns[:max_items]

    # Prioritize Semgrep findings (usually sorted by impact in the report)
    if scan_data.get("sast") and "results" in scan_data["sast"]:
        truncated_results["sast_findings"] = scan_data["sast"]["results"][:max_items]

    return json.dumps(truncated_results, indent=2)


def _call_gemini_api(prompt: str, max_retries: int = 2) -> str:
    """
    Calls the Gemini API with a given prompt and handles retries.

    Args:
        prompt: The complete prompt to send to the LLM.
        max_retries: The number of times to retry on failure.

    Returns:
        The raw text response from the LLM.

    Raises:
        ConnectionError: If the LLM is not configured or fails after retries.
    """
    if not llm:
        raise ConnectionError("Gemini API client is not configured.")

    for attempt in range(max_retries):
        try:
            response = llm.generate_content(prompt)
            # Clean the response to remove potential markdown code fences
            cleaned_text = response.text.strip().replace(
                "```json", "").replace("```", "").strip()
            return cleaned_text
        except Exception as e:
            logging.error(f"API call failed on attempt {attempt + 1}: {e}")
            if attempt + 1 == max_retries:
                raise ConnectionError(
                    f"LLM API call failed after {max_retries} attempts.") from e
    return ""  # Should not be reached

# ==============================================================================
# 3. Core Logic Functions
# ==============================================================================


def analyze_scan_vulnerabilities(scan_data: Dict[str, Any]) -> AnalysisResult:
    """
    Analyzes raw scan data to produce a summarized vulnerability report.

    Args:
        scan_data: The dictionary containing raw SCA and SAST scan data.

    Returns:
        An AnalysisResult object containing the structured summary.

    Raises:
        ValueError: If the LLM response is not valid JSON or does not match the schema.
        ConnectionError: If the LLM API call fails.
    """
    truncated_data = _truncate_scan_data(scan_data)
    prompt = f"""
    You are a principal security analyst. Your task is to analyze the following
    security scan results and provide a concise, actionable summary.

    Scan Data:
    {truncated_data}

    Based on the data, generate a JSON object that strictly adheres to the following schema.
    Do not include any explanations or markdown formatting outside of the JSON object.

    Schema:
    {{
      "summary": "One sentence executive summary",
      "top_vulnerabilities": [
        {{
          "name": "Vuln Name",
          "severity": "HIGH",
          "file": "filename.ts",
          "poc": "Brief explanation of how to exploit this specific finding"
        }}
      ]
    }}
    """

    try:
        raw_response = _call_gemini_api(prompt)
        # Validate the raw JSON response against the Pydantic model
        analysis = AnalysisResult.model_validate_json(raw_response)
        return analysis
    except (json.JSONDecodeError, ValidationError) as e:
        logging.error(
            f"Failed to validate LLM response for vulnerability analysis: {e}")
        logging.debug(f"Invalid raw response received:\n{raw_response}")
        raise ValueError(
            "LLM returned an invalid or malformed JSON response.") from e


def generate_remediation_plan(scan_data: Dict[str, Any]) -> RemediationResult:
    """
    Generates a remediation plan with specific code fixes for vulnerabilities.

    Args:
        scan_data: The dictionary containing raw SCA and SAST scan data.

    Returns:
        A RemediationResult object containing the structured remediation plan.

    Raises:
        ValueError: If the LLM response is not valid JSON or does not match the schema.
        ConnectionError: If the LLM API call fails.
    """
    truncated_data = _truncate_scan_data(scan_data)
    prompt = f"""
    You are a senior software security engineer. Your task is to provide a
    remediation plan for the following security scan results. For each finding,
    provide the exact code change required to fix the issue.

    Scan Data:
    {truncated_data}

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
        raw_response = _call_gemini_api(prompt)
        # Validate the raw JSON response against the Pydantic model
        remediation = RemediationResult.model_validate_json(raw_response)
        return remediation
    except (json.JSONDecodeError, ValidationError) as e:
        logging.error(
            f"Failed to validate LLM response for remediation plan: {e}")
        logging.debug(f"Invalid raw response received:\n{raw_response}")
        raise ValueError(
            "LLM returned an invalid or malformed JSON response.") from e

# ==============================================================================
# 4. Example Usage
# ==============================================================================


if __name__ == "__main__":
    # --- Mock Scan Data (replace with your actual data) ---
    mock_scan_data = {
        "sca": {
            "Results": [{
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.20",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Command Injection in lodash",
                        "Description": "A command injection vulnerability..."
                    },
                    {
                        "VulnerabilityID": "CVE-2022-0123",
                        "PkgName": "minimist",
                        "InstalledVersion": "1.2.5",
                        "FixedVersion": "1.2.6",
                        "Severity": "CRITICAL",
                        "Title": "Prototype Pollution in minimist",
                        "Description": "A prototype pollution vulnerability..."
                    }
                ]
            }]
        },
        "sast": {
            "results": [
                {
                    "check_id": "python.lang.security.exec-use.exec-use",
                    "path": "app/utils.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Use of `exec` is security-sensitive.",
                        "severity": "ERROR",
                        "lines": "exec(user_input)"
                    }
                }
            ]
        }
    }

    if not llm:
        logging.warning(
            "Cannot run example usage because Gemini API is not configured.")
    else:
        print("--- 1. Analyzing Scan Vulnerabilities ---")
        try:
            analysis_result = analyze_scan_vulnerabilities(mock_scan_data)
            print("Summary:", analysis_result.summary)
            print("Top Vulnerabilities:")
            for vuln in analysis_result.top_vulnerabilities:
                print(
                    f"  - Name: {vuln.name}, Severity: {vuln.severity}, File: {vuln.file}")
                print(f"    PoC: {vuln.poc}")
        except (ValueError, ConnectionError) as e:
            print(f"Error: {e}")

        print("\n" + "="*50 + "\n")

        print("--- 2. Generating Remediation Plan ---")
        try:
            remediation_plan = generate_remediation_plan(mock_scan_data)
            print("Remediation Steps:")
            for rem in remediation_plan.remediations:
                print(f"  - Issue: {rem.issue}")
                print(f"    Fix:\n```python\n{rem.fix_code}\n```")
                print(f"    Explanation: {rem.explanation}")
        except (ValueError, ConnectionError) as e:
            print(f"Error: {e}")
