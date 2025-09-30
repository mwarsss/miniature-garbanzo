# miniature-garbanzo
An AI agent that actually reads your code to find the SAST vulnerabilities that matter. Stop chasing ghosts. 👻

# Intelli-Scan: An AI-Augmented SAST Agent

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**An AI agent that actually reads your code to find the SAST vulnerabilities that matter. The goal is to find the signal in the noise. Signal, not noise.**

---

### The Problem
Your SAST scanner just dumped 157 "critical" alerts on you for your last push. Let's be real, most of them are probably noise. **Alert fatigue** is a legit problem, and it's ironically making us less secure by hiding real threats in a flood of low-context false positives. Chasing these ghosts wastes dev time and money.

### The Solution
This isn't just another scanner. It's an **AI Security Agent** that acts as an intelligence layer on top of standard SAST tools. It uses a Retrieval-Augmented Generation (RAG) model to actually *read* the relevant parts of your code and understands the application's topology to see what's *actually* exploitable.



Think of it as a junior security analyst in a box—it does the initial triage so you can focus on the real fires.

### Core Objectives
1.  **Produce a baseline vulnerability report** from an automated scan.
2.  **Generate a tailored remediation plan** and calculate a contextual risk score using the AI engine.
3.  **Demonstrate a measurable reduction** in high-priority alerts.

### Tech Stack
-   **Backend:** Python (FastAPI)
-   **Orchestration:** Docker
-   **Scanner:** OSV-Scanner
-   **AI Core:** LangChain, FAISS, Google Gemini API

### 🚀 Quick Start (MVP)

This project is containerized with Docker. No need to install a million dependencies on your machine.

1.  **Clone the repo:**
    ```bash
    git clone [https://github.com/your-username/intelli-scan.git](https://github.com/your-username/intelli-scan.git)
    cd intelli-scan
    ```

2.  **Build and run the container:**
    ```bash
    docker-compose up --build
    ```

3.  **Run a scan:**
    Open a new terminal and send a POST request to the API with the repo you want to scan.
    ```bash
    curl -X POST -H "Content-Type: application/json" \
    -d '{"repo_url": "[https://github.com/example/vulnerable-repo](https://github.com/example/vulnerable-repo)"}' \
    http://localhost:8000/scan
    ```
    Check the terminal where docker-compose is running to see the JSON output.

---
**Project Status:** This is a capstone project for the Bachelor of Technology in Software Engineering program. It is currently under active development.
