# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# === ADD TRIVY & SEMGREP INSTALLATION ===
# Install curl (for downloading trivy), git, nodejs, npm, and python3-pip (for semgrep)
RUN apt-get update && apt-get install -y curl git nodejs npm python3-pip

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep
RUN pip3 install semgrep

# Copy the dependency file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code to the working directory
COPY . .

# Run main.py when the container launches
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]