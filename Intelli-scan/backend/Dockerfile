# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# === ADD OSV-SCANNER INSTALLATION (THE RIGHT WAY) ===
# Install golang, which is the required installer for osv-scanner
RUN apt-get update && apt-get install -y golang git nodejs npm

# Use the official Go installer to get the latest version of osv-scanner
# This is more stable than a direct download link
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Copy the dependency file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code to the working directory
COPY . .

# Run main.py when the container launches
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]