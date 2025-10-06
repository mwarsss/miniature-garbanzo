# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# === ADD OSV-SCANNER INSTALLATION ===
# Install wget and unzip which are needed to download the scanner
RUN apt-get update && apt-get install -y wget unzip

# Download and install the OSV-Scanner for Linux AMD64
RUN wget https://github.com/google/osv-scanner/releases/download/v2.2.3/osv-scanner_2.2.3_linux_amd64 -O /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner
# ====================================

# Copy the dependency file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code to the working directory
COPY . .

# Run main.py when the container launches
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]