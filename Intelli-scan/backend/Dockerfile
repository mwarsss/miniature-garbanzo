# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

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

# Expose the port the app runs on
EXPOSE 8000

# Run main.py when the container launches
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port $PORT"]
