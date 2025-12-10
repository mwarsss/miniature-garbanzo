# Stage 1: Builder stage to get trivy and semgrep
FROM python:3.11 AS builder

# Install curl and pip
RUN apt-get update && apt-get install -y curl python3-pip git

# Install Trivy
RUN curl -L "https://github.com/aquasecurity/trivy/releases/download/v0.67.2/trivy_0.67.2_Linux-64bit.tar.gz" -o trivy.tar.gz && \
    tar -zxvf trivy.tar.gz && \
    mv trivy /usr/local/bin/trivy && \
    rm trivy.tar.gz

# Install Semgrep with retries and a longer timeout
# Download Semgrep wheel
RUN pip3 download --no-deps semgrep==1.144.1 -d /tmp/semgrep-wheel

# Install Semgrep from the downloaded wheel
RUN pip3 install /tmp/semgrep-wheel/semgrep-1.144.1*.whl

# Clean up
RUN rm -rf /tmp/semgrep-wheel

# Stage 2: Final application image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Install git
RUN apt-get update && apt-get install -y git --no-install-recommends

# Copy trivy and semgrep from the builder stage
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/semgrep

# Copy dependency file
COPY requirements.txt .

# Install Python dependencies with retries and a longer timeout
RUN pip install --retries 5 --timeout 60 --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port
EXPOSE 8000

# Run the application
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port $PORT"]
