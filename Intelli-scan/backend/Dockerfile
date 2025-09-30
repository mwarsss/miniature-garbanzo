# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Add the local user's binary directory to the PATH
ENV PATH="/root/.local/bin:${PATH}"

# Set the working directory in the container
WORKDIR /app

# Copy the dependency file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code to the working directory
COPY . .

# Run main.py when the container launches
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]