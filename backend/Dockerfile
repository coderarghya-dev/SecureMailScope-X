# SecureMailScope X - Backend Dockerfile for Render Free / Cloud Deployment
FROM python:3.11-slim

# Prevent interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=10000 \
    PYTHONPATH=/app

# Install system dependencies: tshark (Wireshark command line dissector) and ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    wireshark-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend codebase
COPY . /app/

# Ensure runtime directories exist
RUN mkdir -p /app/data /app/temp_uploads /app/models /app/keys

# Expose Render standard port
EXPOSE 10000

# Start Uvicorn server dynamically binding to Render's $PORT
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
