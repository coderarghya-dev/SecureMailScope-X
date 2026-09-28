# SecureMailScope X - Production Dockerfile for Render Free / Cloud Deployment
FROM python:3.11-slim

# Prevent interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=10000 \
    PYTHONPATH=/app

# Install system dependencies: tshark (Wireshark command line dissector) and libcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    wireshark-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Configure non-root permissions for tshark if needed
RUN groupadd -f wireshark && \
    usermod -a -G wireshark root || true

WORKDIR /app

# Install Python backend dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend codebase
COPY backend/ /app/

# Ensure runtime directories exist
RUN mkdir -p /app/data /app/temp_uploads /app/models /app/keys

# Expose Render standard port
EXPOSE 10000

# Health check probe against root health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, os; port = os.environ.get('PORT', '10000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health')" || exit 1

# Start Uvicorn server dynamically binding to Render's $PORT
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
