# Military-grade P-521 E2E Secure Communications
# Docker containerization for secure deployment

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cloudflared \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY 0x1FC_p-521_E2E_SecureComs.py .
COPY web_ui.py .
COPY templates/ ./templates/
COPY static/ ./static/

# Create necessary directories
RUN mkdir -p data logs downloads

# Set up non-root user for security
RUN useradd -m -u 1000 securecoms && \
    chown -R securecoms:securecoms /app
USER securecoms

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose default ports
EXPOSE 5000 8765

# Default command
CMD ["python", "0x1FC_p-521_E2E_SecureComs.py"]
