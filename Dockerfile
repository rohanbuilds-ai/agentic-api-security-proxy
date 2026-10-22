# ==============================================================================
# Agentic API Security Proxy - Multi-Service Dockerfile
#
# Builds a lightweight, secure container for running either the Proxy Gateway
# or the Mock Upstream Backend service as a non-privileged user.
# ==============================================================================

FROM python:3.13-slim

# Set security and runtime environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Create unprivileged system group and user
RUN groupadd --system --gid 1001 appgroup && \
    useradd --system --uid 1001 --gid appgroup --no-create-home appuser

# Set working directory and create data directory for persistent SQLite storage
WORKDIR /app
RUN mkdir -p /data && chown -R appuser:appgroup /data

# Install Python dependencies with pinned requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and configuration
COPY src/ /app/src/
COPY config/ /app/config/

# Ensure application files are owned by the non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser:appgroup

# Default port for proxy service
EXPOSE 8000 8001

# Default command runs the Proxy service; overridden in docker-compose.yml for upstream
CMD ["python", "-m", "src.proxy.app"]
