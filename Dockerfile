# Stage 1: Build the Python distribution wheel
FROM python:3.10-alpine AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY webdiskstat/ ./webdiskstat/

# Compile python wheel package
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2: Create runtime container
FROM python:3.10-alpine

# Install minimal runtime dependencies (gdu/ncdu and shell)
RUN apk add --no-cache gdu bash curl

# Copy the built wheel from Builder and install it globally
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip3 install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Create a clean directory for application execution
WORKDIR /app

# Create a clean reports folder and declare it as a mountable volume to persist reports
RUN mkdir -p /app/reports
VOLUME ["/app/reports"]

# Expose FastAPI server port
# Environment variables with sensible defaults
ENV PORT=8080
ENV SCAN_DIR=/scan
ENV OUTPUT=/app/reports/report.json
ENV SCAN_INTERVAL=86400
ENV FORCE_INITIAL_SCAN=false
ENV GDU_IGNORE_DIRS=""

# Expose FastAPI server port
EXPOSE 8080

# Run the Uvicorn ASGI server as the single foreground process (PID 1)
ENTRYPOINT ["webdiskstat"]
