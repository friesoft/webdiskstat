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

# Expose FastAPI server port
EXPOSE 8080

# Environment variables with sensible defaults
ENV SCAN_INTERVAL=86400
ENV FORCE_INITIAL_SCAN=false
ENV GDU_IGNORE_DIRS=""
ENV INPUT_TYPE="gdu"

# Run the Uvicorn ASGI server as the single foreground process (PID 1)
ENTRYPOINT ["sh", "-c", "webdiskstat-server --port 8080 --scan-dir /scan --output /app/index.html --scan-interval $SCAN_INTERVAL --force-initial-scan $FORCE_INITIAL_SCAN --gdu-ignore-dirs \"$GDU_IGNORE_DIRS\" --input-type $INPUT_TYPE"]
