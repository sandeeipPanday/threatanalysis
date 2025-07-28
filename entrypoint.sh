#!/bin/bash
set -e

echo "Starting Docker Base Image Threat Analysis..."
echo "Repository path: ${REPO_PATH:-/repo}"
echo "Output directory: ${OUTPUT_DIR:-/app/reports}"

# Check if Docker socket is available
if [ ! -S /var/run/docker.sock ]; then
    echo "Warning: Docker socket not found. Image metadata analysis will be limited."
fi

# Update vulnerability databases
echo "Updating vulnerability databases..."
trivy --cache-dir /tmp/trivy-cache image --download-db-only || echo "Failed to update Trivy database"

# Run the threat analysis
python3 /app/threat_analyzer.py \
    --repo-path "${REPO_PATH:-/repo}" \
    --output-dir "${OUTPUT_DIR:-/app/reports}"

echo "Analysis complete! Reports available in ${OUTPUT_DIR:-/app/reports}"

# Keep container running if in interactive mode
if [ -t 0 ]; then
    echo "Interactive mode detected. Container will remain running."
    exec /bin/bash
fi
