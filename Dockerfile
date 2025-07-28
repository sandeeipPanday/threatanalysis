FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    jq \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy for vulnerability scanning
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb generic main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy

# Install Grype for additional vulnerability scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the threat analysis script
COPY threat_analyzer.py .
COPY entrypoint.sh .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Create output directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DOCKER_HOST=unix:///var/run/docker.sock

# Entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
