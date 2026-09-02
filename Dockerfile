FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    nmap \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source code
COPY src/ src/

# Create reports directory
RUN mkdir -p /app/reports

# Default entrypoint
ENTRYPOINT ["aegisx"]
CMD ["--help"]
