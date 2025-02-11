FROM python:3.11-slim-bullseye AS build

# Set working directory
WORKDIR /opt/chowkidar

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    wkhtmltopdf \
    python3-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv

# Activate virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and setuptools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir \
    --no-build-isolation \
    --upgrade \
    -r requirements.txt

# Final stage
FROM python:3.11-slim-bullseye AS release
WORKDIR /opt/chowkidar

# Create user and set permissions
RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    chowkidar \
    && mkdir -p /var/log/chowkidar \
    && chown -R 1001:1001 /var/log/chowkidar

# Copy application files
COPY --chown=1001:1001 . /opt/chowkidar

# Copy virtual environment from build stage
COPY --from=build /opt/venv /opt/venv
COPY --from=build /usr /usr

# Set environment paths
ENV PATH="/opt/venv/bin:$PATH"

# Ensure docker-entrypoint.sh is executable
RUN chmod +x /opt/chowkidar/docker-entrypoint.sh

# Switch to non-root user
USER 1001

# Expose application port
EXPOSE 5000

# Set entrypoint
ENTRYPOINT ["/opt/chowkidar/docker-entrypoint.sh"]