# SentinelForge - Proof-carrying release gate
# Dockerfile for deploying FastAPI control plane + dashboard
# Uses Python 3.12, installs SentinelForge, runs sentinelforge-api

FROM python:3.12-slim

# Security: non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# System deps for git + gh CLI + build
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI for PR creation
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml README.md ./
COPY src/ src/

# Install SentinelForge
RUN pip install --no-cache-dir -e .

# Copy rest of repo (config, docs, examples)
COPY config/ config/
COPY docs/ docs/
COPY examples/ examples/
COPY .env.example .env.example

# Create .sentinelforge directory with proper perms and home dir for appuser (fixes permission denied /home/appuser)
RUN mkdir -p .sentinelforge/control .sentinelforge/exploits .sentinelforge/keys .sentinelforge/attestations .sentinelforge/memory /home/appuser/.sentinelforge && \
    chown -R appuser:appuser /app /home/appuser

# Expose control plane port
EXPOSE 8741

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:8741/health', timeout=2); exit(0 if r.status_code==200 else 1)"

# Switch to non-root
USER appuser

# Env defaults (override via deployment platform env vars)
ENV SENTINELFORGE_ALLOWED_ROOTS=/app
ENV SENTINELFORGE_DB_PATH=/app/.sentinelforge/control.db
ENV SENTINELFORGE_HOST=0.0.0.0
ENV PORT=8741
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Run control plane API
# Uses sentinelforge-api entrypoint which reads DATABASE_PATH, ALLOWED_ROOTS, etc from env
CMD ["sentinelforge-api"]
# For custom host/port: CMD ["uvicorn", "sentinelforge.server:application_from_environment", "--host", "0.0.0.0", "--port", "8741"]
