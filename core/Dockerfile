FROM python:3.11-slim

WORKDIR /app

# Install system deps (iptables for Enforcer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (layer caching)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[llm-openai,llm-anthropic]"

# Copy source
COPY . .

EXPOSE 8080 9090

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
