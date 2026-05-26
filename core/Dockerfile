FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 curl openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY ml/ ./ml/
RUN pip install --no-cache-dir --default-timeout=120 -e .

COPY core/ ./core/
COPY connectors/ ./connectors/
COPY config/ ./config/

EXPOSE 8080

WORKDIR /app/core
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
