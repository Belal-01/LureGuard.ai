# LureGuard.ai

An Open-Source Host-Level SIEM with AI-Driven Detection and Dynamic Honeypot Deception for SSH.

## Quick Start

```bash
./install.sh          # interactive: picks LLM provider
docker compose up -d  # standard (Cloud LLM / Disabled)

# OR with local Ollama:
docker compose --profile local-llm up -d
```

## Team
- مجد الخلف   — Core Platform + DB + Enforcement + Deployment
- علي أحمد    — Data Pipeline + Feature Extraction
- جلال كوبا   — ML Modeling + Evaluation
- بلال خبية   — Wazuh + Cowrie + BYOLLM + Alerting
