"""Central configuration loaded from environment variables."""
from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    """Runtime settings for CyberGuard AI."""

    APP_NAME: str = "CyberGuard AI"
    VERSION: str = "0.1.0"
    ENV: str = os.getenv("ENV", "dev")

    # AI / Groq  (no default — must be supplied via the environment)
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_BASE_URL: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")

    # Data stores
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cyberguard.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Auth
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-insecure-change-me")
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = int(os.getenv("JWT_TTL_SECONDS", "86400"))

    # Symmetric encryption for at-rest secrets (org-supplied AI provider API
    # keys). Any string works — it's stretched into a Fernet key — but it must
    # stay STABLE in production or previously-encrypted values become unreadable.
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "dev-insecure-change-me")

    # Bring-your-own-AI-provider models catalogue lives in
    # core/services/ai_client.py; only the system-default Groq creds live here.

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))

    # Chakra integration  (no defaults — supplied via the environment)
    CHAKRA_ORG_ID: str = os.getenv("CHAKRA_ORG_ID", "")
    INTERNAL_SYNC_SECRET: str = os.getenv("INTERNAL_SYNC_SECRET", "")

    # Outbound email for alert notifications (optional; alerts still hit the DB
    # and Slack without it)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_FROM: str = os.getenv("SMTP_FROM", "alerts@cyberguard.ai")

    # SendGrid (primary email transport for notifications; SMTP is the fallback)
    SENDGRID_API_KEY: str = os.getenv("SENDGRID_API_KEY", "")
    SENDGRID_API_URL: str = os.getenv(
        "SENDGRID_API_URL", "https://api.sendgrid.com/v3/mail/send"
    )
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", "security@goiratech.com")

    # Public URL of the web app, used in notification deep-links
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "https://cyberguard.goiratech.com")

    # LiveGuard integration
    LIVEGUARD_URL: str = os.getenv(
        "LIVEGUARD_URL", "https://liveguard.goiratech.com/api/errors"
    )

    # External agents
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    GITLAB_TOKEN: str = os.getenv("GITLAB_TOKEN", "")
    JIRA_URL: str = os.getenv("JIRA_URL", "")
    JIRA_USER: str = os.getenv("JIRA_USER", "")
    JIRA_TOKEN: str = os.getenv("JIRA_TOKEN", "")
    JIRA_PROJECT_KEY: str = os.getenv("JIRA_PROJECT_KEY", "SEC")
    SLACK_BOT_TOKEN: str = os.getenv("SLACK_BOT_TOKEN", "")

    # Inbound SCM webhook secrets (fallback when the org has none of its own
    # in org_settings.github_webhook_secret)
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    GITLAB_WEBHOOK_TOKEN: str = os.getenv("GITLAB_WEBHOOK_TOKEN", "")

    # External vuln feeds
    OSV_API_URL: str = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
    NVD_API_URL: str = os.getenv(
        "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
