"""Multi-channel notifications: SendGrid email + Slack Block Kit."""
from core.services.notifications import dispatcher, email_service, slack_service, templates

__all__ = ["dispatcher", "email_service", "slack_service", "templates"]
