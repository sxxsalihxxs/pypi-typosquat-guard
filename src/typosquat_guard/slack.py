import json
import os
import urllib.request


def send_slack_alert(text: str) -> None:
    """Post `text` to the Slack incoming webhook in $SLACK_WEBHOOK_URL."""
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        raise RuntimeError("SLACK_WEBHOOK_URL env var is not set")
    if not webhook.startswith("https://"):
        raise RuntimeError("SLACK_WEBHOOK_URL must be an https:// URL")

    payload = {"text": text}

    req = urllib.request.Request(
        webhook,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
