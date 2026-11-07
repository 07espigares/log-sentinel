import io
import json
import urllib.error
from datetime import datetime

import pytest

from logsentinel.detectors import Finding, Severity
from logsentinel.notifier import (
    DiscordNotifier,
    NotifyError,
    TelegramNotifier,
    WebhookNotifier,
    build_notifier,
    format_message,
)

FINDING = Finding(
    Severity.CRITICAL,
    "success_after_failures",
    "Acceso correcto de 'backup' desde 203.0.113.9 tras 8 fallos",
    datetime(2026, 9, 25, 15, 41, 14),
    datetime(2026, 9, 25, 15, 42, 29),
    8,
    ip="203.0.113.9",
    user="backup",
    mitre="T1078 Valid Accounts",
    details="posible credencial adivinada",
)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Capture:
    def __init__(self):
        self.request = None

    def __call__(self, request, timeout):
        self.request = request
        return FakeResponse(b"{}")

    def payload(self):
        return json.loads(self.request.data.decode())


def test_message_has_severity_title_and_mitre():
    msg = format_message(FINDING, host="srv-web01")
    assert "CRÍTICA" in msg and "backup" in msg
    assert "T1078 Valid Accounts" in msg and "srv-web01" in msg


def test_telegram_sends_chat_id_and_text():
    cap = Capture()
    TelegramNotifier("TOKEN123", "999").send(FINDING, "srv", opener=cap)
    assert cap.request.full_url == "https://api.telegram.org/botTOKEN123/sendMessage"
    body = cap.payload()
    assert body["chat_id"] == "999" and "backup" in body["text"]


def test_discord_sends_content():
    cap = Capture()
    DiscordNotifier("https://discord.test/webhook").send(FINDING, opener=cap)
    assert cap.request.full_url == "https://discord.test/webhook"
    assert "backup" in cap.payload()["content"]


def test_webhook_sends_structured_finding():
    cap = Capture()
    WebhookNotifier("https://my.test/hook").send(FINDING, "srv", opener=cap)
    body = cap.payload()
    assert body["finding"]["rule"] == "success_after_failures"
    assert body["finding"]["severity"] == "CRÍTICA" and body["host"] == "srv"


def test_network_error_becomes_notifyerror():
    def broken(request, timeout):
        raise urllib.error.URLError("sin red")

    with pytest.raises(NotifyError):
        DiscordNotifier("https://x.test").send(FINDING, opener=broken)


def test_build_notifier_reads_environment():
    env = {
        "TELEGRAM_BOT_TOKEN": "t",
        "TELEGRAM_CHAT_ID": "c",
        "DISCORD_WEBHOOK_URL": "https://d.test",
        "LOGSENTINEL_WEBHOOK_URL": "https://w.test",
    }
    assert isinstance(build_notifier("telegram", env), TelegramNotifier)
    assert isinstance(build_notifier("discord", env), DiscordNotifier)
    assert isinstance(build_notifier("webhook", env), WebhookNotifier)


def test_build_notifier_missing_credentials():
    with pytest.raises(NotifyError, match="TELEGRAM"):
        build_notifier("telegram", {})
    with pytest.raises(NotifyError, match="DISCORD"):
        build_notifier("discord", {})
    with pytest.raises(NotifyError, match="desconocido"):
        build_notifier("sms", {})


def test_http_error_becomes_notifyerror():
    def rejected(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)

    with pytest.raises(NotifyError, match="429"):
        TelegramNotifier("TOKEN", "1").send(FINDING, opener=rejected)


def test_error_message_never_contains_the_secret_url():
    secret = "https://discord.test/api/webhooks/123/SECRETO"

    def broken(request, timeout):
        raise ValueError(f"URL rara: {request.full_url}")

    with pytest.raises(NotifyError) as exc:
        DiscordNotifier(secret).send(FINDING, opener=broken)
    assert "SECRETO" not in str(exc.value)


@pytest.mark.parametrize("url", ["discord.com/api/webhooks/1/SECRETO", "file:///etc/passwd", "http://discord.test/x"])
def test_bad_discord_url_is_rejected_at_startup(url):
    with pytest.raises(NotifyError, match="https://") as exc:
        build_notifier("discord", {"DISCORD_WEBHOOK_URL": url})
    assert "SECRETO" not in str(exc.value)


def test_generic_webhook_accepts_http():
    assert build_notifier("webhook", {"LOGSENTINEL_WEBHOOK_URL": "http://10.0.0.5:8080/hook"}).name == "webhook"


def test_control_characters_do_not_reach_the_message():
    evil = Finding(
        Severity.HIGH, "x", "Prueba de \x1b[2Jusuarios", datetime(2026, 1, 1), datetime(2026, 1, 1), 1, details="a\x07b"
    )
    msg = format_message(evil)
    assert "\x1b" not in msg and "\x07" not in msg
    assert "\\x1b[2J" in msg


# --- reintentos (noviembre de 2026) -----------------------------------------


class Flaky:
    """Un notificador que falla `fails` veces antes de funcionar."""

    name = "prueba"

    def __init__(self, fails, retryable=True):
        self.fails, self.retryable, self.calls = fails, retryable, 0

    def send(self, finding, host=""):
        self.calls += 1
        if self.calls <= self.fails:
            raise NotifyError("caído", retryable=self.retryable)


def test_a_failed_alert_is_retried():
    from logsentinel.notifier import deliver

    waits = []
    notifier = Flaky(fails=2)
    deliver(notifier, FINDING, wait=waits.append)
    assert notifier.calls == 3 and waits == [2, 5]


def test_it_gives_up_after_three_tries():
    from logsentinel.notifier import deliver

    notifier = Flaky(fails=5)
    with pytest.raises(NotifyError):
        deliver(notifier, FINDING, wait=lambda s: None)
    assert notifier.calls == 3


def test_a_wrong_token_is_not_retried():
    from logsentinel.notifier import deliver

    notifier = Flaky(fails=5, retryable=False)
    with pytest.raises(NotifyError):
        deliver(notifier, FINDING, wait=lambda s: None)
    assert notifier.calls == 1


@pytest.mark.parametrize(("code", "retryable"), [(429, True), (502, True), (401, False), (404, False)])
def test_which_http_errors_are_worth_retrying(code, retryable):
    import urllib.error

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, code, "x", {}, None)

    with pytest.raises(NotifyError) as exc:
        WebhookNotifier("https://hooks.example/x").send(FINDING, opener=opener)
    assert exc.value.retryable is retryable
