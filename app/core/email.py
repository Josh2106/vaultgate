"""Outbound email behind a provider interface.

Production would add an SES / SMTP / Postmark implementation; the console
backend logs messages (useful in development) and the memory backend lets
tests assert on what was "sent".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import structlog

from app.core.config import EmailBackend

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class EmailMessage:
    to: str
    subject: str
    body: str


class EmailProvider(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class ConsoleEmailProvider:
    async def send(self, message: EmailMessage) -> None:
        log.info("email_sent", to=message.to, subject=message.subject, body=message.body)


@dataclass
class MemoryEmailProvider:
    outbox: list[EmailMessage] = field(default_factory=list)

    async def send(self, message: EmailMessage) -> None:
        self.outbox.append(message)


def build_email_provider(backend: EmailBackend) -> EmailProvider:
    if backend is EmailBackend.MEMORY:
        return MemoryEmailProvider()
    return ConsoleEmailProvider()
