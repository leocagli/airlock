"""Text detectors. Each module exposes detect(segment) -> list[Finding]."""

from . import exfil, hidden, injection, secrets

TEXT_DETECTORS = (injection.detect, hidden.detect, exfil.detect, secrets.detect)

__all__ = ["TEXT_DETECTORS"]
