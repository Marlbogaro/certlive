#!/usr/bin/env python3
"""certlive - Real-time feed of domains found in TLS certificates.

This script connects to the public `certstream` feed (an aggregator of
Certificate Transparency logs) and displays, for each newly issued
certificate, the list of domains (CN + SAN) associated with it,
regardless of the certificate type (DV, OV, EV, wildcard, etc.).

Inspired by https://certstream.calidog.io/.

Usage examples::

    # Continuously display all domains
    python certlive.py

    # Save domains to a file
    python certlive.py -o domains.txt

    # Filter by keyword (substring, case-insensitive)
    python certlive.py -k paypal

    # Ignore wildcard domains (*.example.com)
    python certlive.py --no-wildcard

    # Also display the certificate issuer
    python certlive.py -v
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import IO, Iterable, Optional

import certstream
import certstream.core as _certstream_core


def _patch_certstream_callbacks() -> None:
    """Make ``certstream`` compatible with ``websocket-client`` >= 1.0.

    Starting with version 1.0 of ``websocket-client``, the
    ``on_open``/``on_message``/``on_error`` callbacks receive the
    ``WebSocketApp`` instance as their first argument. However,
    ``certstream`` 1.11 still uses the old signatures (without this
    argument), which produces the error::

        error from callback ...CertStreamClient._on_error() takes 2
        positional arguments but 3 were given

    We rewrite the three methods to accept both conventions.
    """

    client_cls = _certstream_core.CertStreamClient

    # Only patch once, even if ``main`` is called several times.
    if getattr(client_cls, "_certlive_patched", False):
        return

    logger = _certstream_core.certstream_logger

    def _on_open(self, *_args):
        logger.info("Connection established to CertStream! Listening for events...")
        if self.on_open_handler:
            self.on_open_handler()

    def _on_message(self, *args):
        # Compat: websocket-client >= 1.0 calls on_message(ws, message);
        # earlier versions called on_message(message).
        message = args[-1]
        frame = json.loads(message)

        if frame.get("message_type", None) == "heartbeat" and self.skip_heartbeats:
            return

        self.message_callback(frame, self._context)

    def _on_error(self, *args):
        # We always take the last positional value, which corresponds to
        # the exception regardless of the websocket-client version.
        ex = args[-1]
        if isinstance(ex, KeyboardInterrupt):
            raise ex
        if self.on_error_handler:
            self.on_error_handler(ex)
        logger.error(
            "Error connecting to CertStream - %s - Sleeping for a few seconds and trying again...",
            ex,
        )

    client_cls._on_open = _on_open
    client_cls._on_message = _on_message
    client_cls._on_error = _on_error
    client_cls._certlive_patched = True


def _iter_domains(message: dict) -> Iterable[str]:
    """Return all domains (CN + SAN) from a certstream message."""
    leaf = message.get("data", {}).get("leaf_cert", {})
    all_domains = list(leaf.get("all_domains", []) or [])
    if not all_domains:
        subject_cn = (leaf.get("subject") or {}).get("CN")
        if subject_cn:
            all_domains.append(subject_cn)
    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    for domain in all_domains:
        if domain and domain not in seen:
            seen.add(domain)
            yield domain


def _build_handler(
    output: Optional[IO[str]],
    keyword: Optional[str],
    include_wildcard: bool,
    verbose: bool,
):
    """Build the callback invoked by certstream for each message."""
    keyword_lower = keyword.lower() if keyword else None

    def handler(message: dict, context: dict) -> None:  # noqa: ARG001
        if message.get("message_type") != "certificate_update":
            return

        data = message.get("data", {})
        leaf = data.get("leaf_cert", {})
        issuer = (leaf.get("issuer") or {}).get("O") or "?"
        source = (data.get("source") or {}).get("name") or "?"

        seen_ts = data.get("seen") or datetime.now(timezone.utc).timestamp()
        try:
            ts = datetime.fromtimestamp(float(seen_ts), tz=timezone.utc).isoformat()
        except (TypeError, ValueError):
            ts = datetime.now(timezone.utc).isoformat()

        for domain in _iter_domains(message):
            if not include_wildcard and domain.startswith("*."):
                continue
            if keyword_lower and keyword_lower not in domain.lower():
                continue

            if verbose:
                line = f"{ts} [{source}] {domain} (issuer: {issuer})"
            else:
                line = domain

            print(line, flush=True)
            if output is not None:
                output.write(line + "\n")
                output.flush()

    return handler


def _on_open() -> None:
    logging.info("Connected to the Certificate Transparency feed.")


def _on_error(exception) -> None:  # noqa: ANN001 - signature imposed
    logging.error("certstream connection error: %s", exception)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="certlive",
        description=(
            "Fetch in real time the domains associated with newly issued "
            "TLS certificates (via Certificate Transparency logs)."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="File to append domains to (one per line).",
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Only keep domains containing this keyword (case-insensitive).",
    )
    parser.add_argument(
        "--no-wildcard",
        action="store_true",
        help="Ignore wildcard domains (*.example.com).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Also display the timestamp and issuer in addition to the domain.",
    )
    parser.add_argument(
        "-u",
        "--url",
        default="wss://certstream.calidog.io/",
        help="certstream server URL to use (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # Compatibility with websocket-client >= 1.0 (certstream 1.11 ignores it).
    _patch_certstream_callbacks()

    # Clean Ctrl+C exit
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    output_fp: Optional[IO[str]] = None
    try:
        if args.output:
            output_fp = open(args.output, "a", encoding="utf-8")

        handler = _build_handler(
            output=output_fp,
            keyword=args.keyword,
            include_wildcard=not args.no_wildcard,
            verbose=args.verbose,
        )

        certstream.listen_for_events(
            handler,
            url=args.url,
            on_open=_on_open,
            on_error=_on_error,
        )
    finally:
        if output_fp is not None:
            output_fp.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
