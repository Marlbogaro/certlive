#!/usr/bin/env python3
"""certlive - Flux en temps réel des domaines présents dans les certificats TLS.

Ce script se connecte au flux public `certstream` (agrégateur des logs
Certificate Transparency) et affiche, pour chaque certificat nouvellement
émis, la liste des domaines (CN + SAN) qui lui sont associés, quel que
soit le type de certificat (DV, OV, EV, wildcard, etc.).

Inspiré de https://certstream.calidog.io/.

Exemples d'utilisation::

    # Afficher tous les domaines en continu
    python certlive.py

    # Enregistrer les domaines dans un fichier
    python certlive.py -o domains.txt

    # Filtrer sur un mot-clé (sous-chaîne, insensible à la casse)
    python certlive.py -k paypal

    # Ignorer les domaines wildcard (*.example.com)
    python certlive.py --no-wildcard

    # Afficher aussi l'émetteur du certificat
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
    """Rend ``certstream`` compatible avec ``websocket-client`` >= 1.0.

    À partir de la version 1.0 de ``websocket-client``, les callbacks
    ``on_open``/``on_message``/``on_error`` reçoivent l'instance
    ``WebSocketApp`` en premier argument. Or, ``certstream`` 1.11 utilise
    encore les anciennes signatures (sans cet argument), ce qui produit
    l'erreur::

        error from callback ...CertStreamClient._on_error() takes 2
        positional arguments but 3 were given

    On réécrit les trois méthodes pour accepter les deux conventions.
    """

    client_cls = _certstream_core.CertStreamClient

    # Ne patcher qu'une seule fois, même si ``main`` est appelé plusieurs fois.
    if getattr(client_cls, "_certlive_patched", False):
        return

    logger = _certstream_core.certstream_logger

    def _on_open(self, *_args):
        logger.info("Connection established to CertStream! Listening for events...")
        if self.on_open_handler:
            self.on_open_handler()

    def _on_message(self, *args):
        # Compat: websocket-client >= 1.0 appelle on_message(ws, message);
        # les versions antérieures appelaient on_message(message).
        message = args[-1]
        frame = json.loads(message)

        if frame.get("message_type", None) == "heartbeat" and self.skip_heartbeats:
            return

        self.message_callback(frame, self._context)

    def _on_error(self, *args):
        # On prend toujours la dernière valeur positionnelle, qui correspond
        # à l'exception quelle que soit la version de websocket-client.
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
    """Retourne tous les domaines (CN + SAN) d'un message certstream."""
    leaf = message.get("data", {}).get("leaf_cert", {})
    all_domains = list(leaf.get("all_domains", []) or [])
    if not all_domains:
        subject_cn = (leaf.get("subject") or {}).get("CN")
        if subject_cn:
            all_domains.append(subject_cn)
    # Dé-duplication tout en préservant l'ordre d'apparition
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
    """Construit le callback appelé par certstream pour chaque message."""
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
    logging.info("Connecté au flux Certificate Transparency.")


def _on_error(exception) -> None:  # noqa: ANN001 - signature imposée
    logging.error("Erreur de connexion certstream: %s", exception)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="certlive",
        description=(
            "Récupère en temps réel les domaines associés aux certificats "
            "TLS nouvellement émis (via les logs Certificate Transparency)."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FICHIER",
        help="Fichier dans lequel ajouter les domaines (un par ligne).",
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Ne garder que les domaines contenant ce mot-clé (insensible à la casse).",
    )
    parser.add_argument(
        "--no-wildcard",
        action="store_true",
        help="Ignorer les domaines wildcard (*.exemple.com).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Afficher l'horodatage et l'émetteur en plus du domaine.",
    )
    parser.add_argument(
        "-u",
        "--url",
        default="wss://certstream.calidog.io/",
        help="URL du serveur certstream à utiliser (défaut: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # Compatibilité avec websocket-client >= 1.0 (certstream 1.11 l'ignore).
    _patch_certstream_callbacks()

    # Sortie Ctrl+C propre
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
