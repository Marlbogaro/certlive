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
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import IO, Iterable, Optional

import certstream


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


def _on_error(instance, exception) -> None:  # noqa: ANN001 - signature imposée
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
