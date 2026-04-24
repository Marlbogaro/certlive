#!/usr/bin/env python3
"""certlive - Real-time domain stream from CT logs (no certstream/Docker needed).

Queries Certificate Transparency logs directly via HTTP (RFC 6962).

Usage::

    python certlive.py -o domains.txt
    python certlive.py --date 2026-04-17 --logs https://ct.cloudflare.com/logs/nimbus2026/
    python certlive.py --since 2026-04-18T20:00Z --until 2026-04-18T21:00Z
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import IO, Callable, Iterable, Optional

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
DEFAULT_BATCH = 256
DEFAULT_POLL_INTERVAL = 10.0
HTTP_TIMEOUT = 20.0
# CT log Maximum Merge Delay: 24 h in milliseconds.
MMD_MS = 24 * 3600 * 1000


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO-8601 datetime string; assumes UTC if no timezone given."""
    normalized = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _decode_entry(entry: dict) -> Optional[tuple[bytes, int]]:
    """Decode a get-entries entry and return ``(cert_der, timestamp_ms)``."""
    try:
        leaf_input = base64.b64decode(entry.get("leaf_input", ""))
        extra_data = base64.b64decode(entry.get("extra_data", ""))
    except Exception:
        return None
    cert_der = _parse_merkle_leaf(leaf_input, extra_data)
    if cert_der is None:
        return None
    try:
        timestamp_ms = int.from_bytes(leaf_input[2:10], "big")
    except Exception:
        timestamp_ms = int(time.time() * 1000)
    return cert_der, timestamp_ms


def _find_index_for_timestamp(
    session: requests.Session,
    log_url: str,
    target_ts_ms: int,
    tree_size: int,
    stop_event: Optional[threading.Event] = None,
    label: str = "",
) -> int:
    """Return the smallest index ``i`` in ``[0, tree_size)`` where ``ts(i) >= target``.

    Returns 0 if target precedes all entries, or tree_size if it follows all.
    Uses binary search (~log2(tree_size) requests).
    """
    if tree_size <= 0:
        return 0
    lo, hi = 0, tree_size
    step = 0
    max_steps = max(1, (tree_size).bit_length())
    while lo < hi:
        if stop_event is not None and stop_event.is_set():
            return lo
        mid = (lo + hi) // 2
        step += 1
        if label and step % 3 == 0:
            sys.stderr.write(
                f"\r[{label}] binary search {step}/{max_steps} "
                f"(window {hi - lo:,} entries)   "
            )
            sys.stderr.flush()
        try:
            resp = session.get(
                log_url + "ct/v1/get-entries",
                params={"start": mid, "end": mid},
                timeout=HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            entries = resp.json().get("entries") or []
        except requests.RequestException:
            time.sleep(1.0)
            continue
        if not entries:
            hi = mid
            continue
        decoded = _decode_entry(entries[0])
        if decoded is None:
            lo = mid + 1
            continue
        _, ts_ms = decoded
        if ts_ms < target_ts_ms:
            lo = mid + 1
        else:
            hi = mid
    if label:
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()
    return lo


def _fetch_log_list(target_date: Optional[datetime] = None) -> list[dict]:
    """Fetch the CT log list, filtered by state and temporal interval.

    For historical mode (target_date given): include usable/retired/readonly logs
    covering that date. For real-time mode: only usable logs covering today.
    """
    resp = requests.get(LOG_LIST_URL, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    ref = target_date or datetime.now(timezone.utc)
    allowed_states = {"usable", "retired", "readonly"} if target_date else {"usable"}
    logs: list[dict] = []
    for operator in data.get("operators", []):
        for log in operator.get("logs", []):
            state = log.get("state") or {}
            if not (set(state.keys()) & allowed_states):
                continue
            interval = log.get("temporal_interval")
            if interval:
                try:
                    start = datetime.fromisoformat(
                        interval["start_inclusive"].replace("Z", "+00:00")
                    )
                    end = datetime.fromisoformat(
                        interval["end_exclusive"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError):
                    continue
                if not (start <= ref < end):
                    continue
            url = log.get("url")
            if not url:
                continue
            logs.append(
                {
                    "url": url.rstrip("/") + "/",
                    "name": log.get("description") or url,
                    "operator": operator.get("name", ""),
                }
            )
    return logs


def _parse_merkle_leaf(leaf_input: bytes, extra_data: bytes) -> Optional[bytes]:
    """Extract DER certificate bytes from a MerkleTreeLeaf TLS structure.

    Returns None if the structure is malformed or of an unknown type.
    """
    # MerkleTreeLeaf: version(1) leaf_type(1) + TimestampedEntry
    # TimestampedEntry: timestamp(8) entry_type(2) signed_entry extensions(2+)
    if len(leaf_input) < 12:
        return None
    entry_type = int.from_bytes(leaf_input[10:12], "big")
    if entry_type == 0:
        # x509_entry: ASN.1Cert = uint24 length + DER
        if len(leaf_input) < 15:
            return None
        cert_len = int.from_bytes(leaf_input[12:15], "big")
        end = 15 + cert_len
        if end > len(leaf_input):
            return None
        return leaf_input[15:end]
    if entry_type == 1:
        # precert_entry: signed cert is the first element of extra_data (uint24 len + DER).
        if len(extra_data) < 3:
            return None
        cert_len = int.from_bytes(extra_data[0:3], "big")
        end = 3 + cert_len
        if end > len(extra_data):
            return None
        return extra_data[3:end]
    return None


def _extract_cert_info(cert_der: bytes, timestamp_ms: int) -> Optional[dict]:
    """Parse a DER certificate and return CN, SANs, and issuer."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception:
        return None

    cn: Optional[str] = None
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            cn = attrs[0].value
    except Exception:
        pass

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    domains: list[str] = []
    seen: set[str] = set()
    for candidate in ([cn] if cn else []) + sans:
        if candidate and candidate not in seen:
            seen.add(candidate)
            domains.append(candidate)

    issuer_o = ""
    try:
        attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if attrs:
            issuer_o = attrs[0].value
    except Exception:
        pass

    return {
        "domains": domains,
        "timestamp": timestamp_ms / 1000.0,
        "issuer": issuer_o or "?",
    }


class _LogPoller(threading.Thread):
    """Poll a CT log and invoke ``callback`` for each certificate."""

    def __init__(
        self,
        log: dict,
        callback: Callable[[dict, str], None],
        stop_event: threading.Event,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        batch_size: int = DEFAULT_BATCH,
    ) -> None:
        super().__init__(name=f"ct-{log['name'][:30]}", daemon=True)
        self._log = log
        self._url = log["url"]
        self._name = log["name"]
        self._callback = callback
        self._stop_event = stop_event
        self._poll_interval = poll_interval
        self._batch = batch_size
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "certlive-direct/1.0"
        self._index = 0

    def _get(self, path: str, **params) -> dict:
        resp = self._session.get(
            self._url + path, params=params, timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()

    def run(self) -> None:  # noqa: D401
        try:
            sth = self._get("ct/v1/get-sth")
            self._index = int(sth.get("tree_size", 0))
            logging.info("[%s] connected (tree_size=%d)", self._name, self._index)
        except Exception as exc:
            logging.warning("[%s] initial get-sth failed: %s", self._name, exc)
            return

        while not self._stop_event.is_set():
            try:
                sth = self._get("ct/v1/get-sth")
                tree_size = int(sth.get("tree_size", 0))
            except Exception as exc:
                logging.warning("[%s] get-sth: %s", self._name, exc)
                self._stop_event.wait(self._poll_interval)
                continue

            while self._index < tree_size and not self._stop_event.is_set():
                end = min(self._index + self._batch - 1, tree_size - 1)
                try:
                    data = self._get(
                        "ct/v1/get-entries", start=self._index, end=end
                    )
                except Exception as exc:
                    logging.warning("[%s] get-entries: %s", self._name, exc)
                    break

                entries = data.get("entries") or []
                if not entries:
                    break

                for entry in entries:
                    self._process_entry(entry)

                self._index += len(entries)

            self._stop_event.wait(self._poll_interval)

    def _process_entry(self, entry: dict) -> None:
        decoded = _decode_entry(entry)
        if decoded is None:
            return
        cert_der, timestamp_ms = decoded
        info = _extract_cert_info(cert_der, timestamp_ms)
        if info and info["domains"]:
            try:
                self._callback(info, self._name)
            except Exception as exc:  # pragma: no cover
                logging.debug("[%s] callback: %s", self._name, exc)


class _ProgressAggregator:
    """Aggregate progress from multiple ``_HistoricalFetcher`` and render a single progress bar on stderr."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._totals: dict[str, int] = {}
        self._done: dict[str, int] = {}
        self._emitted: dict[str, int] = {}
        self._active: set[str] = set()
        self._t_start = time.monotonic()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def set_total(self, name: str, total: int) -> None:
        with self._lock:
            self._totals[name] = total
            self._done.setdefault(name, 0)
            self._emitted.setdefault(name, 0)
            self._active.add(name)

    def update(self, name: str, done: int, emitted: int) -> None:
        with self._lock:
            self._done[name] = done
            self._emitted[name] = emitted

    def finish(self, name: str) -> None:
        with self._lock:
            self._active.discard(name)

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="progress-bar", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.5)
        self._draw(final=True)
        sys.stderr.write("\n")
        sys.stderr.flush()

    def _run(self) -> None:
        while not self._stop.wait(0.5):
            self._draw()

    def _draw(self, final: bool = False) -> None:
        with self._lock:
            total = sum(self._totals.values())
            done = sum(self._done.values())
            emitted = sum(self._emitted.values())
            active = len(self._active)
            sources = len(self._totals)
        if total <= 0:
            return
        elapsed = time.monotonic() - self._t_start
        frac = min(1.0, done / total)
        width = 40
        filled = int(width * frac)
        bar = "█" * filled + "░" * (width - filled)
        rate = done / elapsed if elapsed > 0 else 0.0
        remaining = (total - done) / rate if rate > 0 else 0.0
        eta_m, eta_s = divmod(int(remaining), 60)
        eta_h, eta_m = divmod(eta_m, 60)
        eta = f"{eta_h:d}h{eta_m:02d}m" if eta_h else f"{eta_m:d}m{eta_s:02d}s"
        line = (
            f"\r|{bar}| {frac * 100:5.1f}% {done:,}/{total:,} "
            f"@ {rate:,.0f}/s ETA {eta} — emitted={emitted:,} "
            f"logs={active}/{sources}   "
        )
        sys.stderr.write(line)
        sys.stderr.flush()


class _HistoricalFetcher(threading.Thread):
    """Scan a CT log over a given timestamp range, then exit."""

    def __init__(
        self,
        log: dict,
        callback: Callable[[dict, str], None],
        stop_event: threading.Event,
        start_ts_ms: int,
        end_ts_ms: int,
        batch_size: int = DEFAULT_BATCH,
        progress: Optional[_ProgressAggregator] = None,
    ) -> None:
        super().__init__(name=f"hist-{log['name'][:30]}", daemon=True)
        self._url = log["url"]
        self._name = log["name"]
        self._callback = callback
        self._stop_event = stop_event
        self._start_ts_ms = start_ts_ms
        self._end_ts_ms = end_ts_ms
        self._batch = batch_size
        self._progress = progress
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "certlive-direct/1.0"
        self.scanned = 0
        self.emitted = 0

    def _get(self, path: str, **params) -> dict:
        resp = self._session.get(self._url + path, params=params, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def run(self) -> None:  # noqa: D401
        try:
            sth = self._get("ct/v1/get-sth")
            tree_size = int(sth.get("tree_size", 0))
        except Exception as exc:
            logging.error("[%s] get-sth: %s", self._name, exc)
            return
        if tree_size == 0:
            logging.warning("[%s] empty log", self._name)
            return

        logging.info("[%s] resolving index bounds…", self._name)
        start_idx = _find_index_for_timestamp(
            self._session, self._url,
            max(0, self._start_ts_ms - MMD_MS), tree_size, self._stop_event,
            label=f"{self._name} start",
        )
        end_idx = _find_index_for_timestamp(
            self._session, self._url,
            self._end_ts_ms + MMD_MS, tree_size, self._stop_event,
            label=f"{self._name} end",
        )
        if self._stop_event.is_set():
            return
        if start_idx >= end_idx:
            logging.warning(
                "[%s] no entries match the requested range.",
                self._name,
            )
            return
        total = end_idx - start_idx
        logging.info(
            "[%s] index range [%d, %d) — %d entries to scan",
            self._name, start_idx, end_idx, total,
        )
        if self._progress is not None:
            self._progress.set_total(self._name, total)

        idx = start_idx
        while idx < end_idx and not self._stop_event.is_set():
            batch_end = min(idx + self._batch - 1, end_idx - 1)
            try:
                data = self._get("ct/v1/get-entries", start=idx, end=batch_end)
            except requests.RequestException as exc:
                logging.warning("[%s] get-entries: %s", self._name, exc)
                self._stop_event.wait(2.0)
                continue
            entries = data.get("entries") or []
            if not entries:
                logging.warning("[%s] empty response at index %d", self._name, idx)
                break
            for entry in entries:
                decoded = _decode_entry(entry)
                if decoded is None:
                    continue
                cert_der, ts_ms = decoded
                self.scanned += 1
                if ts_ms < self._start_ts_ms or ts_ms >= self._end_ts_ms:
                    continue
                info = _extract_cert_info(cert_der, ts_ms)
                if info and info["domains"]:
                    try:
                        self._callback(info, self._name)
                        self.emitted += 1
                    except Exception as exc:  # pragma: no cover
                        logging.debug("[%s] callback: %s", self._name, exc)
            idx += len(entries)
            if self._progress is not None:
                self._progress.update(self._name, idx - start_idx, self.emitted)

        if self._progress is not None:
            self._progress.finish(self._name)

        logging.info(
            "[%s] done — %d certs scanned, %d with domains emitted",
            self._name, self.scanned, self.emitted,
        )


class _DiskDedup:
    """Disk-based deduplication via SQLite (near-zero RAM usage)."""

    def __init__(self) -> None:
        self._fd, self._path = tempfile.mkstemp(suffix=".db", prefix="certlive_")
        os.close(self._fd)
        self._local = threading.local()
        self._lock = threading.Lock()
        # Create table in the main thread
        conn = self._conn()
        conn.execute("CREATE TABLE seen (domain TEXT PRIMARY KEY)")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.commit()

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn = c
        return c

    def add_if_new(self, domain: str) -> bool:
        """Return ``True`` if the domain is new (and insert it)."""
        conn = self._conn()
        with self._lock:
            try:
                conn.execute("INSERT INTO seen VALUES (?)", (domain,))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def close(self) -> None:
        try:
            os.unlink(self._path)
        except OSError:
            pass


def _wrap_dedup(
    callback: Callable[[dict, str], None],
    dedup: _DiskDedup,
) -> Callable[[dict, str], None]:
    """Wrap a callback to skip already-emitted domains."""

    def wrapped(info: dict, source: str) -> None:
        fresh = [d for d in info["domains"] if dedup.add_if_new(d)]
        if fresh:
            new_info = dict(info)
            new_info["domains"] = fresh
            callback(new_info, source)

    return wrapped


def _build_callback(
    output: Optional[IO[str]],
    keyword: Optional[str],
    include_wildcard: bool,
    verbose: bool,
):
    keyword_lower = keyword.lower() if keyword else None

    def callback(info: dict, source: str) -> None:
        ts = datetime.fromtimestamp(info["timestamp"], tz=timezone.utc).isoformat()
        issuer = info["issuer"]
        for domain in info["domains"]:
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

    return callback


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="certlive",
        description="Real-time domain stream from CT logs (no certstream dependency).",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="File to append domains to (one per line).",
    )
    parser.add_argument(
        "-k", "--keyword",
        help="Only keep domains containing this keyword (case-insensitive).",
    )
    parser.add_argument(
        "--no-wildcard", action="store_true",
        help="Skip wildcard domains (*.example.com).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Also print timestamp, source, and issuer.",
    )
    parser.add_argument(
        "--logs", metavar="URL[,URL...]",
        help="CT log URLs to use (comma-separated). Default: all usable Google-listed logs.",
    )
    parser.add_argument(
        "--date", metavar="YYYY-MM-DD",
        help="Scan a full UTC day (e.g. yesterday).",
    )
    parser.add_argument(
        "--since", metavar="ISO8601",
        help="Range start (inclusive), e.g. 2026-04-17T00:00Z.",
    )
    parser.add_argument(
        "--until", metavar="ISO8601",
        help="Range end (exclusive).",
    )
    return parser.parse_args(argv)


def _resolve_logs(args: argparse.Namespace, target_date: Optional[datetime] = None) -> list[dict]:
    if args.logs:
        urls = [u.strip() for u in args.logs.split(",") if u.strip()]
        return [
            {"url": u.rstrip("/") + "/", "name": u, "operator": "custom"}
            for u in urls
        ]
    logging.info("Fetching CT log list…")
    logs = _fetch_log_list(target_date=target_date)
    logging.info("%d CT logs found.", len(logs))
    return logs


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # Resolve the historical range first (need target date to filter logs)
    historical_range: Optional[tuple[int, int]] = None
    target_date: Optional[datetime] = None
    if args.date and (args.since or args.until):
        logging.error("--date is incompatible with --since/--until.")
        return 2
    if args.date:
        try:
            day = _parse_iso_datetime(args.date + "T00:00:00Z")
        except ValueError as exc:
            logging.error("invalid --date: %s", exc)
            return 2
        start_dt = day
        end_dt = day + timedelta(days=1)
        target_date = day
        historical_range = (
            int(start_dt.timestamp() * 1000),
            int(end_dt.timestamp() * 1000),
        )
    elif args.since or args.until:
        if not (args.since and args.until):
            logging.error("--since and --until must be used together.")
            return 2
        try:
            start_dt = _parse_iso_datetime(args.since)
            end_dt = _parse_iso_datetime(args.until)
        except ValueError as exc:
            logging.error("invalid ISO date: %s", exc)
            return 2
        if end_dt <= start_dt:
            logging.error("--until must be later than --since.")
            return 2
        target_date = start_dt
        historical_range = (
            int(start_dt.timestamp() * 1000),
            int(end_dt.timestamp() * 1000),
        )

    try:
        logs = _resolve_logs(args, target_date=target_date)
    except requests.RequestException as exc:
        logging.error("Failed to fetch CT log list: %s", exc)
        return 1

    if not logs:
        logging.error("No CT logs available.")
        return 1

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    output_fp: Optional[IO[str]] = None
    dedup = _DiskDedup()
    try:
        if args.output:
            output_fp = open(args.output, "a", encoding="utf-8")

        callback = _build_callback(
            output=output_fp,
            keyword=args.keyword,
            include_wildcard=not args.no_wildcard,
            verbose=args.verbose,
        )
        callback = _wrap_dedup(callback, dedup)

        if historical_range is not None:
            start_ms, end_ms = historical_range
            logging.info(
                "Historical mode: %s → %s (UTC) across %d log(s)",
                datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc).isoformat(),
                datetime.fromtimestamp(end_ms / 1000, tz=timezone.utc).isoformat(),
                len(logs),
            )
            aggregator = _ProgressAggregator()
            aggregator.start()
            fetchers = [
                _HistoricalFetcher(
                    log=log,
                    callback=callback,
                    stop_event=stop_event,
                    start_ts_ms=start_ms,
                    end_ts_ms=end_ms,
                    progress=aggregator,
                )
                for log in logs
            ]
            for fetcher in fetchers:
                fetcher.start()
            for fetcher in fetchers:
                while fetcher.is_alive() and not stop_event.is_set():
                    fetcher.join(timeout=1.0)
            aggregator.stop()
            total_scanned = sum(f.scanned for f in fetchers)
            total_emitted = sum(f.emitted for f in fetchers)
            logging.info(
                "Historical scan done: %d certs scanned, %d emitted.",
                total_scanned, total_emitted,
            )
            return 0

        pollers = [
            _LogPoller(
                log=log,
                callback=callback,
                stop_event=stop_event,
            )
            for log in logs
        ]
        for poller in pollers:
            poller.start()

        logging.info("%d pollers started. Press Ctrl+C to quit.", len(pollers))
        while not stop_event.is_set():
            stop_event.wait(1.0)

        logging.info("Shutting down…")
        for poller in pollers:
            poller.join(timeout=2.0)
    finally:
        dedup.close()
        if output_fp is not None:
            output_fp.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
