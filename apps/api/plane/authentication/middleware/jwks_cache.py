# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import json
import logging
import threading
import time
import urllib.request

import jwt

LIFESPAN_SECONDS = 3600
FETCH_TIMEOUT_SECONDS = 2
FAILURE_BACKOFF_SECONDS = 30
STALE_GRACE_SECONDS = 24 * 3600

logger = logging.getLogger("plane.authentication")


class JwksUnavailable(Exception):
    pass


def jwks_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/jwks.json"


def http_get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
        return response.read()


def _is_signing_key(key: jwt.PyJWK) -> bool:
    return bool(key.key_id) and key.public_key_use in ("sig", None)


def _import_key(jwk):
    try:
        return jwt.PyJWK(jwk)
    except Exception as exc:
        kid = jwk.get("kid", "-") if isinstance(jwk, dict) else "-"
        logger.warning("mPass JWKS key skipped: kid=%s error=%s", kid, type(exc).__name__)
        return None


def parse_signing_keys(body) -> dict:
    """The set's signing keys by kid; a key that fails to import is skipped, not fatal."""
    document = json.loads(body)
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise JwksUnavailable("JWKS has no keys array")
    imported = (_import_key(jwk) for jwk in document["keys"])
    keys = {key.key_id: key for key in imported if key is not None and _is_signing_key(key)}
    if not keys:
        raise JwksUnavailable("JWKS has no usable signing keys")
    return keys


class JwksCache:
    """Signing keys per issuer, shared by the worker's threads.

    The lock guards only the bookkeeping; the HTTP fetch runs outside it, one in
    flight per issuer. A failed fetch backs the issuer off for
    FAILURE_BACKOFF_SECONDS, and a previously fetched set younger than
    STALE_GRACE_SECONDS keeps being served meanwhile, so an issuer outage does
    not turn into refused logins.
    """

    def __init__(
        self,
        fetcher=http_get,
        clock=time.monotonic,
        wait_timeout=FETCH_TIMEOUT_SECONDS * 2,
    ):
        self._fetcher = fetcher
        self._clock = clock
        self._wait_timeout = wait_timeout
        self._condition = threading.Condition()
        self._entries = {}
        self._failed_at = {}
        self._in_flight = set()

    def keys_for(self, issuer: str, refresh: bool = False) -> dict:
        """refresh=True is the key-rotation path: refetch unless the set is younger than the backoff."""
        with self._condition:
            keys = self._claim_or_wait(issuer, refresh)
        if keys is not None:
            return keys
        return self._fetch(issuer)

    def _claim_or_wait(self, issuer: str, refresh: bool):
        deadline = time.monotonic() + self._wait_timeout
        while True:
            keys = self._cached_keys(issuer, refresh)
            if keys is not None:
                return keys
            if issuer not in self._in_flight:
                self._in_flight.add(issuer)
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JwksUnavailable(f"JWKS fetch for {issuer} is still in flight")
            self._condition.wait(remaining)

    def _cached_keys(self, issuer: str, refresh: bool):
        entry = self._entries.get(issuer)
        if entry and self._is_fresh(entry, refresh):
            return entry["keys"]
        if self._backing_off(issuer) or (entry and issuer in self._in_flight and not refresh):
            return self._serve_stale(issuer, entry)
        return None

    def _fetch(self, issuer: str) -> dict:
        try:
            keys = parse_signing_keys(self._fetcher(jwks_url(issuer)))
        except Exception as exc:
            with self._condition:
                return self._record_failure(issuer, exc)
        else:
            with self._condition:
                return self._record_success(issuer, keys)
        finally:
            with self._condition:
                self._in_flight.discard(issuer)
                self._condition.notify_all()

    def _record_success(self, issuer: str, keys: dict) -> dict:
        self._failed_at.pop(issuer, None)
        self._entries[issuer] = {"keys": keys, "fetched_at": self._clock()}
        return keys

    def _record_failure(self, issuer: str, error: Exception) -> dict:
        self._failed_at[issuer] = self._clock()
        logger.warning("mPass JWKS fetch failed: issuer=%s error=%s", issuer, type(error).__name__)
        return self._serve_stale(issuer, self._entries.get(issuer))

    def _serve_stale(self, issuer: str, entry) -> dict:
        if not entry or self._age(entry) >= STALE_GRACE_SECONDS:
            raise JwksUnavailable(f"no usable JWKS for {issuer}")
        if not self._is_fresh(entry, refresh=False):
            logger.warning(
                "mPass JWKS is stale, serving the last good set: issuer=%s age_seconds=%d",
                issuer,
                self._age(entry),
            )
        return entry["keys"]

    def _is_fresh(self, entry, refresh: bool) -> bool:
        return self._age(entry) < (FAILURE_BACKOFF_SECONDS if refresh else LIFESPAN_SECONDS)

    def _age(self, entry) -> float:
        return self._clock() - entry["fetched_at"]

    def _backing_off(self, issuer: str) -> bool:
        failed_at = self._failed_at.get(issuer)
        return failed_at is not None and self._clock() - failed_at < FAILURE_BACKOFF_SECONDS
