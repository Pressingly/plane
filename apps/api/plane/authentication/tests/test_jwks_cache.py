# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Tests for the mPass JWKS cache: stale serving, per-key import failures, and
one in-flight fetch per issuer.

Run (from apps/api/):
    pytest plane/authentication/tests/test_jwks_cache.py -v
"""

import json
import logging
import threading

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from plane.authentication.middleware.jwks_cache import (
    FAILURE_BACKOFF_SECONDS,
    LIFESPAN_SECONDS,
    STALE_GRACE_SECONDS,
    JwksCache,
    JwksUnavailable,
    parse_signing_keys,
)

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool"
SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(kid="k1", **overrides):
    return {**jwt.algorithms.RSAAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True), "kid": kid, **overrides}


def jwks_body(*keys):
    return json.dumps({"keys": list(keys) or [jwk()]})


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ScriptedFetcher:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        response = self.responses[min(self.calls, len(self.responses)) - 1]
        if isinstance(response, BaseException):
            raise response
        return response


class Interrupt(BaseException):
    pass


def warm_cache(*later_responses):
    clock = FakeClock()
    fetcher = ScriptedFetcher(jwks_body(), *later_responses)
    cache = JwksCache(fetcher=fetcher, clock=clock)
    cache.keys_for(ISSUER)
    return cache, fetcher, clock


class TestStaleServing:
    def test_failed_refresh_after_lifespan_serves_last_good_set(self, caplog):
        cache, fetcher, clock = warm_cache(OSError("down"))
        clock.now += LIFESPAN_SECONDS

        with caplog.at_level(logging.WARNING):
            keys = cache.keys_for(ISSUER)

        assert set(keys) == {"k1"}
        assert fetcher.calls == 2
        assert f"mPass JWKS fetch failed: issuer={ISSUER} error=OSError" in caplog.text
        assert f"mPass JWKS is stale, serving the last good set: issuer={ISSUER}" in caplog.text

    def test_backoff_serves_stale_without_fetching(self):
        cache, fetcher, clock = warm_cache(OSError("down"))
        clock.now += LIFESPAN_SECONDS
        cache.keys_for(ISSUER)
        clock.now += FAILURE_BACKOFF_SECONDS - 1

        assert set(cache.keys_for(ISSUER)) == {"k1"}
        assert fetcher.calls == 2

    def test_refetch_after_backoff_replaces_stale_set(self):
        cache, fetcher, clock = warm_cache(OSError("down"), jwks_body(jwk(kid="k2")))
        clock.now += LIFESPAN_SECONDS
        cache.keys_for(ISSUER)
        clock.now += FAILURE_BACKOFF_SECONDS

        assert set(cache.keys_for(ISSUER)) == {"k2"}

    def test_set_older_than_grace_is_unavailable(self):
        cache, _, clock = warm_cache(OSError("down"))
        clock.now += STALE_GRACE_SECONDS

        with pytest.raises(JwksUnavailable):
            cache.keys_for(ISSUER)

    def test_never_fetched_issuer_is_unavailable(self, caplog):
        cache = JwksCache(fetcher=ScriptedFetcher(OSError("down")), clock=FakeClock())

        with caplog.at_level(logging.WARNING), pytest.raises(JwksUnavailable):
            cache.keys_for(ISSUER)

        assert "error=OSError" in caplog.text

    def test_never_fetched_issuer_in_backoff_is_unavailable_without_fetching(self):
        fetcher = ScriptedFetcher(OSError("down"))
        cache = JwksCache(fetcher=fetcher, clock=FakeClock())
        with pytest.raises(JwksUnavailable):
            cache.keys_for(ISSUER)

        with pytest.raises(JwksUnavailable):
            cache.keys_for(ISSUER)

        assert fetcher.calls == 1

    def test_refresh_within_backoff_keeps_cached_set(self):
        cache, fetcher, clock = warm_cache()
        clock.now += FAILURE_BACKOFF_SECONDS - 1

        cache.keys_for(ISSUER, refresh=True)

        assert fetcher.calls == 1

    def test_failed_refresh_keeps_cached_set(self):
        cache, fetcher, clock = warm_cache(OSError("down"))
        clock.now += FAILURE_BACKOFF_SECONDS

        assert set(cache.keys_for(ISSUER, refresh=True)) == {"k1"}
        assert fetcher.calls == 2


class TestKeyImport:
    def test_bad_key_is_skipped_with_its_kid(self, caplog):
        broken = {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"}

        with caplog.at_level(logging.WARNING):
            keys = parse_signing_keys(jwks_body(broken, jwk()))

        assert set(keys) == {"k1"}
        assert "mPass JWKS key skipped: kid=broken" in caplog.text

    def test_encryption_and_kidless_keys_are_not_signing_keys(self):
        keys = parse_signing_keys(jwks_body(jwk(kid="enc", use="enc"), jwk(kid=""), jwk()))

        assert set(keys) == {"k1"}

    @pytest.mark.parametrize(
        "body",
        ["<html>", json.dumps({"keys": "nope"}), json.dumps([]), json.dumps({"keys": [{"kty": "nope", "kid": "x"}]})],
    )
    def test_unusable_body_is_a_fetch_failure(self, body):
        cache = JwksCache(fetcher=ScriptedFetcher(body), clock=FakeClock())

        with pytest.raises(JwksUnavailable):
            cache.keys_for(ISSUER)


class TestInFlightFetch:
    def test_interrupted_fetch_releases_the_issuer(self):
        fetcher = ScriptedFetcher(Interrupt(), jwks_body())
        cache = JwksCache(fetcher=fetcher, clock=FakeClock(), wait_timeout=0.2)

        with pytest.raises(Interrupt):
            cache.keys_for(ISSUER)

        assert set(cache.keys_for(ISSUER)) == {"k1"}
        assert fetcher.calls == 2

    def _blocking_fetcher(self, release, started=None):
        calls = []

        def fetch(url):
            calls.append(url)
            if started:
                started.set()
            release.wait(5)
            return jwks_body(jwk(kid="k2"))

        return fetch, calls

    def _call_concurrently(self, cache, count):
        results, errors = [], []

        def call():
            try:
                results.append(set(cache.keys_for(ISSUER)))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=call) for _ in range(count)]
        for thread in threads:
            thread.start()
        return threads, results, errors

    def test_cold_cache_fetches_once_and_shares_the_result(self):
        release = threading.Event()
        fetch, calls = self._blocking_fetcher(release)
        cache = JwksCache(fetcher=fetch, clock=FakeClock(), wait_timeout=5)

        threads, results, errors = self._call_concurrently(cache, 5)
        release.set()
        for thread in threads:
            thread.join(5)

        assert len(calls) == 1
        assert errors == []
        assert results == [{"k2"}] * 5

    def test_rotation_refresh_waits_for_the_in_flight_fetch(self):
        release, started = threading.Event(), threading.Event()
        fetch, calls = self._blocking_fetcher(release, started)
        clock = FakeClock()
        cache = JwksCache(fetcher=ScriptedFetcher(jwks_body()), clock=clock, wait_timeout=5)
        cache.keys_for(ISSUER)
        cache._fetcher = fetch
        clock.now += LIFESPAN_SECONDS

        refresher, _, _ = self._call_concurrently(cache, 1)
        assert started.wait(5)
        results = []
        waiter = threading.Thread(target=lambda: results.append(set(cache.keys_for(ISSUER, refresh=True))))
        waiter.start()
        waiter.join(0.2)
        assert waiter.is_alive()
        release.set()
        waiter.join(5)
        refresher[0].join(5)

        assert len(calls) == 1
        assert results == [{"k2"}]

    def test_expired_set_is_served_stale_while_one_refresh_is_in_flight(self):
        release, started = threading.Event(), threading.Event()
        fetch, calls = self._blocking_fetcher(release, started)
        clock = FakeClock()
        cache = JwksCache(fetcher=ScriptedFetcher(jwks_body()), clock=clock, wait_timeout=5)
        cache.keys_for(ISSUER)
        cache._fetcher = fetch
        clock.now += LIFESPAN_SECONDS

        refresher, _, _ = self._call_concurrently(cache, 1)
        assert started.wait(5)
        waiters, results, errors = self._call_concurrently(cache, 4)
        for thread in waiters:
            thread.join(5)
        release.set()
        refresher[0].join(5)

        assert len(calls) == 1
        assert errors == []
        assert results == [{"k1"}] * 4
