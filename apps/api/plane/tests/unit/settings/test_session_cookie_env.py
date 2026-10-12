# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only

import importlib

import pytest

import plane.settings.common as common


@pytest.mark.unit
class TestSessionCookieEnv:
    """SESSION_COOKIE_AGE / ADMIN_SESSION_COOKIE_AGE are driven by env (devstack unified session)."""

    def test_session_cookie_ages_from_env(self, monkeypatch):
        try:
            with monkeypatch.context() as patched_env:
                patched_env.setenv("SESSION_COOKIE_AGE", "12345")
                patched_env.setenv("ADMIN_SESSION_COOKIE_AGE", "67890")
                importlib.reload(common)
                assert common.SESSION_COOKIE_AGE == 12345
                assert common.ADMIN_SESSION_COOKIE_AGE == 67890
        finally:
            importlib.reload(common)
