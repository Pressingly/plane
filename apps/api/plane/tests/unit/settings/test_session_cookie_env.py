# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only

import importlib

import pytest

import plane.settings.common as common


@pytest.fixture
def reload_common_after(request):
    """Restore plane.settings.common after a test that mutates env + reloads it."""
    request.addfinalizer(lambda: importlib.reload(common))


@pytest.mark.unit
class TestSessionCookieEnv:
    """SESSION_COOKIE_AGE / ADMIN_SESSION_COOKIE_AGE are driven by env (devstack unified session)."""

    def test_session_cookie_ages_from_env(self, monkeypatch, reload_common_after):
        monkeypatch.setenv("SESSION_COOKIE_AGE", "12345")
        monkeypatch.setenv("ADMIN_SESSION_COOKIE_AGE", "67890")
        importlib.reload(common)
        assert common.SESSION_COOKIE_AGE == 12345
        assert common.ADMIN_SESSION_COOKIE_AGE == 67890


@pytest.mark.unit
class TestMpassSignoutUrlEnv:
    """MPASS_SIGNOUT_URL must be promoted from env onto the settings module so
    SignOutAuthEndpoint's getattr(settings, 'MPASS_SIGNOUT_URL', None) sees it.
    Without this, the 3-layer logout silently degrades to 1-layer."""

    def test_mpass_signout_url_loaded_from_env(self, monkeypatch, reload_common_after):
        monkeypatch.setenv(
            "MPASS_SIGNOUT_URL",
            "https://foss-auth.local.moneta.dev/oauth2/sign_out?rd=https%3A%2F%2Fcognito.example.com%2Flogout",
        )
        importlib.reload(common)
        assert (
            common.MPASS_SIGNOUT_URL
            == "https://foss-auth.local.moneta.dev/oauth2/sign_out?rd=https%3A%2F%2Fcognito.example.com%2Flogout"
        )

    def test_mpass_signout_url_defaults_to_none_when_env_unset(self, monkeypatch, reload_common_after):
        monkeypatch.delenv("MPASS_SIGNOUT_URL", raising=False)
        importlib.reload(common)
        assert common.MPASS_SIGNOUT_URL is None
