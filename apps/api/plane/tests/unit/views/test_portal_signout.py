# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Unit tests for PortalSignOutEndpoint.

SPEC (GIVEN / WHEN / THEN)
──────────────────────────
  1  GIVEN a valid ?next= URL on an allowlisted host
     WHEN  GET /auth/portal-sign-out/?next=… is called
     THEN  Django session is cleared and response 302s to that URL

  2  GIVEN ?next= is omitted
     WHEN  GET /auth/portal-sign-out/ is called with MPASS_SIGNOUT_URL set
     THEN  response 302s to MPASS_SIGNOUT_URL (session still cleared)

  3  GIVEN ?next= is omitted AND MPASS_SIGNOUT_URL is unset
     WHEN  GET /auth/portal-sign-out/ is called
     THEN  response 302s to "/"

  4  GIVEN ?next= is on a host not in MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS
     WHEN  GET /auth/portal-sign-out/?next=https://evil.example/ is called
     THEN  response is 400 Bad Request — open-redirect protection

  5  GIVEN allowlist contains "foss.arbisoft.com"
     WHEN  ?next= hostname is "foss.arbisoft.com.evil"
     THEN  response is 400 — suffix match enforces dot boundary

  6  GIVEN allowlist contains "foss.arbisoft.com"
     WHEN  ?next= hostname is "docs.foss.arbisoft.com" (subdomain)
     THEN  response 302s to that URL — subdomain allowed

  7  GIVEN allowlist is empty
     WHEN  any ?next= is supplied
     THEN  response is 400 — empty allowlist rejects every redirect

  8  GIVEN ?next= contains a malformed URL
     WHEN  GET /auth/portal-sign-out/?next=:::garbage is called
     THEN  response is 400 — defensive; we don't redirect to junk
"""

from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from plane.authentication.views.app.portal_signout import PortalSignOutEndpoint

pytestmark = pytest.mark.unit


def _make_request(factory: RequestFactory, query: str = "") -> MagicMock:
    path = "/auth/portal-sign-out/" + (f"?{query}" if query else "")
    req = factory.get(path)
    req.user = MagicMock(id="user-uuid-1234")
    return req


@pytest.fixture
def factory():
    return RequestFactory()


@pytest.fixture
def view():
    return PortalSignOutEndpoint()


@pytest.mark.unit
class TestPortalSignOutEndpoint:

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_redirects_to_allowlisted_next(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]
        next_url = "https://docs.foss.arbisoft.com/auth/portal-sign-out/"

        response = view.get(_make_request(factory, f"next={next_url}"))

        mock_logout.assert_called_once()
        assert response.status_code == 302
        assert response["Location"] == next_url

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_falls_back_to_mpass_signout_url_when_no_next(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]
        mock_settings.MPASS_SIGNOUT_URL = "https://auth.foss.arbisoft.com/oauth2/sign_out"

        response = view.get(_make_request(factory))

        mock_logout.assert_called_once()
        assert response.status_code == 302
        assert response["Location"] == "https://auth.foss.arbisoft.com/oauth2/sign_out"

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_falls_back_to_root_when_no_next_and_no_mpass_url(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]
        mock_settings.MPASS_SIGNOUT_URL = ""

        response = view.get(_make_request(factory))

        mock_logout.assert_called_once()
        assert response.status_code == 302
        assert response["Location"] == "/"

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_rejects_next_on_disallowed_host(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]

        response = view.get(
            _make_request(factory, "next=https://evil.example/steal")
        )

        mock_logout.assert_called_once()  # session is still flushed
        assert response.status_code == 400

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_suffix_match_enforces_dot_boundary(
        self, mock_settings, mock_logout, factory, view
    ):
        # "foss.arbisoft.com.evil" must not match the "foss.arbisoft.com" entry.
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]

        response = view.get(
            _make_request(factory, "next=https://foss.arbisoft.com.evil/x")
        )

        assert response.status_code == 400

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_subdomain_matches_suffix_entry(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]
        next_url = "https://pm.foss.arbisoft.com/portal/done"

        response = view.get(_make_request(factory, f"next={next_url}"))

        assert response.status_code == 302
        assert response["Location"] == next_url

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_empty_allowlist_rejects_all_next(
        self, mock_settings, mock_logout, factory, view
    ):
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = []

        response = view.get(
            _make_request(factory, "next=https://docs.foss.arbisoft.com/x")
        )

        assert response.status_code == 400

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_malformed_next_is_rejected(
        self, mock_settings, mock_logout, factory, view
    ):
        # Garbage URL: no hostname extractable → reject.
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = ["foss.arbisoft.com"]

        response = view.get(_make_request(factory, "next=not-a-url"))

        assert response.status_code == 400

    @patch("plane.authentication.views.app.portal_signout.logout")
    @patch("plane.authentication.views.app.portal_signout.settings")
    def test_allowlist_entry_with_leading_dot_is_normalised(
        self, mock_settings, mock_logout, factory, view
    ):
        # Operators sometimes write ".foss.arbisoft.com" — that leading dot
        # is stripped and the entry treated as a host suffix.
        mock_settings.MPASS_SIGNOUT_NEXT_ALLOWED_HOSTS = [".foss.arbisoft.com"]
        next_url = "https://pm.foss.arbisoft.com/done"

        response = view.get(_make_request(factory, f"next={next_url}"))

        assert response.status_code == 302
        assert response["Location"] == next_url
