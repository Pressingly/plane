# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Unit tests for SignOutAuthEndpoint.

SPEC (GIVEN / WHEN / THEN)
──────────────────────────
  1  GIVEN MPASS_SIGNOUT_URL is set in settings
     WHEN  POST /auth/sign-out/ is called
     THEN  Django session is cleared and response redirects to MPASS_SIGNOUT_URL

  2  GIVEN MPASS_SIGNOUT_URL is not set
     WHEN  POST /auth/sign-out/ is called
     THEN  response redirects to base_host (original behaviour preserved)

  3  GIVEN user.save() raises an exception
     WHEN  POST /auth/sign-out/ is called with MPASS_SIGNOUT_URL set
     THEN  session is still cleared and response redirects to MPASS_SIGNOUT_URL

  4  GIVEN MPASS_SIGNOUT_URL is not set and save() raises
     WHEN  POST /auth/sign-out/ is called
     THEN  response redirects to base_host
"""

from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from plane.authentication.views.app.signout import SignOutAuthEndpoint

pytestmark = pytest.mark.unit

_MPASS_URL = "https://foss-auth.local.moneta.dev/oauth2/sign_out?rd=https%3A%2F%2Fcognito.example.com%2Flogout"
_BASE_HOST = "https://foss-pm.local.moneta.dev"


def _make_request(factory: RequestFactory) -> MagicMock:
    req = factory.post("/auth/sign-out/")
    req.user = MagicMock(id="user-uuid-1234")
    return req


@pytest.fixture
def factory():
    return RequestFactory()


@pytest.fixture
def view():
    return SignOutAuthEndpoint()


@pytest.mark.unit
class TestSignOutAuthEndpoint:

    @patch("plane.authentication.views.app.signout.base_host", return_value=_BASE_HOST)
    @patch("plane.authentication.views.app.signout.logout")
    @patch("plane.authentication.views.app.signout.User")
    @patch("plane.authentication.views.app.signout.settings")
    def test_redirects_to_mpass_signout_url_when_configured(
        self, mock_settings, mock_user_cls, mock_logout, mock_base_host, factory, view
    ):
        """MPASS_SIGNOUT_URL is set → redirect there, Django session cleared."""
        mock_settings.MPASS_SIGNOUT_URL = _MPASS_URL
        mock_user = MagicMock()
        mock_user_cls.objects.get.return_value = mock_user

        response = view.post(_make_request(factory))

        mock_logout.assert_called_once()
        assert response.status_code == 302
        assert response["Location"] == _MPASS_URL
        mock_base_host.assert_not_called()

    @patch("plane.authentication.views.app.signout.base_host", return_value=_BASE_HOST)
    @patch("plane.authentication.views.app.signout.logout")
    @patch("plane.authentication.views.app.signout.User")
    @patch("plane.authentication.views.app.signout.settings")
    def test_falls_back_to_base_host_when_mpass_url_not_set(
        self, mock_settings, mock_user_cls, mock_logout, mock_base_host, factory, view
    ):
        """No MPASS_SIGNOUT_URL → fall back to original base_host redirect."""
        mock_settings.MPASS_SIGNOUT_URL = None
        mock_user = MagicMock()
        mock_user_cls.objects.get.return_value = mock_user

        response = view.post(_make_request(factory))

        mock_logout.assert_called_once()
        assert response.status_code == 302
        assert response["Location"] == _BASE_HOST

    @patch("plane.authentication.views.app.signout.base_host", return_value=_BASE_HOST)
    @patch("plane.authentication.views.app.signout.logout")
    @patch("plane.authentication.views.app.signout.User")
    @patch("plane.authentication.views.app.signout.settings")
    def test_redirects_to_mpass_url_even_when_user_save_raises(
        self, mock_settings, mock_user_cls, mock_logout, mock_base_host, factory, view
    ):
        """Exception in user.save() → still redirects to MPASS_SIGNOUT_URL."""
        mock_settings.MPASS_SIGNOUT_URL = _MPASS_URL
        mock_user = MagicMock()
        mock_user.save.side_effect = Exception("DB error")
        mock_user_cls.objects.get.return_value = mock_user

        response = view.post(_make_request(factory))

        assert response.status_code == 302
        assert response["Location"] == _MPASS_URL

    @patch("plane.authentication.views.app.signout.base_host", return_value=_BASE_HOST)
    @patch("plane.authentication.views.app.signout.logout")
    @patch("plane.authentication.views.app.signout.User")
    @patch("plane.authentication.views.app.signout.settings")
    def test_falls_back_to_base_host_when_save_raises_and_no_mpass_url(
        self, mock_settings, mock_user_cls, mock_logout, mock_base_host, factory, view
    ):
        """Exception + no MPASS_SIGNOUT_URL → fall back to base_host."""
        mock_settings.MPASS_SIGNOUT_URL = None
        mock_user = MagicMock()
        mock_user.save.side_effect = Exception("DB error")
        mock_user_cls.objects.get.return_value = mock_user

        response = view.post(_make_request(factory))

        assert response.status_code == 302
        assert response["Location"] == _BASE_HOST
