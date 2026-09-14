# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Regression tests for the authenticator ordering on the external API base classes.

``ProxyAuthMiddleware`` establishes a Django session on every non-bypass path,
so a request reaching ``/api/v1/`` behind Traefik always carries an
authenticated ``request.user``. DRF's ``Request._authenticate`` stops at the
first authenticator returning a non-``None`` tuple, so if
``BaseSessionAuthentication`` were listed first the ``X-Api-Key`` header would
never be read and API token revocation would be silently defeated.

These tests pin the ordering and the resolution semantics that make it safe.
"""

import pytest
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from plane.api.middleware.api_authentication import APIKeyAuthentication
from plane.api.views.base import BaseAPIView, BaseViewSet
from plane.authentication.session import BaseSessionAuthentication


@pytest.fixture
def request_factory():
    return RequestFactory()


class TestAuthenticationClassOrdering:
    """The API key authenticator must precede session authentication."""

    @pytest.mark.parametrize("view_class", [BaseAPIView, BaseViewSet])
    def test_api_key_authentication_is_first(self, view_class):
        assert view_class.authentication_classes == [
            APIKeyAuthentication,
            BaseSessionAuthentication,
        ]


class TestAuthenticatorResolution:
    """DRF resolution semantics that the ordering depends on."""

    @staticmethod
    def _drf_request(request_factory, headers=None, session_user=None):
        django_request = request_factory.get("/api/v1/workspaces/", **(headers or {}))
        django_request.user = session_user or AnonymousUser()
        # Build from the real view class so a reordering there is caught here
        # behaviourally, not just by the ordering assertion above.
        return Request(
            django_request,
            authenticators=[cls() for cls in BaseAPIView.authentication_classes],
        )

    def test_valid_api_key_wins_over_session(self, request_factory):
        """With both a key and a session, the key's user is the principal."""
        token_user = Mock(name="token_user", is_active=True)
        session_user = Mock(name="session_user", is_authenticated=True, is_active=True)

        with patch.object(
            APIKeyAuthentication,
            "validate_api_token",
            return_value=(token_user, "tok-123"),
        ):
            request = self._drf_request(
                request_factory,
                headers={"HTTP_X_API_KEY": "tok-123"},
                session_user=session_user,
            )
            assert request.user is token_user
            assert request.auth == "tok-123"

    def test_revoked_api_key_fails_closed_despite_session(self, request_factory):
        """A revoked key must 401, not silently downgrade to the session user."""
        session_user = Mock(name="session_user", is_authenticated=True, is_active=True)

        with patch.object(
            APIKeyAuthentication,
            "validate_api_token",
            side_effect=AuthenticationFailed("Given API token is not valid"),
        ):
            request = self._drf_request(
                request_factory,
                headers={"HTTP_X_API_KEY": "revoked"},
                session_user=session_user,
            )
            with pytest.raises(AuthenticationFailed):
                _ = request.user

    def test_no_api_key_falls_through_to_session(self, request_factory):
        """The Bearer-only MCP path carries no key and must still authenticate."""
        session_user = Mock(name="session_user", is_authenticated=True, is_active=True)

        request = self._drf_request(request_factory, session_user=session_user)
        assert request.user is session_user
