# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""
Regression tests for external API authentication on ``BaseAPIView`` / ``BaseViewSet``.

``ProxyAuthMiddleware`` establishes a Django session on every non-bypass path,
so a request reaching ``/api/v1/`` behind Traefik always carries an
authenticated ``request.user``. DRF's ``Request._authenticate`` stops at the
first authenticator returning a non-``None`` tuple, so if
``BaseSessionAuthentication`` were listed first the ``X-Api-Key`` header would
never be read and API token revocation would be silently defeated.

Two things have to hold for the ordering to be worth anything, and both are
pinned here:

1. ``APIKeyAuthentication`` runs first and fails closed (``TestAuthenticatorResolution``).
2. ``validate_api_token`` actually rejects revoked and expired tokens — the
   ordering is pointless if the lookup stops filtering on ``is_active`` or
   ``expired_at`` (``TestTokenValidationPredicate``).

The predicate is asserted against the real ORM call rather than a live row:
creating a test database requires CREATEDB, which the ``plane`` role does not
hold in the devstack. Patching ``APIToken.objects.get`` and inspecting the
filter still catches the regression that matters (dropping ``is_active=True``
or inverting the ``expired_at`` comparison), without a DB dependency.
"""

import uuid

import pytest
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.db.models import Q
from django.test import RequestFactory
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from plane.api.middleware.api_authentication import APIKeyAuthentication
from plane.api.views.base import BaseAPIView, BaseViewSet
from plane.authentication.session import BaseSessionAuthentication
from plane.db.models import APIToken, User


# Both external API base classes must be covered — they carry independent
# authentication_classes declarations.
BASE_CLASSES = [BaseAPIView, BaseViewSet]


@pytest.fixture
def request_factory():
    return RequestFactory()


def _user(email):
    """An unsaved real User — `is_authenticated` is a genuine property, unlike a Mock."""
    return User(id=uuid.uuid4(), email=email, username=email.split("@")[0])


@pytest.fixture
def session_user():
    return _user("session-principal@example.com")


@pytest.fixture
def token_user():
    return _user("token-principal@example.com")


@pytest.mark.parametrize("view_class", BASE_CLASSES, ids=lambda c: c.__name__)
class TestAuthenticatorResolution:
    """DRF resolution semantics the ordering depends on, per base class."""

    @staticmethod
    def _drf_request(view_class, request_factory, headers=None, user=None):
        django_request = request_factory.get("/api/v1/workspaces/", **(headers or {}))
        django_request.user = user or AnonymousUser()
        # Built from the real view class so a reordering in base.py is caught
        # behaviourally here, not merely by an equality assertion.
        return Request(
            django_request,
            authenticators=[cls() for cls in view_class.authentication_classes],
        )

    def test_api_key_authentication_is_first(self, view_class):
        assert view_class.authentication_classes == [
            APIKeyAuthentication,
            BaseSessionAuthentication,
        ]

    def test_valid_api_key_wins_over_session(
        self, view_class, request_factory, session_user, token_user
    ):
        """With both a key and a session, the key's user is the principal."""
        with patch.object(
            APIKeyAuthentication,
            "validate_api_token",
            return_value=(token_user, "tok-123"),
        ):
            request = self._drf_request(
                view_class,
                request_factory,
                headers={"HTTP_X_API_KEY": "tok-123"},
                user=session_user,
            )
            assert request.user is token_user
            assert request.user is not session_user
            assert request.auth == "tok-123"

    def test_revoked_api_key_fails_closed_despite_session(
        self, view_class, request_factory, session_user
    ):
        """A revoked key must fail closed, not downgrade to the session user."""
        with patch.object(
            APIKeyAuthentication,
            "validate_api_token",
            side_effect=AuthenticationFailed("Given API token is not valid"),
        ):
            request = self._drf_request(
                view_class,
                request_factory,
                headers={"HTTP_X_API_KEY": "revoked"},
                user=session_user,
            )
            with pytest.raises(AuthenticationFailed):
                _ = request.user

    def test_no_api_key_falls_through_to_session(
        self, view_class, request_factory, session_user
    ):
        """The Bearer-only MCP path carries no key and must still authenticate."""
        request = self._drf_request(view_class, request_factory, user=session_user)
        assert request.user is session_user


class TestTokenValidationPredicate:
    """``validate_api_token`` must keep filtering out revoked/expired tokens.

    Without these, the ordering fix above is load-bearing on a lookup nothing
    covers: drop ``is_active=True`` and revoked tokens authenticate again.
    """

    @staticmethod
    def _captured_lookup():
        """Call validate_api_token with a stubbed manager; return the ORM call args."""
        with patch.object(APIToken, "objects") as manager:
            manager.get.return_value = Mock(user=Mock(), token="tok")
            APIKeyAuthentication().validate_api_token("tok")
        return manager.get.call_args

    def test_filters_on_is_active(self):
        call = self._captured_lookup()
        assert call.kwargs["is_active"] is True, (
            "validate_api_token no longer filters on is_active — revoked tokens "
            "would authenticate"
        )

    def test_filters_on_the_supplied_token(self):
        assert self._captured_lookup().kwargs["token"] == "tok"

    def test_rejects_tokens_whose_expiry_has_passed(self):
        """Expiry must be 'expires in the future OR never expires', not the inverse."""
        call = self._captured_lookup()
        q_children = dict(
            child
            for arg in call.args
            if isinstance(arg, Q)
            for sub in arg.children
            for child in (sub.children if isinstance(sub, Q) else [sub])
        )
        assert "expired_at__gt" in q_children, (
            "expiry filter is missing or inverted — expired tokens would authenticate"
        )
        assert q_children.get("expired_at__isnull") is True
        assert q_children["expired_at__gt"] <= timezone.now()

    def test_raises_authentication_failed_when_no_row_matches(self):
        """A token failing the predicate must raise, not return None."""
        with patch.object(APIToken, "objects") as manager:
            manager.get.side_effect = APIToken.DoesNotExist
            with pytest.raises(AuthenticationFailed):
                APIKeyAuthentication().validate_api_token("revoked")
