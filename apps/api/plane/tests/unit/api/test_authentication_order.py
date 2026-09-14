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
2. ``validate_api_token`` actually rejects revoked and expired tokens
   (``TestTokenValidationPredicate``). Note revocation is a *soft delete*:
   ``ApiTokenEndpoint.delete`` calls ``SoftDeleteModel.delete``, which sets
   ``deleted_at`` and leaves ``is_active`` True and ``expired_at`` NULL. So the
   primary guard is the lookup going through ``SoftDeletionManager`` (which
   filters ``deleted_at__isnull=True``); ``is_active`` and ``expired_at`` are
   secondary. A swap to ``APIToken.all_objects`` would defeat revocation while
   leaving every named filter intact.

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
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from plane.api.middleware.api_authentication import APIKeyAuthentication
from plane.api.views.base import BaseAPIView, BaseViewSet
from plane.authentication.session import BaseSessionAuthentication
from plane.db.mixins import SoftDeletionManager
from plane.db.models import APIToken, User


# Both external API base classes must be covered — they carry independent
# authentication_classes declarations.
BASE_CLASSES = [BaseAPIView, BaseViewSet]


@pytest.fixture
def request_factory():
    return RequestFactory()


def _flatten_q(node, out):
    """Collect every ``lookup -> value`` leaf in a Q tree, at any nesting depth."""
    for child in node.children:
        if isinstance(child, Q):
            _flatten_q(child, out)
        else:
            out[child[0]] = child[1]


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

    The ordering fix above is load-bearing on this lookup. Revocation is
    enforced by the soft-deletion manager; expiry and deactivation by the
    explicit filters. All three are pinned here because nothing else covers them.
    """

    def test_lookup_goes_through_the_soft_deletion_manager(self):
        """Revocation is a soft delete: deleted_at is set, is_active stays True.

        Switching the call site to ``APIToken.all_objects`` keeps every named
        filter intact and still returns revoked tokens, so the manager the
        lookup runs through is the real guard.
        """
        assert isinstance(APIToken.objects, SoftDeletionManager), (
            "APIToken.objects is no longer a SoftDeletionManager — revoked "
            "(soft-deleted) tokens would authenticate"
        )
        default_manager, unfiltered_manager = self._captured_lookup()
        assert default_manager.get.called, "lookup did not use APIToken.objects"
        assert not unfiltered_manager.get.called, (
            "validate_api_token queries APIToken.all_objects, bypassing the "
            "deleted_at filter — revoked tokens would authenticate"
        )

    @staticmethod
    def _captured_lookup():
        """Call validate_api_token with both managers stubbed.

        Returns ``(default_manager, unfiltered_manager)`` so callers can assert
        both the filter shape and which manager the call site actually used.
        """
        with (
            patch.object(APIToken, "objects") as default_manager,
            patch.object(APIToken, "all_objects") as unfiltered_manager,
        ):
            default_manager.get.return_value = Mock(user=Mock(), token="tok")
            unfiltered_manager.get.return_value = Mock(user=Mock(), token="tok")
            APIKeyAuthentication().validate_api_token("tok")
        return default_manager, unfiltered_manager

    def test_filters_on_is_active(self):
        call = self._captured_lookup()[0].get.call_args
        assert call.kwargs["is_active"] is True, (
            "validate_api_token no longer filters on is_active — revoked tokens "
            "would authenticate"
        )

    def test_filters_on_the_supplied_token(self):
        assert self._captured_lookup()[0].get.call_args.kwargs["token"] == "tok"

    def test_rejects_tokens_whose_expiry_has_passed(self):
        """Expiry must be 'expires in the future OR never expires', not the inverse."""
        call = self._captured_lookup()[0].get.call_args
        lookups = {}
        for arg in call.args:
            if isinstance(arg, Q):
                _flatten_q(arg, lookups)
        assert "expired_at__gt" in lookups, (
            "expiry filter is missing or inverted — expired tokens would "
            f"authenticate (found: {sorted(lookups)})"
        )
        assert lookups.get("expired_at__isnull") is True

    def test_raises_authentication_failed_when_no_row_matches(self):
        """A token failing the predicate must raise, not return None."""
        with patch.object(APIToken, "objects") as manager:
            manager.get.side_effect = APIToken.DoesNotExist
            with pytest.raises(AuthenticationFailed):
                APIKeyAuthentication().validate_api_token("revoked")
