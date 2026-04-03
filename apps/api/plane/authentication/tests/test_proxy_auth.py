# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Tests for ProxyAuthMiddleware.

Location of middleware under test:
    apps/api/plane/authentication/middleware/proxy_auth.py

Run (from apps/api/):
    pytest plane/authentication/tests/test_proxy_auth.py -v

Design contract being tested
-----------------------------
- Reads HTTP_X_AUTH_REQUEST_EMAIL from request.META
- If MPASS_PROXY_AUTH_ENABLED is False → pass through (kill switch)
- If request.user.is_authenticated → pass through immediately (no DB, no login)
- If path starts with a bypass prefix → pass through immediately (no DB, no login)
  Default bypass prefixes: ["/god-mode", "/api/instances"]
- If email header is absent → pass through unauthenticated
- If email is present → get_or_create User, create Profile on first creation,
  then call user_login(request, user, is_app=True) to establish session
- New users get: set_unusable_password(), is_password_autoset=True, is_email_verified=True
- username is always uuid4().hex (never the Cognito sub — avoids length/collision issues)
- Email is normalised (lowercased + stripped) before DB lookup
- Inactive users pass through unauthenticated even with a valid header
- IntegrityError on concurrent creation falls back to .get(email=email),
  re-raises if the user still doesn't exist
"""

import pytest
from unittest.mock import MagicMock, patch
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, override_settings

from plane.authentication.middleware.proxy_auth import ProxyAuthMiddleware
from plane.db.models import User, Profile

PATCH_USER_LOGIN = "plane.authentication.middleware.proxy_auth.user_login"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(path="/api/issues/", meta=None, authenticated_user=None):
    """Return a fake GET request with optional META headers and auth state."""
    factory = RequestFactory()
    request = factory.get(path)
    request.session = {}
    request.user = authenticated_user if authenticated_user else AnonymousUser()
    if meta:
        request.META.update(meta)
    return request


def make_middleware(get_response=None):
    """Return a ProxyAuthMiddleware instance with a trivial get_response stub."""
    if get_response is None:
        get_response = MagicMock(return_value=MagicMock(status_code=200))
    return ProxyAuthMiddleware(get_response)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestProxyAuthMiddlewareKillSwitch:
    """MPASS_PROXY_AUTH_ENABLED = False must disable the middleware entirely."""

    @override_settings(MPASS_PROXY_AUTH_ENABLED=False)
    def test_disabled_passes_through_without_login(self):
        """
        GIVEN  MPASS_PROXY_AUTH_ENABLED is False
        WHEN   a request with a valid email header arrives
        THEN   user_login() is never called
        """
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "user@example.com"})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        get_response.assert_called_once_with(request)


class TestProxyAuthMiddlewareAlreadyAuthenticated:
    """Middleware must short-circuit for requests that already carry a session."""

    @pytest.mark.django_db
    def test_skips_when_user_already_authenticated(self, django_user_model):
        """
        GIVEN  a request whose user.is_authenticated is True
        WHEN   the middleware processes the request
        THEN   get_response is called exactly once
               AND user_login() is never called
        """
        existing_user = django_user_model.objects.create_user(
            email="active@example.com",
            username="active_user",
            password="irrelevant",
        )
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "active@example.com"},
            authenticated_user=existing_user,
        )
        count_before = User.objects.count()

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        get_response.assert_called_once_with(request)
        mock_login.assert_not_called()
        assert User.objects.count() == count_before


class TestProxyAuthMiddlewareNoHeader:
    """Middleware must pass through cleanly when the email header is absent."""

    def test_passes_through_when_no_email_header(self):
        """
        GIVEN  a request with no X-Auth-Request-Email header
        WHEN   the middleware processes the request
        THEN   get_response is called
               AND user_login() is never called
               AND request.user remains AnonymousUser
        """
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request()

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        get_response.assert_called_once_with(request)
        mock_login.assert_not_called()
        assert isinstance(request.user, AnonymousUser)


class TestProxyAuthMiddlewareNewUser:
    """Middleware must create a User + Profile on first-seen email."""

    @pytest.mark.django_db
    def test_creates_new_user_with_correct_fields(self):
        """
        GIVEN  a request carrying a previously-unseen email header
        WHEN   the middleware processes the request
        THEN   a new User row exists with:
                 email == lowercased header value
                 is_password_autoset == True
                 is_email_verified == True
                 has_usable_password() == False
        """
        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "newuser@example.com"})

        with patch(PATCH_USER_LOGIN):
            middleware(request)

        user = User.objects.get(email="newuser@example.com")
        assert user.is_password_autoset is True
        assert user.is_email_verified is True
        assert user.has_usable_password() is False

    @pytest.mark.django_db
    def test_creates_profile_for_new_user(self):
        """
        GIVEN  a request carrying a previously-unseen email header
        WHEN   the middleware processes the request
        THEN   a Profile row is created for the new user
        """
        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "profiletest@example.com"})

        with patch(PATCH_USER_LOGIN):
            middleware(request)

        user = User.objects.get(email="profiletest@example.com")
        assert Profile.objects.filter(user=user).exists()

    @pytest.mark.django_db
    def test_username_is_uuid_hex(self):
        """
        GIVEN  a request for a new user
        WHEN   the user is created
        THEN   username is a 32-char hex string (uuid4().hex), not the Cognito sub
        """
        middleware = make_middleware()
        request = make_request(
            meta={
                "HTTP_X_AUTH_REQUEST_EMAIL": "uuidtest@example.com",
                "HTTP_X_AUTH_REQUEST_USER": "cognito-sub-should-not-be-username",
            }
        )

        with patch(PATCH_USER_LOGIN):
            middleware(request)

        user = User.objects.get(email="uuidtest@example.com")
        assert len(user.username) == 32
        assert user.username != "cognito-sub-should-not-be-username"
        assert user.username.isalnum()


class TestProxyAuthMiddlewareExistingUser:
    """Middleware must find — not duplicate — an existing user."""

    @pytest.mark.django_db
    def test_finds_existing_user_without_creating_duplicate(self, django_user_model):
        """
        GIVEN  a User already exists for the incoming email
        WHEN   the middleware processes a request with that email header
        THEN   no new User row is created
               AND user_login() is called with the existing user
        """
        existing = django_user_model.objects.create_user(
            email="returning@example.com",
            username="returning_user",
            password="whatever",
        )
        count_before = User.objects.count()

        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "returning@example.com"})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        assert User.objects.count() == count_before
        call_kwargs = mock_login.call_args.kwargs
        assert call_kwargs.get("user") == existing

    @pytest.mark.django_db
    def test_inactive_user_is_not_logged_in(self, django_user_model):
        """
        GIVEN  a User exists but is_active == False
        WHEN   a request arrives with that user's email header
        THEN   user_login() is never called
               AND get_response is called (request passes through unauthenticated)
        """
        django_user_model.objects.create_user(
            email="inactive@example.com",
            username="inactive_user",
            password="x",
            is_active=False,
        )
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "inactive@example.com"})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        get_response.assert_called_once_with(request)


class TestProxyAuthMiddlewareLogin:
    """Middleware must call user_login() with the correct arguments."""

    @pytest.mark.django_db
    def test_user_login_called_with_request_user_and_is_app(self):
        """
        GIVEN  a valid email header for a new user
        WHEN   the middleware runs
        THEN   user_login() is called with request=request, user=<resolved user>,
               is_app=True
        """
        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "logincheck@example.com"})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_called_once()
        call_kwargs = mock_login.call_args.kwargs
        assert call_kwargs["request"] is request
        assert call_kwargs["user"].email == "logincheck@example.com"
        assert call_kwargs["is_app"] is True


class TestProxyAuthMiddlewareBypassPaths:
    """Middleware must not authenticate requests on bypass paths."""

    @pytest.mark.django_db
    def test_god_mode_path_is_bypassed(self):
        """
        GIVEN  a request to /god-mode/setup/ with a valid email header
        WHEN   the middleware processes the request
        THEN   user_login() is never called AND no User is created
        """
        count_before = User.objects.count()
        middleware = make_middleware()
        request = make_request(
            path="/god-mode/setup/",
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "admin@example.com"},
        )

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        assert User.objects.count() == count_before

    @pytest.mark.django_db
    def test_instances_path_is_bypassed(self):
        """
        GIVEN  a request to /api/instances/config/ with a valid email header
        WHEN   the middleware processes the request
        THEN   user_login() is never called AND no User is created
        """
        count_before = User.objects.count()
        middleware = make_middleware()
        request = make_request(
            path="/api/instances/config/",
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "instance-admin@example.com"},
        )

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        assert User.objects.count() == count_before


class TestProxyAuthMiddlewareEdgeCases:
    """Email normalisation and concurrent creation races."""

    @pytest.mark.django_db
    def test_email_normalised_before_lookup(self, django_user_model):
        """
        GIVEN  a User exists with lowercase email "norm@example.com"
               AND the incoming header supplies "  NORM@EXAMPLE.COM  "
        WHEN   the middleware processes the request
        THEN   the existing user is found (no duplicate created)
               AND user_login() is called with the original user
        """
        existing = django_user_model.objects.create_user(
            email="norm@example.com",
            username="norm_user",
            password="x",
        )
        count_before = User.objects.count()

        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "  NORM@EXAMPLE.COM  "})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        assert User.objects.count() == count_before
        assert mock_login.call_args.kwargs["user"].pk == existing.pk

    @pytest.mark.django_db
    def test_integrity_error_race_condition_is_handled(self):
        """
        GIVEN  get_or_create raises IntegrityError (concurrent insert race)
               AND the user already exists in the DB
        WHEN   the middleware processes the request
        THEN   it falls back to .get(email=email)
               AND user_login() is still called
               AND no exception propagates
        """
        from django.db import IntegrityError

        existing = User.objects.create(email="race@example.com", username="race_user")
        existing.set_unusable_password()
        existing.save()

        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "race@example.com"})

        def raise_integrity_error(*args, **kwargs):
            raise IntegrityError("duplicate key value")

        with patch.object(User.objects, "get_or_create", side_effect=raise_integrity_error):
            with patch(PATCH_USER_LOGIN) as mock_login:
                middleware(request)

        mock_login.assert_called_once()
        assert mock_login.call_args.kwargs["user"].pk == existing.pk
