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
- Reads identity headers from request.META:
    * HTTP_X_AUTH_REQUEST_EMAIL
    * HTTP_X_AUTH_REQUEST_USER (fallback when email header is empty)
- If path starts with a bypass prefix → pass through immediately (no DB, no login)
  Default bypass prefixes: ["/god-mode", "/api/instances"]
- If request.user.is_authenticated:
    * proxy header absent or matches request.user.email → short-circuit
    * proxy header asserts a DIFFERENT email → logout() to flush the stale session,
      then fall through and re-authenticate
      (defends against the "stale Django session survives upstream logout"
      class of bug — see TestProxyAuthMiddlewareUserSwitch)
- If both identity headers are absent (and no existing session) → pass through unauthenticated
- If identity can be derived from headers → get_or_create User, create Profile on first creation,
  then call user_login(request, user, is_app=True) to establish session
- New users get: set_unusable_password(), is_password_autoset=True, is_email_verified=True
- username is always uuid4().hex (never the Cognito sub — avoids length/collision issues)
- Email is normalised (lowercased + stripped) before DB lookup
- Inactive users pass through unauthenticated even with a valid header
- IntegrityError on concurrent creation falls back to .get(email=email),
  re-raises if the user still doesn't exist
"""

import pytest
from unittest.mock import MagicMock, Mock, patch
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

from plane.authentication.middleware.proxy_auth import ProxyAuthMiddleware
from plane.db.models import User, Profile

PATCH_USER_LOGIN = "plane.authentication.middleware.proxy_auth.user_login"
PATCH_LOGOUT = "plane.authentication.middleware.proxy_auth.logout"


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


class TestProxyAuthMiddlewareUserSwitch:
    """Stale Django session must not survive an upstream identity change."""

    @pytest.mark.django_db
    def test_logs_in_new_user_when_proxy_email_differs(self, django_user_model):
        """
        GIVEN  the current Django session belongs to alice
               AND X-Auth-Request-Email = bob's email (oauth2-proxy now says bob)
        WHEN   the middleware processes the request
        THEN   logout() is called to flush alice's stale session
               AND user_login is called with bob (not short-circuited on alice)

        Real-world repro: portal "log out of all apps" clears the shared
        _oauth2_proxy cookie + Cognito session but NOT Plane's own Django
        session cookie. The next user logs in upstream; this tab refreshes
        and must re-bind to the new identity.
        """
        django_user_model.objects.create_user(
            email="alice@example.com", username="alice", password="x",
        )
        bob = django_user_model.objects.create_user(
            email="bob@example.com", username="bob", password="x",
        )
        alice = django_user_model.objects.get(email="alice@example.com")
        middleware = make_middleware()
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "bob@example.com"},
            authenticated_user=alice,
        )

        # Use a manager mock to track call order
        manager = Mock()
        
        with patch(PATCH_USER_LOGIN) as mock_login, \
             patch(PATCH_LOGOUT) as mock_logout:
            # Attach mocks to manager to track order
            manager.attach_mock(mock_logout, 'logout')
            manager.attach_mock(mock_login, 'login')
            
            middleware(request)

        # Session should be flushed when mismatch is detected
        mock_logout.assert_called_once_with(request)
        # Then re-auth with the new user
        mock_login.assert_called_once()
        assert mock_login.call_args.kwargs["user"].pk == bob.pk
        
        # Verify logout happens before user_login (order matters for security)
        call_names = [call[0] for call in manager.mock_calls]
        assert 'logout' in call_names and 'login' in call_names, \
            "Both logout and login should be called"
        assert call_names.index('logout') < call_names.index('login'), \
            "logout() must be called before user_login() to flush stale session"

    @pytest.mark.django_db
    def test_no_logout_when_header_absent(self, django_user_model):
        """
        GIVEN  the current Django session belongs to alice
               AND no X-Auth-Request-Email header is present
        WHEN   the middleware processes the request
        THEN   user_login is NOT called — header absence is not a logout signal.

        Header absence can occur on internal requests, bypass paths reached
        via redirect, or test paths. Treating it as "log out" would break
        every such call.
        """
        alice = django_user_model.objects.create_user(
            email="alice@example.com", username="alice", password="x",
        )
        middleware = make_middleware()
        request = make_request(authenticated_user=alice)

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()

    @pytest.mark.django_db
    def test_match_is_case_and_whitespace_insensitive(self, django_user_model):
        """
        GIVEN  the current Django session belongs to alice@example.com
               AND X-Auth-Request-Email = "  ALICE@example.com  "
        WHEN   the middleware processes the request
        THEN   user_login is NOT called — match comparison runs through the
               same normalisation as user creation does.
        """
        alice = django_user_model.objects.create_user(
            email="alice@example.com", username="alice", password="x",
        )
        middleware = make_middleware()
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "  ALICE@example.com  "},
            authenticated_user=alice,
        )

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()

    @pytest.mark.django_db
    def test_flushes_session_when_incoming_user_is_inactive(self, django_user_model):
        """
        GIVEN  the current Django session belongs to alice (active)
               AND X-Auth-Request-Email = bob's email
               AND bob exists but is_active=False
        WHEN   the middleware processes the request
        THEN   logout() is called to flush alice's session
               AND user_login is NOT called (bob is inactive)
               AND the request proceeds without re-authentication

        This prevents a stale session from surviving when re-auth fails.
        Without the explicit logout(), alice's session would remain active
        and the request would proceed as alice even though the proxy now
        asserts bob's identity.
        """
        alice = django_user_model.objects.create_user(
            email="alice@example.com", username="alice", password="x"
        )
        django_user_model.objects.create_user(
            email="bob@example.com", username="bob", password="x", is_active=False
        )
        
        # Capture what request object get_response receives
        received_request = None
        def capture_get_response(req):
            nonlocal received_request
            received_request = req
            return MagicMock(status_code=200)
        
        middleware = make_middleware(get_response=capture_get_response)
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "bob@example.com"},
            authenticated_user=alice,
        )

        with patch(PATCH_USER_LOGIN) as mock_login, \
             patch(PATCH_LOGOUT) as mock_logout:
            middleware(request)

        # Session should be flushed when mismatch is detected
        mock_logout.assert_called_once_with(request)
        # user_login should NOT be called because bob is inactive
        mock_login.assert_not_called()
        # Verify get_response was called with the request (middleware didn't block it)
        assert received_request is request, \
            "Middleware should pass the request to get_response after logout"


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
    def test_username_derived_from_email_local_part(self):
        """
        GIVEN  a request for a new user
        WHEN   the user is created
        THEN   username equals the email local part (the text before @)
               — derived from email, never the raw X-Auth-Request-User header
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
        assert user.username == "uuidtest"
        assert user.username != "cognito-sub-should-not-be-username"



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

    @pytest.mark.django_db
    def test_bypass_dominates_mismatched_proxy_header(self, django_user_model):
        """
        GIVEN  the current Django session belongs to alice
               AND the request targets a bypass path (/god-mode/setup/)
               AND X-Auth-Request-Email = bob's email (mismatch)
        WHEN   the middleware processes the request
        THEN   logout() is NOT called — bypass dominates the mismatch flow
               AND user_login() is NOT called

        The bypass check runs at the top of __call__, before the proxy header
        is read or session identity is compared. This guards god-mode local
        admin sessions against being kicked out by an unrelated mPass
        identity reaching the same browser.
        """
        alice = django_user_model.objects.create_user(
            email="alice@example.com", username="alice", password="x",
        )
        middleware = make_middleware()
        request = make_request(
            path="/god-mode/setup/",
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "bob@example.com"},
            authenticated_user=alice,
        )

        with patch(PATCH_USER_LOGIN) as mock_login, \
             patch(PATCH_LOGOUT) as mock_logout:
            middleware(request)

        mock_logout.assert_not_called()
        mock_login.assert_not_called()


class TestProxyAuthMiddlewareEdgeCases:
    """Email normalisation and concurrent creation races."""

    @pytest.mark.django_db
    def test_whitespace_only_email_header_passes_through(self):
        """
        GIVEN  the incoming header supplies only whitespace
        WHEN   the middleware processes the request
        THEN   request passes through unauthenticated
               AND user_login() is never called
               AND no User row is created
        """
        count_before = User.objects.count()
        get_response = MagicMock(return_value=MagicMock(status_code=200))
        middleware = make_middleware(get_response)
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "   "})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        mock_login.assert_not_called()
        get_response.assert_called_once_with(request)
        assert User.objects.count() == count_before
        assert isinstance(request.user, AnonymousUser)

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


class TestProxyAuthMiddlewareUsernameSynth:
    """DEFAULT_EMAIL_DOMAIN-based email synthesis when header carries bare username."""

    @pytest.mark.django_db
    def test_bare_username_synthesizes_email(self):
        """
        GIVEN  X-Auth-Request-Email contains a bare username (no @)
               AND DEFAULT_EMAIL_DOMAIN is not set
        WHEN   the middleware processes the request
        THEN   email is synthesized as {username}@askii.ai (the hardcoded default)
               AND the user is created with that email
        """
        middleware = make_middleware()
        request = make_request(meta={"HTTP_X_AUTH_REQUEST_EMAIL": "testuser"})

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        created = User.objects.get(email="testuser@askii.ai")
        assert mock_login.call_args.kwargs["user"].pk == created.pk

    @pytest.mark.django_db
    def test_real_email_bypasses_synth(self):
        """
        GIVEN  X-Auth-Request-Email already contains a real email (has @)
        WHEN   the middleware processes the request
        THEN   email is used as-is and no synthesized email is created
        """
        middleware = make_middleware()
        request = make_request(
            meta={"HTTP_X_AUTH_REQUEST_EMAIL": "testuser@example.com"}
        )

        with patch(PATCH_USER_LOGIN) as mock_login:
            middleware(request)

        created = User.objects.get(email="testuser@example.com")
        assert mock_login.call_args.kwargs["user"].pk == created.pk
        assert not User.objects.filter(email__endswith="@askii.ai").exists()


class TestProxyAuthMiddlewareSettings:
    """Guard the middleware registration and position in the MIDDLEWARE list."""

    def test_proxy_auth_middleware_is_registered(self):
        """
        GIVEN  the Django settings MIDDLEWARE list
        WHEN   inspected at runtime
        THEN   ProxyAuthMiddleware is present
        """
        from django.conf import settings

        assert (
            "plane.authentication.middleware.proxy_auth.ProxyAuthMiddleware"
            in settings.MIDDLEWARE
        )

    def test_proxy_auth_middleware_comes_after_authentication_middleware(self):
        """
        GIVEN  the Django settings MIDDLEWARE list
        WHEN   inspected at runtime
        THEN   ProxyAuthMiddleware appears after AuthenticationMiddleware
               so that request.user is already populated when the proxy check runs.
               If this order is reversed, the is_authenticated short-circuit never
               fires and user_login() is called on every single request.
        """
        from django.conf import settings

        middleware = settings.MIDDLEWARE
        auth_idx = middleware.index(
            "django.contrib.auth.middleware.AuthenticationMiddleware"
        )
        proxy_idx = middleware.index(
            "plane.authentication.middleware.proxy_auth.ProxyAuthMiddleware"
        )
        assert proxy_idx > auth_idx, (
            "ProxyAuthMiddleware must come after AuthenticationMiddleware — "
            "request.user must be populated before the proxy auth check runs."
        )
