# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
from dataclasses import dataclass
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError, transaction
from django.http import JsonResponse

from plane.authentication.middleware.config_values import is_placeholder
from plane.authentication.middleware.edge_trust import (
    edge_secret_is_usable,
    request_is_from_edge,
)
from plane.authentication.middleware.identity_binding import (
    AssertedIdentity,
    binding_rejection,
    token_mpass_id,
)
from plane.authentication.middleware.mpass_token import (
    InvalidMpassToken,
    MpassTokenVerifier,
    cognito_issuer_from_settings,
)
from plane.authentication.middleware.proxy_auth_utils import (
    _coerce_bypass_paths,
    _is_bypass_path,
    _normalise_email,
)
from plane.authentication.utils.login import user_login
from plane.db.models import (
    Profile,
    Project,
    ProjectMember,
    User,
    Workspace,
    WorkspaceMember,
)
from plane.db.models.workspace import ROLE_CHOICES

# Build a label → value lookup so role names can be used symbolically.
# e.g. _ROLE["Member"] == 15, _ROLE["Guest"] == 5, _ROLE["Admin"] == 20
_ROLE = {label: value for value, label in ROLE_CHOICES}

# Provisioning tags the SMB default project with this external_source and
# external_id=SMB_NAME; the identifier is not used because it can collide with
# an existing team project (SMB_NAME "foss" -> identifier "FOSS").
SMB_DEFAULT_PROJECT_SOURCE = "smb-default"

logger = logging.getLogger("plane.authentication")

_NEW_USER_FLAGS = {
    "is_password_autoset": True,
    "is_email_verified": True,
}

# Session flag marking that this session's user has had its Profile and SMB
# memberships ensured. Renaming it makes every live session re-check once.
_SESSION_ENSURED_KEY = "proxy_auth_smb_membership_ensured"


_IDENTITY_HEADERS = ("HTTP_X_AUTH_REQUEST_EMAIL", "HTTP_X_AUTH_REQUEST_USER")
# Preferred-Username first: with email capture on it carries the mPass id and
# X-Auth-Request-User carries the email; with capture off only User has the id.
_MPASS_ID_HEADERS = ("HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME", "HTTP_X_AUTH_REQUEST_USER")
_ACCESS_TOKEN_HEADER = "HTTP_X_AUTH_REQUEST_ACCESS_TOKEN"


def _carries_identity_headers(request) -> bool:
    return any(request.META.get(header) for header in _IDENTITY_HEADERS)


def _asserted_mpass_ids(request) -> tuple[str, ...]:
    """Every mPass id the proxy headers assert, in header order; an email-shaped value is not one."""
    candidates = (request.META.get(header, "").strip() for header in _MPASS_ID_HEADERS)
    return tuple(value for value in candidates if value and "@" not in value)


def _mpass_id_for_logs(request) -> str:
    return next(iter(_asserted_mpass_ids(request)), "-")


def _synthetic_email_domain() -> str:
    return getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")


def _expected_corporate_id() -> str:
    """The trimmed SMB_CORPORATE_ID; a CHANGE_ME_ placeholder is kept so the gate stays on and refuses."""
    return (getattr(settings, "SMB_CORPORATE_ID", None) or "").strip()


def _corporate_config_rejection() -> str | None:
    return "placeholder_config" if is_placeholder(_expected_corporate_id()) else None


def _corporate_claims_rejection(claims: dict) -> str | None:
    """Why the verified token fails the SMB corporate gate, or None when it passes or the gate is off."""
    expected = _expected_corporate_id()
    if not expected:
        return None
    if claims.get("custom:is_corporate") != "true":
        return "not_corporate"
    if claims.get("custom:corporate_id") != expected:
        return "wrong_organization"
    return None


def _verified_token_claims(request, token_verifier) -> dict:
    token = request.META.get(_ACCESS_TOKEN_HEADER)
    if not token:
        raise InvalidMpassToken("missing_token")
    return token_verifier.verify(token)


@dataclass(frozen=True)
class LoginRefusal:
    reason: str
    token_mpass_id: str = "-"


def _login_refusal(request, email: str, token_verifier) -> LoginRefusal | None:
    """Why a header login is refused, or None when the verified token backs the asserted identity."""
    config_rejection = _corporate_config_rejection()
    if config_rejection:
        return LoginRefusal(config_rejection)
    try:
        claims = _verified_token_claims(request, token_verifier)
    except InvalidMpassToken as exc:
        return LoginRefusal(exc.reason)
    asserted = AssertedIdentity(email=email, mpass_ids=_asserted_mpass_ids(request))
    reason = _corporate_claims_rejection(claims) or binding_rejection(claims, asserted, _synthetic_email_domain())
    if reason is None:
        return None
    return LoginRefusal(reason, token_mpass_id(claims) or "-")


class ProxyAuthMiddleware:
    """
    Django middleware for mPass proxy authentication.

    oauth2-proxy sets X-Auth-Request-Email and X-Auth-Request-User on every
    request that has passed OIDC validation. This middleware reads those
    headers, finds or creates the corresponding Plane user, and establishes a
    native Django session — so the rest of the app sees a fully authenticated
    request.user just as it would after a normal login.

    The headers are honoured only on requests carrying MPASS_EDGE_SECRET in
    X-Mpass-Edge-Secret, which Traefik sets on the SSO router; on any other
    request they are ignored and Plane's own authentication applies. A login
    from them also needs the forwarded X-Auth-Request-Access-Token to verify
    and to name the same mPass id (and email, when it carries one).

    To disable, remove this class from the MIDDLEWARE list in settings.
    """

    def __init__(self, get_response, token_verifier=None):
        self.get_response = get_response
        self.bypass_paths = _coerce_bypass_paths(getattr(settings, "MPASS_BYPASS_PATHS", None))
        self.edge_secret = (getattr(settings, "MPASS_EDGE_SECRET", "") or "").strip()
        self.token_verifier = token_verifier or MpassTokenVerifier.from_settings(settings)
        if not edge_secret_is_usable(self.edge_secret):
            logger.error(
                "MPASS_EDGE_SECRET is unset, a CHANGE_ME_ placeholder or shorter than 32 characters: "
                "mPass identity headers will be ignored and SSO login is disabled"
            )
        elif is_placeholder(_expected_corporate_id()):
            logger.error("SMB_CORPORATE_ID is a CHANGE_ME_ placeholder: every mPass login is refused")
        else:
            self._log_token_verification_misconfiguration()

    def _log_token_verification_misconfiguration(self):
        if not self.token_verifier.is_configured:
            logger.error(
                "mPass token verification has no issuer or client id (MPASS_COGNITO_ISSUER_URL, "
                "MPASS_TOKEN_ISSUER_URL, MPASS_OIDC_CLIENT_ID): every mPass login will be refused"
            )
        if not cognito_issuer_from_settings(settings):
            logger.error(
                "the Cognito issuer is empty (MPASS_COGNITO_ISSUER_URL, or COGNITO_AWS_REGION and "
                "COGNITO_USER_POOL_ID): browser sessions forward Cognito-issued tokens, so every "
                "browser mPass login will be refused"
            )

    def __call__(self, request):
        # Bypass paths use their own auth (god-mode local login, instance admin).
        # TODO(mpass): Keep OPTIONS bypass at the proxy layer; add an app-level
        # fallback here only if preflight routing becomes inconsistent.
        if _is_bypass_path(request.path, self.bypass_paths):
            return self.get_response(request)

        email = _normalise_email(self._read_trusted_proxy_email(request))

        if request.user.is_authenticated:
            # Short-circuit only when the upstream-asserted identity matches the
            # current Django session, or when no header is present (request did
            # not pass through ForwardAuth — header absence is not a logout signal).
            current = _normalise_email(request.user.email or "")
            if not email or current == email:
                # A user provisioned outside the signup path can already hold a
                # session while still missing a Profile, and would otherwise
                # keep 404ing on /api/users/me/profile/ until the session
                # expires. Gate on a session flag so this runs once per session
                # rather than once per request. _auto_join_workspace then
                # finishes onboarding, the product tour and SMB memberships for
                # users provisioned or backfilled out of band.
                if not request.session.get(_SESSION_ENSURED_KEY):
                    Profile.objects.get_or_create(user=request.user)
                    self._auto_join_workspace(request.user)
                    request.session[_SESSION_ENSURED_KEY] = True
                return self.get_response(request)

            # Mismatch detected: proxy asserts a different identity than the
            # current session. Flush the stale session immediately so that if
            # subsequent re-auth fails (e.g., incoming user is inactive), the
            # request proceeds as unauthenticated rather than retaining the
            # previous user's identity.
            logout(request)

        if not email:
            return self.get_response(request)

        refusal = _login_refusal(request, email, self.token_verifier)
        if refusal:
            logger.warning(
                "mPass proxy login refused: reason=%s mpass_id=%s token_mpass_id=%s path=%s",
                refusal.reason,
                _mpass_id_for_logs(request),
                refusal.token_mpass_id,
                request.path,
            )
            return JsonResponse({"error": "access_denied"}, status=403)

        user = self._resolve_user(email)

        # Respect deactivated accounts — mPass authentication does not
        # override an explicit Plane account suspension.
        if not user.is_active:
            return self.get_response(request)

        user_login(request=request, user=user, is_app=True)
        # _resolve_user just guaranteed the profile, so the next request on this
        # session can skip the check instead of re-running it once per login.
        request.session[_SESSION_ENSURED_KEY] = True
        return self.get_response(request)

    def _read_trusted_proxy_email(self, request):
        """The proxy-asserted email, or "" when the request did not come through the edge.

        Untrusted identity headers are dropped before anything acts on them, so a
        forged header can neither log anyone in nor end an existing session.
        """
        if request_is_from_edge(request, self.edge_secret):
            return self._read_proxy_email(request)
        if _carries_identity_headers(request):
            logger.warning(
                "mPass identity headers ignored: request lacks the edge secret mpass_id=%s path=%s remote_addr=%s",
                _mpass_id_for_logs(request),
                request.path,
                request.META.get("REMOTE_ADDR", "-"),
            )
        return ""

    @staticmethod
    def _read_proxy_email(request):
        """Extract the upstream-asserted email from oauth2-proxy headers.

        Handles three cases:
          - X-Auth-Request-Email contains a real email → use as-is
          - X-Auth-Request-Email contains a bare username (user_id_claim=
            cognito:username) → synthesise <username>@DEFAULT_EMAIL_DOMAIN
          - X-Auth-Request-Email is empty but X-Auth-Request-User has a username
            → synthesise the same way

        Returns the raw (un-normalised) email string, or "" if none could be
        derived. Caller is responsible for `_normalise_email` before using.

        The login path only accepts a synthesised address that is the verified
        token's own `<mpass id>@DEFAULT_EMAIL_DOMAIN`, so a caller can synthesise
        no one else's.
        """
        email = (request.META.get("HTTP_X_AUTH_REQUEST_EMAIL") or "").strip()
        if email and "@" not in email:
            domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
            email = f"{email}@{domain}"
        if not email:
            username = (request.META.get("HTTP_X_AUTH_REQUEST_USER") or "").strip()
            if username:
                domain = getattr(settings, "DEFAULT_EMAIL_DOMAIN", "askii.ai")
                email = f"{username}@{domain}"
        return email

    def _resolve_user(self, email):
        username_hint = email.split("@")[0] or uuid4().hex
        try:
            user, _ = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": username_hint,
                    "password": make_password(None),
                    **_NEW_USER_FLAGS,
                },
            )
        except IntegrityError:
            # Concurrent email insert race — fall back to get().
            user = User.objects.get(email=email)

        # Run for every user, not just newly created ones. Users provisioned
        # outside the signup path — e.g. inserted directly by the JIRA import —
        # have no Profile row, which makes /api/users/me/profile/ return 404 and
        # bounces the client back to the login page in a loop. get_or_create is
        # idempotent, so an existing profile is left untouched.
        Profile.objects.get_or_create(user=user)

        # Run for every user (new or existing) — idempotent, no-op if already joined.
        self._auto_join_workspace(user)

        return user

    @staticmethod
    def _auto_join_workspace(user):
        """
        On every login, ensure the user is a member of the SMB workspace and its
        default project, and that their onboarding and product tour are marked
        complete so Plane skips the wizard and the welcome modal.
        If no workspace exists yet, do nothing — the normal create-workspace flow
        will be shown.
        Idempotent: get_or_create and conditional profile update make repeated
        calls safe and cheap.
        """

        # Prefer the workspace whose slug matches SMB_DEFAULT_WORKSPACE_NAME or SMB_NAME.
        smb_slug = getattr(settings, "SMB_DEFAULT_WORKSPACE_NAME", None) or getattr(
            settings, "SMB_NAME", ""
        )
        workspace = Workspace.objects.filter(slug=smb_slug).first()

        if workspace is None:
            return

        # Role: Member — auto-joined SSO users get full member access, not guest.
        workspace_member, _ = WorkspaceMember.objects.get_or_create(
            workspace=workspace,
            member=user,
            defaults={"role": _ROLE["Member"], "is_active": True},
        )

        if workspace_member.is_active:
            ProxyAuthMiddleware._join_smb_project(user, workspace_member)

        # Only update profile if onboarding is not yet complete — avoids a
        # write on every request for already-onboarded users.
        Profile.objects.filter(user=user, is_onboarded=False).update(
            is_onboarded=True,
            last_workspace_id=workspace.id,
            onboarding_step={
                "profile_complete": True,
                "workspace_create": True,
                "workspace_invite": True,
                "workspace_join": True,
            },
        )
        Profile.objects.filter(user=user, is_tour_completed=False).update(
            is_tour_completed=True
        )

    @staticmethod
    def _join_smb_project(user, workspace_member):
        smb_name = getattr(settings, "SMB_NAME", None)
        if not smb_name:
            return
        project = Project.objects.filter(
            workspace=workspace_member.workspace,
            external_source=SMB_DEFAULT_PROJECT_SOURCE,
            external_id=smb_name,
            archived_at__isnull=True,
        ).first()
        if project is None:
            return
        # An inactive row means the user left or an admin removed them, so it
        # is deliberately not reactivated.
        try:
            with transaction.atomic():
                ProjectMember.objects.get_or_create(
                    project=project,
                    member=user,
                    defaults={
                        "role": workspace_member.role,
                        "is_active": True,
                    },
                )
        except IntegrityError:
            logger.warning(
                "SMB project auto-join failed for user %s on project %s",
                user.id,
                project.id,
                exc_info=True,
            )
