# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
"""
Unit tests for mPass proxy auth helper functions.

These are pure Python tests with no Django/DB dependency.

Run (from apps/api/):
    pytest plane/authentication/tests/test_proxy_auth_core.py -v
"""

import pytest

from plane.authentication.middleware.proxy_auth_utils import (
    _DEFAULT_BYPASS_PATHS,
    _coerce_bypass_paths,
    _is_bypass_path,
    _normalise_email,
)


# ---------------------------------------------------------------------------
# _normalise_email
# ---------------------------------------------------------------------------


class TestNormaliseEmail:
    def test_lowercases(self):
        assert _normalise_email("USER@EXAMPLE.COM") == "user@example.com"

    def test_strips_leading_trailing_whitespace(self):
        assert _normalise_email("  user@example.com  ") == "user@example.com"

    def test_lowercases_and_strips_combined(self):
        assert _normalise_email("  NORM@EXAMPLE.COM  ") == "norm@example.com"

    def test_already_normalised_is_unchanged(self):
        assert _normalise_email("user@example.com") == "user@example.com"

    def test_internal_whitespace_preserved(self):
        assert _normalise_email("user @example.com") == "user @example.com"


# ---------------------------------------------------------------------------
# _is_bypass_path
# ---------------------------------------------------------------------------


class TestIsBypassPath:
    def test_exact_match(self):
        assert _is_bypass_path("/god-mode", ["/god-mode"]) is True

    def test_prefix_match(self):
        assert _is_bypass_path("/god-mode/setup/", ["/god-mode"]) is True

    def test_no_match(self):
        assert _is_bypass_path("/api/issues/", ["/god-mode", "/api/instances"]) is False

    def test_partial_segment_does_not_match(self):
        assert _is_bypass_path("/god-modex/", ["/god-mode"]) is False

    def test_instances_prefix_match(self):
        assert _is_bypass_path("/api/instances/config/", ["/god-mode", "/api/instances"]) is True

    def test_empty_bypass_list_never_matches(self):
        assert _is_bypass_path("/god-mode/", []) is False

    def test_root_path_no_match(self):
        assert _is_bypass_path("/", ["/god-mode", "/api/instances"]) is False


# ---------------------------------------------------------------------------
# _coerce_bypass_paths
# ---------------------------------------------------------------------------


class TestCoerceBypassPaths:
    def test_none_returns_defaults(self):
        assert _coerce_bypass_paths(None) == list(_DEFAULT_BYPASS_PATHS)

    def test_empty_string_returns_defaults(self):
        assert _coerce_bypass_paths("") == list(_DEFAULT_BYPASS_PATHS)

    def test_empty_list_returns_defaults(self):
        assert _coerce_bypass_paths([]) == list(_DEFAULT_BYPASS_PATHS)

    def test_single_string_wrapped_in_list(self):
        assert _coerce_bypass_paths("/god-mode") == ["/god-mode"]

    def test_comma_separated_string_split_into_multiple_paths(self):
        result = _coerce_bypass_paths("/god-mode,/api/instances")
        assert result == ["/god-mode", "/api/instances"]

    def test_comma_separated_string_with_spaces(self):
        result = _coerce_bypass_paths("/god-mode, /api/instances")
        assert result == ["/god-mode", "/api/instances"]

    def test_comma_only_string_returns_defaults(self):
        assert _coerce_bypass_paths(",,,") == list(_DEFAULT_BYPASS_PATHS)

    def test_list_returned_as_list(self):
        result = _coerce_bypass_paths(["/god-mode", "/api/instances"])
        assert result == ["/god-mode", "/api/instances"]

    def test_tuple_converted_to_list(self):
        result = _coerce_bypass_paths(("/god-mode", "/api/instances"))
        assert isinstance(result, list)
        assert result == ["/god-mode", "/api/instances"]

    def test_returns_copy_not_same_object(self):
        result = _coerce_bypass_paths(None)
        result.append("/extra")
        assert "/extra" not in _DEFAULT_BYPASS_PATHS
