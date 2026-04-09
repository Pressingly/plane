# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

_DEFAULT_BYPASS_PATHS = ["/god-mode", "/api/instances"]


def _normalise_email(email: str) -> str:
    return email.strip().lower()


def _is_bypass_path(path: str, bypass_paths: list) -> bool:
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in bypass_paths)


def _coerce_bypass_paths(setting) -> list:
    if not setting:
        return list(_DEFAULT_BYPASS_PATHS)
    if isinstance(setting, str):
        return [setting]
    return list(setting)
