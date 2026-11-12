# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

PLACEHOLDER_PREFIX = "CHANGE_ME_"


def is_placeholder(value: str) -> bool:
    return value.startswith(PLACEHOLDER_PREFIX)


def configured(value) -> str:
    """A setting's value, or "" when it is unset or still an .env.example placeholder."""
    text = (value or "").strip()
    return "" if is_placeholder(text) else text
