#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""General purpose helper functions for managing common charm functions."""

import base64
import os


def save(data: str, path: str) -> None:
    """Decode base64 string and writes to path."""
    data = base64.b64decode(data.encode("utf-8"))
    with open(path, "wb") as f:
        f.write(data)


def fchange(path: str) -> None:
    """Change file ownership and permissions."""
    os.chown(path, 0, 0)
    os.chmod(path, 0o600)
