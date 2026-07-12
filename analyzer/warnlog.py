"""
Shared stderr warning helper.

Keeps the "[component] [WARN] message" format consistent across modules
instead of each one hand-writing its own print(..., file=sys.stderr) call.
"""

from __future__ import annotations

import sys


def warn(component: str, message: str) -> None:
    print(f"  [{component}] [WARN] {message}", file=sys.stderr)
