"""Path handling shared by the host adapters.

The hook no longer models shell commands (program 2026-09-30, back to the
front door): it looks at a command only for installer invocations, and at
file tools and patches for the paths they write.
"""
import os
from pathlib import Path


def given(value, cwd):
    """The path as the tool will use it: absolute and tidied, links NOT
    resolved. The gate checks this form and the resolved one, because a
    link inside a skills folder can lead anywhere."""
    path(value, cwd)  # the same validation
    return os.path.normpath(os.path.join(cwd, os.path.expanduser(value)))


def path(value, cwd):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Expected a nonempty filesystem path")
    if value.startswith("~") and value != "~" and not value.startswith("~/"):
        raise ValueError("Named-user expansion is not supported")
    path = Path(os.path.expanduser(value))
    if not path.is_absolute():
        path = Path(cwd) / path
    try:
        return str(path.resolve())
    except (OSError, RuntimeError) as exc:
        raise ValueError("Cannot resolve tool path") from exc
