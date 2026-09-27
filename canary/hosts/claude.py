"""Claude Code host boundary (docs/architecture.md, "Host adapters").

Slice 3 needs only `install_root`; the hook functions land with slice 4.
"""
import os


def install_root(home: str) -> str:
    """User-level skills folder Claude Code discovers."""
    return os.path.join(home, ".claude", "skills")
