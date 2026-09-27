"""Layer-2 backend that runs `claude -p` on the person's own login.

Isolation verified 2026-09-26 (docs/architecture.md): from a fresh empty
directory with these flags the model gets no tools, MCP servers, skills,
hooks or CLAUDE.md. `--bare` is not used because it drops subscription login.
"""
import json
import os
import shutil
import subprocess
import tempfile


def classify(system_prompt: str, fenced_skill_text: str, timeout_s: int, *, model: str) -> str:
    """Return the model's unmodified answer text, or raise RuntimeError
    without diagnostics. The skill text goes on stdin, never in argv."""
    claude = shutil.which("claude")
    if not claude:
        raise RuntimeError("claude is not installed")
    workdir = tempfile.mkdtemp(prefix="canary-classify-")
    try:
        prompt_dir = tempfile.mkdtemp(prefix="canary-prompt-")
        try:
            prompt_file = os.path.join(prompt_dir, "system.txt")
            with open(prompt_file, "w", encoding="utf-8") as fh:
                fh.write(system_prompt)
            argv = [claude, "-p", "--disable-slash-commands", "--tools", "",
                    "--strict-mcp-config", "--setting-sources", "",
                    "--no-session-persistence", "--max-turns", "1",
                    "--output-format", "json", "--model", model,
                    "--system-prompt-file", prompt_file]
            try:
                proc = subprocess.run(argv, cwd=workdir, input=fenced_skill_text,
                                      capture_output=True, text=True, timeout=timeout_s)
            except Exception:
                raise RuntimeError("claude did not finish") from None
        finally:
            shutil.rmtree(prompt_dir, ignore_errors=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if proc.returncode != 0:
        raise RuntimeError("claude exited with an error")
    try:
        data = json.loads(proc.stdout)
        if data.get("is_error") is not False or not isinstance(data.get("result"), str):
            raise ValueError
    except Exception:
        raise RuntimeError("claude returned an error or malformed output") from None
    return data["result"]
