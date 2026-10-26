"""Contributor prompt generation.

Each project exposes a contributor prompt in the style of the Open-BFME
"give your AI agent this exact prompt": identity, what counts, setup, the
loop, publishing, final report. The prompt lives with the plugin
(``plugins/<name>/prompt.md``) so the host's agent can rewrite the workflow
prompt together with the workflow itself — and because plugin files are
policy-hashed, every prompt edit is versioned like any other tooling change.
"""

from __future__ import annotations

from pathlib import Path

from recomp.plugin import resolve_plugin
from recomp.project import load_project
from recomp.templates import _read

def render_prompt(project_root: str | Path, cfg: dict | None = None,
                  lock: dict | None = None) -> str:
    root = Path(project_root)
    if cfg is None:
        cfg, _ = load_project(root)
    plugin = resolve_plugin(root, cfg["project"]["plugin"])

    source = plugin.root / "prompt.md"
    text = source.read_text() if source.is_file() else _read("prompt_default.md")

    if lock is None:
        from recomp.policy import load_lock
        lock = load_lock(root) or {"policy_version": 0}

    github = cfg.get("github", {})
    repository_url = (f"https://github.com/{github.get('owner', 'OWNER')}/"
                      f"{github.get('repository', cfg['project']['name'])}")
    replacements = {
        "PROJECT_NAME": cfg["project"]["name"],
        "GOAL": cfg["project"]["goal"],
        "PLUGIN": plugin.name,
        "TIER": cfg.get("target", {}).get("tier", "t1-structure"),
        "PLATFORM": cfg.get("target", {}).get("platform", "unknown"),
        "REPOSITORY_URL": repository_url,
        "TARGET_SHA256": cfg.get("target", {}).get("sha256", ""),
        "POLICY_VERSION": str(lock["policy_version"]),
    }
    for key, value in replacements.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text
