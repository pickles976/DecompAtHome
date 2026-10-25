"""Embedded templates: dashboard, per-project AGENTS.md, plugin scaffolds."""

from __future__ import annotations

TEMPLATES_DIR = __file__.rsplit("/", 1)[0] + "/templates"


def _read(name: str) -> str:
    from pathlib import Path
    return (Path(__file__).parent / "templates" / name).read_text()


def dashboard_html(project_name: str) -> str:
    return _read("dashboard.html").replace("{{PROJECT_NAME}}", project_name)


def project_agents_md(cfg: dict) -> str:
    target = cfg.get("target", {})
    return (_read("project_agents.md")
            .replace("{{PROJECT_NAME}}", cfg["project"]["name"])
            .replace("{{PLUGIN}}", cfg["project"]["plugin"])
            .replace("{{GOAL}}", cfg["project"]["goal"])
            .replace("{{TIER}}", target.get("tier", "t1-structure"))
            .replace("{{PLATFORM}}", target.get("platform", "unknown")))


def plugin_manifest(name: str, capability: str) -> str:
    return (_read("plugin_manifest.toml")
            .replace("{{NAME}}", name)
            .replace("{{CAPABILITY}}", capability))


def plugin_runner() -> str:
    return _read("plugin_runner.py")
