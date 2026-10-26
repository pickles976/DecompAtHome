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


def toolchain_launcher(image) -> str:
    return _read("recomp-launcher").replace("{{IMAGE}}", str(image))


def toolchain_containerfile() -> str:
    return _read("toolchain/Containerfile")


def systemd_unit() -> str:
    return _read("systemd/recomp-coordinator.service")


def github_workflow(name: str) -> str:
    return _read(f"github/{name}")


def pull_request_template() -> str:
    return _read("github/pull_request_template.md")


def codeowners() -> str:
    return _read("github/CODEOWNERS")


def project_readme() -> str:
    return _read("project_readme.md")


def contributing() -> str:
    return _read("contributing.md")


def coordinator_machine_setup() -> str:
    return _read("coordinator_machine_setup.sh")
