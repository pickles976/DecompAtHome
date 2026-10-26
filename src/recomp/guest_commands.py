"""Render the guest's trusted command table from a project's plugin manifest.

The host addresses guest work by one identifier per plugin and verification
mode — `<plugin>.<mode>` (see `verification.VerificationPlan.command_id`) — and
`guest.resolve_command` insists that the argv it runs is absolute. A plugin
manifest, by contrast, stays host-portable: its `[commands]` are relative to the
plugin directory so `recomp plugin run-task` works from a checkout.

This module is the one place that translates between them. The translation is
pinned in both directions: the interpreter and plugin paths become the image's
absolute layout, and every rendered table is fed back through `resolve_command`
so a manifest the guest would reject fails here, at build time, with the plugin's
own words in the message.

A plugin that ships no `guest` command cannot be verified in a microVM at all,
which is exactly what the caller needs to know before it publishes tasks.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from recomp.guest import SCHEMA, GuestJobError, resolve_command
from recomp.plugin import Plugin

#: Where the toolchain image installs the project's pinned plugin copies.
IMAGE_PLUGIN_ROOT = "/opt/recomp/plugins"
#: The interpreter the pinned toolchain image guarantees.
IMAGE_INTERPRETER = "/usr/local/bin/python3"
#: The plugin subcommand that speaks the guest job protocol (--job/--input/--target).
GUEST_COMMAND = "guest"


class GuestCommandError(ValueError):
    """The plugin cannot be addressed by the guest contract."""


def _absolute(plugin_root: str, argv: Sequence[str]) -> tuple[str, ...]:
    """Rewrite a manifest argv into the image's absolute layout.

    A manifest written as `["python3", "runner.py", "guest"]` means "the plugin's
    own runner, run by the image's interpreter": the interpreter becomes the image
    path and the first `.py` argument becomes relative to the installed plugin.
    Anything else (a subcommand name, a flag) is carried through unchanged.
    """

    if not argv:
        raise GuestCommandError("the plugin declares an empty argv")
    program, *rest = [str(item) for item in argv]
    if program in ("python3", "python"):
        program = IMAGE_INTERPRETER
    elif not program.startswith("/"):
        raise GuestCommandError(
            f"the interpreter {program!r} must be an absolute path in the image")
    rewritten = [program]
    located = False
    for item in rest:
        if not located and item.endswith(".py") and not item.startswith("/"):
            rewritten.append(f"{plugin_root}/{item}")
            located = True
        else:
            rewritten.append(item)
    if not located:
        raise GuestCommandError(
            f"the command argv {list(argv)} names no runner script inside the plugin")
    return tuple(rewritten)


def guest_argv(plugin: Plugin, *, plugin_root: str = IMAGE_PLUGIN_ROOT) -> tuple[str, ...]:
    """The absolute argv the guest runs for this plugin's verification command."""

    declared = plugin.commands
    if GUEST_COMMAND not in declared:
        available = ", ".join(sorted(declared)) or "none"
        raise GuestCommandError(
            f"plugin {plugin.name!r} declares no {GUEST_COMMAND!r} command (it has: "
            f"{available}); a plugin whose work is judged in a microVM must implement "
            "the guest job protocol")
    return _absolute(f"{IMAGE_PLUGIN_ROOT.rstrip('/')}/{plugin.name}", declared[GUEST_COMMAND])


def render_commands(plugin: Plugin, *, plugin_root: str = IMAGE_PLUGIN_ROOT) -> dict[str, Any]:
    """The trusted table one image ships, keyed by the host's command id."""

    from recomp.verification import VerificationPlan

    plan = VerificationPlan.from_plugin(plugin)
    table = {
        "schema": SCHEMA,
        "commands": {plan.command_id: list(guest_argv(plugin, plugin_root=plugin_root))},
    }
    try:
        resolve_command(table, plan.command_id)
    except GuestJobError as exc:
        raise GuestCommandError(f"the rendered command table is invalid: {exc}") from exc
    return table


def write_commands(plugin: Plugin, destination: str | Path, *,
                   plugin_root: str = IMAGE_PLUGIN_ROOT) -> Path:
    """Write `commands.json` deterministically; the file is part of the build context."""

    table = render_commands(plugin, plugin_root=plugin_root)
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n")
    return target
