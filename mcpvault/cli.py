"""Command-line entry points (see vault.py)."""

import os
import sys
import webbrowser

from . import paths


def _ui() -> int:
    from .launcher import AgentClient, LauncherError

    try:
        AgentClient().ensure_running()
    except LauncherError as exc:
        print(f"mcp-vault: {exc}", file=sys.stderr)
        return 1
    if not os.environ.get("MCPVAULT_NO_BROWSER"):
        webbrowser.open(f"http://127.0.0.1:{paths.PORT}/")
    return 0


def _status() -> int:
    from .launcher import AgentClient

    client = AgentClient()
    if not client.ping():
        print("agent: not running")
        return 1
    _, body = client.call("GET", "/internal/ping")
    print(f"agent: running on 127.0.0.1:{client.port}, vault {'unlocked' if body.get('unlocked') else 'locked'}")
    return 0


def _stop(force: bool) -> int:
    """Stop the agent. With force, also end agent processes that no longer answer
    (e.g. a stale agent whose token file was overwritten)."""
    import time

    from . import winutil
    from .launcher import AgentClient

    client = AgentClient()
    stopped = False
    if client.ping():
        client.call("POST", "/internal/shutdown")
        stopped = True
    if force:
        deadline = time.monotonic() + 5  # give a clean shutdown a moment first
        leftovers = winutil.agent_pids(paths.ENTRY)
        while leftovers and time.monotonic() < deadline:
            time.sleep(0.5)
            leftovers = winutil.agent_pids(paths.ENTRY)
        # An agent started from another MCP Vault folder (old install, share zip) that
        # still holds the port would block every new agent; end it too.
        holder = winutil.port_owner(paths.PORT)
        if holder and holder not in leftovers and holder != os.getpid() and not client.ping() \
                and winutil.is_vault_agent_cmdline(winutil.process_cmdline(holder)):
            leftovers.append(holder)
        for pid in leftovers:
            try:
                os.kill(pid, 9)  # TerminateProcess on Windows
            except OSError as exc:
                print(f"agent: could not end pid {pid} ({exc}); try again from an elevated prompt")
        if leftovers:
            print(f"agent: ended {len(leftovers)} unresponsive agent process(es)")
            stopped = True
        try:
            os.remove(paths.SPAWN_LOCK)
        except OSError:
            pass
    print("agent: stopped" if stopped else "agent: not running")
    return 0


def _install_shortcut(quiet: bool = False) -> int:
    from . import winutil

    # Point at the .bat files so the shortcuts always go through the dependency check.
    winutil.create_shortcut(winutil.start_menu_shortcut_path(), paths.LAUNCHER_BAT, "", paths.APP_DIR, "Open MCP Vault")
    winutil.create_shortcut(winutil.stop_menu_shortcut_path(), paths.STOP_BAT, "", paths.APP_DIR,
                            "Stop the MCP Vault agent (locks the vault)", icon=winutil.STOP_ICON)
    if not quiet:
        print(f"Start menu shortcuts created: {winutil.start_menu_shortcut_path()}, {winutil.stop_menu_shortcut_path()}")
    return 0


# Files that go into a share zip. An allowlist, so a vault, logs, notes or a
# .venv can never be included by accident (user data lives in %APPDATA% anyway).
SHARE_FILES = ["MCP Vault.bat", "Stop MCP Vault.bat", "Make share zip.bat", "vault.py", "requirements.txt", "README.md",
               "SERVER-SPEC.md", "LICENSE"]
SHARE_DIRS = {
    "mcpvault": (".py", ".html"),
    "skills": (".md", ".py", ".json", ".txt"),
    "agent": (".ps1", ".bat", ".md"),
    "servers": (".py", ".json", ".txt", ".md"),
}
SKIP_SHARE_NAMES = {"hosts.json", "agent.key", "agent.log", "agent.pid"}


def _package(out_dir: str | None) -> int:
    import os
    import zipfile

    from . import __version__

    out_dir = out_dir or paths.APP_DIR
    out = os.path.join(out_dir, f"mcp-vault-{__version__}.zip")
    files = [f for f in SHARE_FILES if os.path.exists(os.path.join(paths.APP_DIR, f))]
    for d, exts in SHARE_DIRS.items():
        top = os.path.join(paths.APP_DIR, d)
        if not os.path.isdir(top):
            continue
        for root, dirs, names in os.walk(top):
            dirs[:] = [x for x in dirs if x not in ("__pycache__", ".venv", ".git")]
            files += [
                os.path.relpath(os.path.join(root, n), paths.APP_DIR)
                for n in names
                if n.endswith(exts) and n.lower() not in SKIP_SHARE_NAMES
            ]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(files):
            zf.write(os.path.join(paths.APP_DIR, rel), os.path.join("mcp-vault", rel))
    print(f"Created {out} ({len(files)} files):")
    for rel in sorted(files):
        print(f"  {rel}")
    return 0


def _install_skills(force: bool = False) -> int:
    import shutil

    try:
        os.makedirs(paths.DATA_DIR, exist_ok=True)
        app_dir_file = getattr(paths, "APP_DIR_FILE", os.path.join(paths.DATA_DIR, "app_dir.txt"))
        with open(app_dir_file, "w", encoding="utf-8") as fh:
            fh.write(paths.APP_DIR)
    except OSError:
        pass

    src = os.path.join(paths.APP_DIR, "skills")
    if not os.path.isdir(src):
        print("no skills folder in this copy of MCP Vault", file=sys.stderr)
        return 1
    home = os.path.expanduser("~")
    targets = []
    claude_home = os.environ.get("MCPVAULT_CLAUDE_HOME") or os.path.join(home, ".claude")
    claude = os.path.join(claude_home, "skills")
    if os.path.isdir(claude_home):
        targets.append(("Claude Code", claude, "Claude Code picks the skills up in new sessions."))
    if os.path.isdir(paths.KIMI_SKILLS_DIR) or os.path.isdir(os.path.dirname(paths.KIMI_SKILLS_DIR)):
        targets.append(("Kimi Work", paths.KIMI_SKILLS_DIR, "Kimi Work picks the skills up in new sessions."))
    if os.path.isdir(paths.CODEX_HOME):
        targets.append(("Codex", paths.CODEX_SKILLS_DIR, "Codex picks the skills up in new sessions."))
    ag_alt = os.path.join(home, ".gemini", "antigravity")
    if os.path.isdir(paths.ANTIGRAVITY_HOME) or (
        not os.environ.get("MCPVAULT_ANTIGRAVITY_HOME") and os.path.isdir(ag_alt)
    ):
        targets.append(("Antigravity", paths.ANTIGRAVITY_SKILLS_DIR, "Antigravity picks the skills up automatically."))
    if not targets:
        print("no supported client installation found (Claude Code, Kimi Work, Codex, Antigravity)", file=sys.stderr)
        return 1
    default_app_dir = os.path.join(home, ".mcp-servers", "mcp-vault")
    stamp_app_dir = os.path.normcase(os.path.normpath(paths.APP_DIR)) != os.path.normcase(os.path.normpath(default_app_dir))
    for label, dst, note in targets:
        os.makedirs(dst, exist_ok=True)
        for name in sorted(os.listdir(src)):
            if not os.path.isfile(os.path.join(src, name, "SKILL.md")):
                continue
            target = os.path.join(dst, name)
            if os.path.exists(target) and not force:
                print(f"skip {name} ({label}): {target} exists (use --force to replace it)")
                continue
            if os.path.exists(target):
                shutil.rmtree(target)
            shutil.copytree(os.path.join(src, name), target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            if stamp_app_dir:
                skill_md = os.path.join(target, "SKILL.md")
                try:
                    with open(skill_md, encoding="utf-8") as fh:
                        text = fh.read()
                    updated = text.replace(r"$HOME\.mcp-servers\mcp-vault", paths.APP_DIR)
                    if updated != text:
                        with open(skill_md, "w", encoding="utf-8", newline="\n") as fh:
                            fh.write(updated)
                except OSError:
                    pass
            print(f"installed skill {name} -> {target}")
        print(note)
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "ui"
    from .manage import COMMANDS

    if cmd in COMMANDS:
        from .manage import main as manage_main

        return manage_main(argv)
    if cmd == "install-skills":
        return _install_skills("--force" in argv)
    if cmd == "relink":
        from .clients import relink

        for r in relink():
            if r.get("error"):
                print(f"relink: {r['client']}: skipped ({r['error']})")
            else:
                print(f"relink: {r['label']}: {', '.join(r['servers'])} now use {paths.APP_DIR}")
        return 0
    if cmd == "run":
        if len(argv) != 2:
            print("usage: vault.py run <server>", file=sys.stderr)
            return 2
        from .launcher import run

        return run(argv[1])
    if cmd == "agent":
        from .agent import serve

        return serve()
    if cmd == "prompt":
        from .prompt import main as prompt_main

        if sys.stdout is not None:
            sys.stdout.reconfigure(encoding="utf-8")
        return prompt_main(argv[1] if len(argv) > 1 else "")
    if cmd == "ui":
        return _ui()
    if cmd == "status":
        return _status()
    if cmd == "stop":
        return _stop("--force" in argv)
    if cmd == "install-shortcut":
        return _install_shortcut("--quiet" in argv)
    if cmd == "package":
        return _package(argv[1] if len(argv) > 1 else None)
    print("usage: vault.py [ui | status | stop [--force] | list | show | templates | logs | host | server | test | apply\n"
          "                 | run <server> | agent | install-shortcut | install-skills [--force] | relink | package [dir]]\n"
          "       vault.py <command> --help   for details", file=sys.stderr)
    return 2
