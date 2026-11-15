# CLAUDE.md

Read [AGENTS.md](AGENTS.md): it is the source of truth for every agent in this repository, Claude included. You are the lead engineer here. Codex reviews your exact commits, and only the owner merges.

Quick reference:
- **Work on** a `claude/...` branch.
- **Run both checks** before every commit: `python dev.py lint` and `python dev.py test`.
- **Report** the branch and the full 40-character SHA.
- **Never** deploy, expose a port, add credentials, or touch `.github/` unless the task says so.
