# Billy Mission Control

An owner-only, read-only, phone-first cockpit for the owner of the AI Medicine Collective's agent team. It shows what agents are working on, what is waiting for the owner, and each task's path from issue to reviewed commit to merged pull request. It never approves, merges or publishes anything: those stay on GitHub, with the owner.

**This repository is public; the cockpit is not.** The code is open, but Mission Control will run only on the owner's agent server, reachable over Tailscale with a passkey (phase A4). This repository never holds data, credentials, or details of that machine (names, addresses, configuration). Its `main` branch is protected by an enforced ruleset.

**Status: phase A4a, the service, in supervised testing only.** The A3 screens (Home, Tasks, Task detail, Usage and Settings, on made-up demo data) can now also run as a service behind Tailscale Serve. It checks the owner's exact Tailscale login, has one write action (a stop button that asks a separate stop helper to set Billy's stop marker), keeps an append-only events log, and refuses to start unless its start-up checks pass. The passkey (A4b) and the owner's acceptance tests (A4c) come before routine use. No real data, no credentials, no outbound network calls, nothing deployed by an agent. The design and the build plan live in the public repository:

- [Design: `docs/agents/mission-control.md`](https://github.com/DrZaff/ai-medicine-collective/blob/main/docs/agents/mission-control.md)
- [Build plan: `docs/agents/mission-control-plan.md`](https://github.com/DrZaff/ai-medicine-collective/blob/main/docs/agents/mission-control-plan.md) (A1 is issue [#200](https://github.com/DrZaff/ai-medicine-collective/issues/200))

How agents work in this repository: [AGENTS.md](AGENTS.md). The owner's GitHub settings: [docs/owner-settings.md](docs/owner-settings.md).

## Stack

**Python 3.12, standard library only** (WSGI, `wsgiref`, `unittest`), with server-rendered HTML.

- **Small and maintainable on the Dell:**
  - Ubuntu 24.04 ships Python 3.12.
  - The app has no runtime dependencies to install, update or patch.
  - Billy's existing tools are Python too.
- **A small attack surface:** no JavaScript framework, no build step, no package tree. The page is plain HTML under a strict Content Security Policy that allows nothing to load.
- **Easy to test:** a WSGI app is a plain function, so tests call it directly with no server and no network.
- **One development tool,** [ruff](https://docs.astral.sh/ruff/), for lint and formatting. It's pinned by version and file hash in `requirements-dev.txt`.

## Develop

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.txt

.venv/bin/python dev.py lint    # ruff check, ruff format --check, credential scan
python3 dev.py test             # unit tests; needs nothing installed

python3 -m mission_control      # local preview at http://127.0.0.1:8765/ (loopback only)
```

The preview server refuses any address but IPv4 loopback (`127.0.0.1` or `localhost`), so it can't be reached from another machine.

### The service (phase A4a; installed by the owner, never by an agent)

```sh
python3 -m mission_control serve --config FILE                 # the web app, from its systemd socket unit
python3 -m mission_control stopper --config FILE               # the stop helper, from its own socket unit
python3 -m mission_control selfcheck app|stopper --config FILE  # every start-up check, PASS or FAIL
python3 -m mission_control export-events --config FILE --since YYYY-MM-DD --out NEW_FILE
```

The config files live only on the server; `config.example.json` and `stopper.example.json` show their shape with placeholder paths. `serve` and `stopper` refuse to start unless every check passes, and accept only a socket that systemd hands them (no TCP port).

CI (`.github/workflows/ci.yml`) runs the same two commands, as the **lint** and **test** checks, on every pull request.

## Layout

| Path | What |
| --- | --- |
| `mission_control/app.py` | The WSGI app: routes, read-only method handling, security headers; in service mode, the owner check, the stop POST and event logging |
| `mission_control/__main__.py` | The loopback-only development server, and the service commands (`serve`, `stopper`, `selfcheck`, `export-events`) |
| `mission_control/service.py` | The Unix-socket server: systemd socket activation, kernel-checked callers, the trusted Tailscale login, header limits |
| `mission_control/stopper.py` | The stop helper: one fixed request, one caller, an atomic and durable marker, no way to remove it |
| `mission_control/events.py` | The append-only events log (SQLite) and its JSON Lines export |
| `mission_control/config.py`, `checks.py` | The server config's shape, and the start-up checks that fail closed |
| `config.example.json`, `stopper.example.json` | The configs' shape, with placeholder paths |
| `mission_control/views.py` | The screens: server-rendered HTML, every state and flag in words, everything escaped |
| `mission_control/demo.py`, `demo.json` | Demo 0: synthetic tasks and the placeholder command templates, validated on load |
| `mission_control/static/app.css` | The one stylesheet: one column on phones, light and dark |
| `mission_control/tasks.py` | The task-state model (A2): pure functions deriving a task's state from GitHub-shaped data and Billy's run records |
| `tests/fixtures/tasks/` | Synthetic task examples with their expected states, for the model's tests |
| `tests/` | App, screens, service, server, credential scanner and repository-policy tests |
| `tools/check_secrets.py` | Fails on credential-shaped text in any file |
| `dev.py` | The `lint` and `test` commands |
| `.github/workflows/ci.yml` | CI: read-only permissions, no secrets, actions pinned to commits |
| `.github/CODEOWNERS` | Every path belongs to the owner |
| `docs/owner-settings.md` | The `main` ruleset and repository settings only the owner can set |
