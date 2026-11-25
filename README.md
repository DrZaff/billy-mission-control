# Billy Mission Control

An owner-only, read-only, phone-first cockpit for the owner of the AI Medicine Collective's agent team. It shows what agents are working on, what is waiting for the owner, and each task's path from issue to reviewed commit to merged pull request. It never approves, merges or publishes anything: those stay on GitHub, with the owner.

**This repository is public; the cockpit is not.** The code is open, but Mission Control will run only on the owner's agent server, reachable over Tailscale with a passkey (phase A4). This repository never holds data, credentials, or details of that machine (names, addresses, configuration). Its `main` branch is protected by an enforced ruleset.

**Status: phase A4b, passkey sign-in, in supervised testing only.** The A3 screens (on made-up demo data) run as a service behind Tailscale Serve (A4a): the owner's exact Tailscale login, one write action (a stop button that asks a separate stop helper to set Billy's stop marker), an append-only events log, and start-up checks that fail closed. A4b adds the second sign-in layer: every page now also needs a passkey session (the owner's iPhone, or a backup security key), with passkeys added and removed only from a shell on the server. The owner's acceptance tests (A4c) come before routine use. No real data, no outbound network calls from the app, nothing deployed by an agent. Phase A5a, in review, adds the fetcher (below): a separate, read-only process that reads GitHub for the app; the screens will use its snapshot in A5b.

- [Design: `docs/agents/mission-control.md`](https://github.com/DrZaff/ai-medicine-collective/blob/main/docs/agents/mission-control.md)
- [Build plan: `docs/agents/mission-control-plan.md`](https://github.com/DrZaff/ai-medicine-collective/blob/main/docs/agents/mission-control-plan.md) (A1 is issue [#200](https://github.com/DrZaff/ai-medicine-collective/issues/200))

How agents work in this repository: [AGENTS.md](AGENTS.md). The owner's GitHub settings: [docs/owner-settings.md](docs/owner-settings.md).

## Stack

**Python 3.12, standard library only** (WSGI, `wsgiref`, `unittest`), with server-rendered HTML, apart from one pinned library for passkey sign-in, `fido2`, and its dependency `cryptography`, which the fetcher also uses to sign the GitHub App's token.

- **Small and maintainable on the Dell:**
  - Ubuntu 24.04 ships Python 3.12.
  - Apart from those two pinned libraries, nothing to install, update or patch.
  - Billy's existing tools are Python too.
- **A small attack surface:** no JavaScript framework, no build step, no package tree. The page is plain HTML under a strict Content Security Policy that allows nothing to load.
- **Easy to test:** a WSGI app is a plain function, so tests call it directly with no server and no network.
- **One development tool,** [ruff](https://docs.astral.sh/ruff/), for lint and formatting. It's pinned by version and file hash in `requirements-dev.txt`.

## Develop

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.txt

.venv/bin/python dev.py lint    # ruff check, ruff format --check, credential scan
python3 -m pip install --require-hashes -r requirements.txt   # passkey sign-in's one library (pinned by hash)
python3 dev.py test             # unit tests
python3 tools/audit_deps.py     # known vulnerabilities in the pinned requirements (CI runs it too)

python3 -m mission_control      # local preview at http://127.0.0.1:8765/ (loopback only)
```

The preview server refuses any address but IPv4 loopback (`127.0.0.1` or `localhost`), so it can't be reached from another machine.

### The service (phase A4a; installed by the owner, never by an agent)

```sh
python3 -m mission_control serve --config FILE                 # the web app, from its systemd socket unit
python3 -m mission_control stopper --config FILE               # the stop helper, from its own socket unit
python3 -m mission_control selfcheck app|stopper --config FILE  # every start-up check, PASS or FAIL
python3 -m mission_control export-events --config FILE --since YYYY-MM-DD --out NEW_FILE
python3 -m mission_control passkey enroll|list|revoke ID|reset --config FILE   # server shell only
```

The config files live only on the server; `config.example.json` and `stopper.example.json` show their shape with placeholder paths. `serve` and `stopper` refuse to start unless every check passes, and accept only a socket that systemd hands them (no TCP port).

### The fetcher (phase A5a; installed by the owner, never by an agent)

```sh
python3 -m mission_fetcher serve --config FILE                # from its own systemd socket unit
python3 -m mission_fetcher selfcheck [--github] --config FILE # start-up checks; --github checks the App too
# (--github counts as that minute's one GitHub attempt: wait a minute before fetch-now)
python3 -m mission_fetcher fetch-now --config FILE            # one refresh, for installing
```

The only part with network access: its own package and account, the only one that can read the read-only GitHub App's key. It reads `api.github.com` only, checks on every refresh that the App is still read-only and limited to the configured repositories, and writes a snapshot that only the web app's account can read. Each item says when its passing checks stop being fresh (`checks_fresh_until`); after that the web app must treat them as not known. The web app will ask it to refresh over a local socket (phase A5b), at most once a minute, and never imports it. `fetcher.example.json` shows its config's shape.

CI (`.github/workflows/ci.yml`) runs the same two commands, as the **lint** and **test** checks, on every pull request.

## Layout

| Path | What |
| --- | --- |
| `mission_control/app.py` | The WSGI app: routes, read-only method handling, security headers; in service mode, the owner check, the stop POST and event logging |
| `mission_control/__main__.py` | The loopback-only development server, and the service commands (`serve`, `stopper`, `selfcheck`, `export-events`) |
| `mission_control/service.py` | The Unix-socket server: systemd socket activation, kernel-checked callers, the trusted Tailscale login, header limits |
| `mission_control/stopper.py` | The stop helper: one fixed request, one caller, an atomic and durable marker, no way to remove it |
| `mission_control/events.py` | The append-only events log (SQLite) and its JSON Lines export |
| `mission_control/auth/` | Passkey sign-in (A4b): one-time enrollment codes, challenges, sessions, local-only recovery; `passkeys.py` is the only file that uses python-fido2 |
| `mission_control/static/passkey.js` | The site's only script, on the sign-in and enrollment pages only |
| `requirements.txt` | The runtime requirements (python-fido2 and what it needs), every file pinned by hash |
| `mission_control/config.py`, `checks.py` | The server config's shape, and the start-up checks that fail closed |
| `config.example.json`, `stopper.example.json` | The configs' shape, with placeholder paths |
| `mission_control/views.py` | The screens: server-rendered HTML, every state and flag in words, everything escaped |
| `mission_control/demo.py`, `demo.json` | Demo 0: synthetic tasks and the placeholder command templates, validated on load |
| `mission_control/static/app.css` | The one stylesheet: one column on phones, light and dark |
| `mission_fetcher/` | The fetcher (A5a): `github.py`, the only module that talks to the network (api.github.com only); `snapshot.py`, GitHub's answers into the task model's input; `server.py`, the refresh socket; `checks.py`, its start-up checks |
| `fetcher.example.json` | The fetcher's config shape, with placeholder paths |
| `mission_control/tasks.py` | The task-state model (A2): pure functions deriving a task's state from GitHub-shaped data and Billy's run records |
| `tests/fixtures/tasks/` | Synthetic task examples with their expected states, for the model's tests |
| `tests/` | App, screens, service, server, credential scanner and repository-policy tests |
| `tools/check_secrets.py` | Fails on credential-shaped text in any file |
| `tools/audit_deps.py` | Fails if a pinned requirement has a known vulnerability (PyPI's advisory data) |
| `dev.py` | The `lint` and `test` commands |
| `.github/workflows/ci.yml` | CI: read-only permissions, no secrets, actions pinned to commits |
| `.github/CODEOWNERS` | Every path belongs to the owner |
| `docs/owner-settings.md` | The `main` ruleset and repository settings only the owner can set |
