"""Repository guards: CI stays read-only and secret-free, the app makes no outbound calls, and
CODEOWNERS covers everything. A change that weakens one of these fails the tests, so it has to
be argued for in a reviewed pull request rather than slipping in."""

from __future__ import annotations

import ast
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

# Modules the app package must not import: outbound network clients and process execution.
# (The development server's wsgiref is allowed; it only listens, on loopback.) Since A4a
# (owner decision 3), `socket` is allowed for Unix sockets only: the service listens on one and
# the web app asks the stop helper over another. Internet sockets stay forbidden (below).
FORBIDDEN_IMPORTS = {
    "urllib.request",
    "http.client",
    "ssl",
    "subprocess",
    "requests",
    "httpx",
    "aiohttp",
    "smtplib",
    "ftplib",
}


# Triggers that run on a timer, with write access, or from other workflows' events.
RISKY_TRIGGERS = ("schedule", "pull_request_target", "workflow_run", "repository_dispatch")


def imported_modules(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            # `from http import client` imports http.client (audit of e58b933).
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _is_from_name(name: str, path: Path) -> bool:
    """Whether `name` is `module.name` from a `from module import name` in the file."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if any(name == f"{node.module}.{a.name}" for a in node.names):
                return True
    return False


# Every module the fetcher may import, by top-level name; http and ssl only in its github.py.
FETCHER_ALLOWED_TOP = {
    "__future__",
    "argparse",
    "base64",
    "collections",
    "contextvars",
    "cryptography",
    "dataclasses",
    "datetime",
    "errno",
    "fcntl",
    "fnmatch",
    "grp",
    "json",
    "math",
    "mission_control",
    "os",
    "pathlib",
    "pwd",
    "re",
    "signal",  # SIGTERM unwinds a refresh (pre-review of e4a8096); no network
    "socket",
    "stat",
    "string",
    "sys",
    "threading",
    "time",
    "typing",
    "unicodedata",
}


# Every module the web app may import, by top-level name (audit of 8c62413: the deny-list above
# alone let other network clients and process starters in).
APP_ALLOWED_TOP = {
    "__future__",
    "argparse",
    "base64",
    "collections",
    "contextlib",
    "dataclasses",
    "datetime",
    "enum",
    "fido2",
    "fnmatch",
    "hashlib",
    "hmac",
    "html",
    "ipaddress",
    "itertools",
    "json",
    "os",
    "pathlib",
    "pwd",
    "queue",
    "re",
    "secrets",
    "socket",
    "socketserver",
    "sqlite3",
    "stat",
    "struct",
    "sys",
    "threading",
    "time",
    "typing",
    "urllib",
    "wsgiref",
}
# Packages the app may use one part of: urllib's parser, wsgiref's server, fido2's checks.
APP_ALLOWED_PARTS = {
    "urllib": {"parse"},
    "wsgiref": {"simple_server"},
    "fido2": {"server", "webauthn"},
}
# Ways to start a process or signal one through os, banned in both packages.
PROCESS_NAMES = re.compile(
    r"_?(system|popen|posix_spawnp?|fork(pty)?|exec[lv]p?e?|spawn[lv]p?e?f?|startfile|kill(pg)?)"
)

# Ways to reach a module, a builtin or an object's insides without naming it in the code,
# banned in both packages: builtins by name, and attributes anywhere.
DYNAMIC_NAMES = (
    "__import__",
    "eval",
    "exec",
    "compile",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "importlib",
    "builtins",
)
DYNAMIC_ATTRIBUTES = (
    "__import__",
    "__dict__",
    "__class__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__getattribute__",
    "__code__",
    "modules",
    "environb",
)

# Everything either package may use from the socket module: Unix sockets, and shutting one down.
# SO_ACCEPTCONN only reads whether systemd's socket is listening (Codex's review of a86575d).
SOCKET_NAMES = (
    "socket",
    "AF_UNIX",
    "SOCK_STREAM",
    "SOL_SOCKET",
    "SO_PEERCRED",
    "SO_ACCEPTCONN",
    "SHUT_RDWR",
)

CONNECTION_NAMES = ("HTTPSConnection", "HTTPConnection")
OUTBOUND_NAMES = ("create_connection", "get_server_certificate", "open_connection", "set_tunnel")
# A connection's destination, which nothing may set after the connection is made.
ATTACH_NAMES = ("host", "port", "_tunnel_host", "_tunnel_port", "_tunnel_headers")


class Workflows(unittest.TestCase):
    def test_there_is_a_workflow(self):
        self.assertTrue(WORKFLOWS)

    def test_read_only_and_secret_free(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n(?!  \S)", path.name)
            self.assertNotRegex(text, r":\s*write\b", path.name)
            self.assertNotIn("secrets.", text, path.name)
            self.assertNotIn("write-all", text, path.name)

    def test_no_schedule_or_risky_triggers(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            for trigger in RISKY_TRIGGERS:
                self.assertNotRegex(text, rf"(?m)^\s*{trigger}\s*:", (path.name, trigger))

    def test_actions_are_pinned_to_full_commits(self):
        for path in WORKFLOWS:
            for ref in re.findall(r"uses:\s*([^\s#]+)", path.read_text(encoding="utf-8")):
                self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", (path.name, ref))

    def test_checkout_keeps_no_token(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            checkouts = text.count("actions/checkout@")
            self.assertEqual(text.count("persist-credentials: false"), checkouts, path.name)

    def test_ci_runs_the_two_commands_as_lint_and_test_jobs(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: lint", text)
        self.assertIn("name: test", text)
        self.assertIn("python dev.py lint", text)
        self.assertIn("python dev.py test", text)
        self.assertIn("--require-hashes", text)

    def test_ci_installs_the_runtime_pins_and_audits_them(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("pip install --require-hashes -r requirements.txt", text)
        self.assertIn("python tools/audit_deps.py requirements.txt", text)
        self.assertLess(text.index("tools/audit_deps.py"), text.index("python dev.py test"))


class App(unittest.TestCase):
    def test_no_outbound_network_or_process_execution(self):
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            bad = {m for m in imported_modules(path) if m in FORBIDDEN_IMPORTS}
            self.assertEqual(bad, set(), path.name)

    def test_only_modules_on_the_apps_allow_list(self):
        # Audit of 8c62413: a deny-list let xmlrpc, imaplib, multiprocessing and asyncio in.
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            modules = imported_modules(path)
            tops = {m.split(".")[0] for m in modules}
            self.assertEqual(tops - APP_ALLOWED_TOP, set(), str(path))
            # Packages allowed for one part only.
            for module in modules:
                top = module.split(".")[0]
                if top in APP_ALLOWED_PARTS:
                    second = module.split(".")[1] if "." in module else None
                    self.assertIn(second, APP_ALLOWED_PARTS[top], (str(path), module))

    def test_no_process_is_started_through_os(self):
        paths = sorted((ROOT / "mission_control").rglob("*.py"))
        paths += sorted((ROOT / "mission_fetcher").rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # os is only ever used as os.<name>, never handed on (x = os; x.system).
            bases = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "os":
                    self.assertIn(id(node), bases, (path.name, node.lineno))
                names: list[str] = []
                # os.system(...), and `from os import system`.
                if isinstance(node, ast.Attribute) and ast.unparse(node.value) == "os":
                    names.append(node.attr)
                if isinstance(node, ast.ImportFrom) and node.module == "os":
                    names += [a.name for a in node.names]
                # Nor os reached through getattr, or os handed on under another name.
                if isinstance(node, ast.Call) and ast.unparse(node.func) == "getattr":
                    self.assertNotEqual(
                        [ast.unparse(a) for a in node.args[:1]], ["os"], (path.name, node.lineno)
                    )
                if isinstance(node, ast.alias) and node.name == "os":
                    self.assertIn(node.asname, (None, "os"), (path.name, node.lineno))
                for name in names:
                    self.assertIsNone(PROCESS_NAMES.fullmatch(name), (path.name, node.lineno))
        # The pattern itself (Codex's review of 0f323f6: it missed "kill").
        names = ("kill", "killpg", "fork", "_execvpe", "_spawnvef")
        self.assertTrue(all(PROCESS_NAMES.fullmatch(n) for n in names))

    def test_nothing_is_reached_around_the_rules(self):
        # Audit of 7712dec: __import__, sys.modules, a star import, __dict__, type(conn)(...),
        # re-setting HOST from another module, or a fake AF_UNIX each got past the rules above,
        # which read names and import statements.
        paths = sorted((ROOT / "mission_control").rglob("*.py"))
        paths += sorted((ROOT / "mission_fetcher").rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                where = (path.name, getattr(node, "lineno", None))
                if isinstance(node, ast.Name):
                    self.assertNotIn(node.id, DYNAMIC_NAMES + DYNAMIC_ATTRIBUTES, where)
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, DYNAMIC_ATTRIBUTES, where)
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn("*", [a.name for a in node.names], where)
                if isinstance(node, ast.alias):
                    self.assertNotIn(node.name, ("importlib", "builtins"), where)
                if isinstance(node, ast.Call):
                    # type(x) only reads a type; type(...)(...) or type(a, b, c) makes one.
                    if ast.unparse(node.func) == "type":
                        self.assertEqual((len(node.args), node.keywords), (1, []), where)
                    if isinstance(node.func, ast.Call):
                        self.assertNotEqual(ast.unparse(node.func.func), "type", where)
                    # Every socket is a Unix one, by socket.AF_UNIX itself, or handed over.
                    if ast.unparse(node.func) == "socket.socket" and node.args:
                        self.assertEqual(ast.unparse(node.args[0]), "socket.AF_UNIX", where)
                # No module's settings are changed from outside it (github.HOST = ...).
                targets: list[ast.AST] = []
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                if isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.Delete)):
                    targets = node.targets if isinstance(node, ast.Delete) else [node.target]
                for target in targets:
                    for part in ast.walk(target):
                        if isinstance(part, ast.Attribute):
                            self.assertFalse(part.attr.isupper(), where)
                # Nor rebound inside it, after it is set once at the top.
                if isinstance(node, (ast.Global, ast.Nonlocal)):
                    self.assertEqual(
                        [n for n in node.names if n.isupper()], [], (path.name, node.lineno)
                    )

    def test_only_these_socket_names_are_used(self):
        # Pre-review of e995f6a: socket.SocketType(2, 1), socket.fromfd(0, 2, 1) and
        # socket.create_server(("", 8080)) each made an internet socket past the rules above.
        paths = sorted((ROOT / "mission_control").rglob("*.py"))
        paths += sorted((ROOT / "mission_fetcher").rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            values = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            for node in ast.walk(tree):
                where = (path.name, getattr(node, "lineno", None))
                if isinstance(node, ast.Attribute) and ast.unparse(node.value) == "socket":
                    self.assertIn(node.attr, SOCKET_NAMES, where)
                if isinstance(node, ast.Attribute) and ast.unparse(node.value) == "socket.socket":
                    self.assertIn(node.attr, ("shutdown",), where)
                # The module only ever as socket.<name>: never handed on or renamed.
                if isinstance(node, ast.Name) and node.id == "socket":
                    self.assertIn(id(node), values, where)
                if isinstance(node, ast.alias) and node.name == "socket":
                    self.assertIn(node.asname, (None, "socket"), where)

    def test_the_app_never_imports_the_fetcher(self):
        # Phase A5a (issue #16): the fetcher is the only part with network access, in its own
        # package and process. The web app reads its snapshot file and never imports it.
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            uses = {m for m in imported_modules(path) if m.split(".")[0] == "mission_fetcher"}
            self.assertEqual(uses, set(), path.name)

    def test_sockets_are_unix_only(self):
        # No internet address families, name lookups or connection helpers anywhere in the app,
        # or in the fetcher's own code (its one HTTPS client is http.client, in github.py).
        banned = {
            "AF_INET",
            "AF_INET6",
            "create_connection",
            "getaddrinfo",
            "gethostbyname",
            # Other ways out, by name (audit of 80e8fb3).
            "get_server_certificate",
            "open_connection",
            "set_tunnel",
        }
        paths = list((ROOT / "mission_control").rglob("*.py"))
        paths += list((ROOT / "mission_fetcher").rglob("*.py"))
        for path in sorted(paths):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            self.assertEqual(names & banned, set(), path.name)
            for node in ast.walk(tree):
                # Every socket made: a Unix one, or one handed over by systemd (fileno=). A
                # bare socket.socket() is an internet socket (audit of e58b933).
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "socket"
                ):
                    first = node.args[0] if node.args else None
                    unix = isinstance(first, ast.Attribute) and first.attr == "AF_UNIX"
                    handed = any(k.arg == "fileno" for k in node.keywords) and not node.args
                    self.assertTrue(unix or handed, (path.name, node.lineno))

    def test_the_fetcher_uses_signal_only_to_stop_itself(self):
        # Never pthread_kill, pidfd_send_signal and the like (Fable's pre-review of 0d516b1).
        allowed = {"signal", "SIGTERM", "SIG_DFL", "raise_signal"}
        for path in sorted((ROOT / "mission_fetcher").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            receivers = set()
            for node in ast.walk(tree):
                where = (path.name, getattr(node, "lineno", None))
                self.assertFalse(
                    isinstance(node, ast.ImportFrom) and node.module == "signal", where
                )
                # Never under another name (Codex's review of b2e12a7).
                if isinstance(node, ast.alias) and node.name == "signal":
                    self.assertIsNone(node.asname, where)
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    if node.value.id == "signal":
                        self.assertIn(node.attr, allowed, where)
                        receivers.add(id(node.value))
            # Nor handed on: the name is only ever read as `signal.<allowed>`.
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "signal":
                    self.assertIn(id(node), receivers, (path.name, node.lineno))

    def test_only_the_fetchers_github_module_reaches_the_network(self):
        # Owner's decision for A5a (issues #15 and #16): one module may make outbound calls,
        # with http.client and ssl only, and nothing else in the fetcher may.
        network = {"http.client", "ssl"}
        for path in sorted((ROOT / "mission_fetcher").rglob("*.py")):
            modules = imported_modules(path)
            # By its exact path: another file named github.py is no exception (audit of
            # 80e8fb3).
            github = path == ROOT / "mission_fetcher" / "github.py"
            allowed = network if github else set()
            self.assertEqual((modules & FORBIDDEN_IMPORTS) - allowed, set(), path.name)
            # And only modules on the fetcher's allow-list, so asyncio, xmlrpc and the like
            # can't reach the network either.
            permitted = FETCHER_ALLOWED_TOP | ({"http", "ssl"} if github else set())
            tops = {m.split(".")[0] for m in modules}
            self.assertEqual(tops - permitted, set(), str(path))

    def test_no_connection_or_socket_comes_in_another_way(self):
        # Audit of 24973b8: a from-imported HTTPSConnection, a second subclass, or `from socket
        # import socket` got past the attribute-only checks.
        paths = sorted((ROOT / "mission_control").rglob("*.py"))
        paths += sorted((ROOT / "mission_fetcher").rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertNotIn(
                        node.module,
                        ("socket", "http", "http.client", "ssl"),
                        (path.name, node.lineno),
                    )
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(
                        node.func.id,
                        ("HTTPSConnection", "HTTPConnection", "socket"),
                        (path.name, node.lineno),
                    )
                if isinstance(node, ast.ClassDef):
                    bases = " ".join(ast.unparse(b) for b in node.bases)
                    if "HTTPSConnection" in bases or "HTTPConnection" in bases:
                        self.assertEqual((path.name, node.name), ("github.py", "_Connection"))
                    # Nor a subclass of _Connection (audit of b69faa7).
                    self.assertNotIn("_Connection", bases, (path.name, node.name))
            # The connection classes' names appear only as _Connection's base and in its one
            # TCP connect: never aliased or used anywhere else (audits of b69faa7 and 80e8fb3:
            # an alias such as `_Plain = http.client.HTTPSConnection` got past a rule that
            # matched the text, not the place).
            permitted: set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name == "_Connection":
                    permitted |= {id(n) for b in node.bases for n in ast.walk(b)}
                if (
                    isinstance(node, ast.Call)
                    and ast.unparse(node.func) == "http.client.HTTPConnection.connect"
                    and [ast.unparse(a) for a in node.args] == ["self"]
                ):
                    permitted |= {id(n) for n in ast.walk(node.func)}
            for node in ast.walk(tree):
                named = (isinstance(node, ast.Attribute) and node.attr in CONNECTION_NAMES) or (
                    isinstance(node, ast.Name) and node.id in CONNECTION_NAMES
                )
                if named:
                    self.assertIn(id(node), permitted, (path.name, node.lineno))
                # Nor reached by name as text (getattr(http.client, "HTTPSConnection")).
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn(
                        node.value, CONNECTION_NAMES + OUTBOUND_NAMES, (path.name, node.lineno)
                    )

    def test_the_connection_class_is_used_once_and_never_re_aimed(self):
        # Audit of 8c62413: another module could import _Connection (or tls_context) and aim
        # it at any host, and github.py could re-aim its one connection by setting .host.
        github = ROOT / "mission_fetcher" / "github.py"
        private = ("_Connection", "tls_context")
        paths = sorted((ROOT / "mission_control").rglob("*.py"))
        paths += sorted((ROOT / "mission_fetcher").rglob("*.py"))
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            uses = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in private:
                    uses.append(node)
                if isinstance(node, ast.Attribute) and node.attr in private:
                    uses.append(node)
                if isinstance(node, ast.alias) and {node.name, node.asname} & set(private):
                    uses.append(node)
                if isinstance(node, ast.Constant) and node.value in private + ATTACH_NAMES:
                    uses.append(node)
                # Nothing sets where a connection goes once it is made.
                targets: list[ast.AST] = []
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                    targets = [node.target]
                for target in targets:
                    for part in ast.walk(target):
                        if isinstance(part, ast.Attribute):
                            self.assertNotIn(part.attr, ATTACH_NAMES, (path.name, part.lineno))
                if isinstance(node, ast.Call) and ast.unparse(node.func) in ("setattr", "vars"):
                    self.fail((path.name, node.lineno, "setattr/vars"))
            if path != github:
                self.assertEqual(uses, [], path.name)
                continue
            # In github.py: exactly the one call _Connection(..., context=tls_context()).
            names = [n for n in uses if isinstance(n, ast.Name)]
            self.assertEqual(len(uses), len(names), "only plain names in github.py")
            made = [
                n
                for n in ast.walk(tree)
                if isinstance(n, ast.Call) and ast.unparse(n.func) == "_Connection"
            ]
            self.assertEqual(len(made), 1)
            context = [k.value for k in made[0].keywords if k.arg == "context"]
            self.assertEqual([ast.unparse(c) for c in context], ["tls_context()"])
            self.assertEqual(
                {id(n) for n in names}, {id(made[0].func), id(context[0].func)}, "github.py"
            )

    def test_the_fetcher_talks_to_api_github_com_only(self):
        tree = ast.parse((ROOT / "mission_fetcher" / "github.py").read_text(encoding="utf-8"))
        hosts = [
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "HOST" for t in node.targets)
        ]
        self.assertEqual(hosts, ["api.github.com"])
        ports = [
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "PORT" for t in node.targets)
        ]
        self.assertEqual(ports, [443])
        # No HTTP(S) connection is made directly: the one connection class is _Connection, an
        # HTTPSConnection, made once, to HOST and PORT.
        direct = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("HTTPSConnection", "HTTPConnection")
        ]
        self.assertEqual(direct, [])
        classes = [
            n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "_Connection"
        ]
        self.assertEqual(len(classes), 1)
        self.assertEqual(
            [ast.unparse(b) for b in classes[0].bases], ["http.client.HTTPSConnection"]
        )
        made = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_Connection"
        ]
        self.assertEqual(len(made), 1)
        self.assertEqual([ast.unparse(a) for a in made[0].args[2:4]], ["HOST", "PORT"])
        # No redirects or proxy settings: nothing reads the environment.
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        # TLS is set up by hand: create_default_context() honours SSLKEYLOGFILE and would write
        # session secrets (Codex's review of f772122).
        self.assertNotIn("create_default_context", names)
        # load_default_certs() honours SSL_CERT_FILE and SSL_CERT_DIR, which would swap the
        # trusted authorities (audit of e58b933).
        self.assertNotIn("load_default_certs", names)
        self.assertNotIn("environ", names)
        self.assertNotIn("getenv", names)

    def test_the_stop_helper_cannot_remove_a_marker(self):
        tree = ast.parse((ROOT / "mission_control" / "stopper.py").read_text(encoding="utf-8"))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        removers = {"unlink", "remove", "rmdir", "rename", "replace", "truncate", "ftruncate"}
        self.assertEqual(names & (removers | {"O_TRUNC", "shutil"}), set())

    def test_one_runtime_dependency_for_sign_in_only(self):
        # A4b (issue #10, owner decision 1): python-fido2, pinned with everything it needs by
        # hash in requirements.txt. Adding another needs the owner's approval in a PR.
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^dependencies = \["fido2==2\.2\.1"\]$')
        self.assertIn("fido2==2.2.1 \\", (ROOT / "requirements.txt").read_text(encoding="utf-8"))


# Generic shapes of a server's details: absolute system paths, privilege escalation, a Node
# version manager folder, Tailscale machine names. Deliberately generic: the guard itself must
# not name any account or path of the real server, because this repository is public.
MACHINE_DETAILS = re.compile(
    r"(?<![\w.])/(?:home|opt|srv|etc|var/lib)/[A-Za-z0-9_.-]"
    r"|\bsudo\s"
    r"|\.nvm[/\\]"
    r"|\.ts\.net\b"
)


def tracked_text_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [ROOT / name for name in out.split("\0") if name]


class Machine(unittest.TestCase):
    def test_no_details_of_the_server_are_committed(self):
        # Codex's reviews of bb74c3c and 09fd27d (blocking): the docs, then this guard's own
        # pattern, named the server's accounts and paths. No file is exempt, this one included.
        for path in tracked_text_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                self.assertIsNone(MACHINE_DETAILS.search(line), f"{path.name}:{number}")

    def test_the_pattern_catches_each_shape(self):
        # Samples are assembled at run time so this file contains none of the shapes.
        for sample in (
            "/" + "home/someone/x",
            "/" + "opt/tool/x",
            "/" + "var/lib/thing",
            "/" + "etc/hosts",
            "/" + "srv/www",
            "su" + "do -u x id",
            "~/." + "nvm/versions",
            "box.tail0." + "ts" + ".net",
        ):
            self.assertIsNotNone(MACHINE_DETAILS.search(sample), sample)

    def test_ordinary_text_passes(self):
        for sample in (
            "docs/owner-settings.md",
            "https://github.com/DrZaff/x",
            "a/home/b",
            "pseudo code",
            "--repo billy-mission-control",
            "127.0.0.1:8765",
        ):
            self.assertIsNone(MACHINE_DETAILS.search(sample), sample)


# The task-state model (phase A2) is pure: only these modules, and no I/O, clock or code
# execution, so the same input always gives the same answer with no side effects.
TASKS_ALLOWED_IMPORTS = {
    "__future__",
    "re",
    "collections.abc",
    "dataclasses",
    "datetime",
    "enum",
    "fnmatch",
    "typing",
}
TASKS_FORBIDDEN_CALLS = {"open", "print", "input", "eval", "exec", "compile", "__import__"}
TASKS_FORBIDDEN_ATTRIBUTES = {"now", "today", "utcnow", "time", "sleep", "environ", "getenv"}


class PureTaskModel(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "mission_control" / "tasks.py"
        self.tree = ast.parse(self.path.read_text(encoding="utf-8"))

    def test_imports_only_pure_standard_modules(self):
        # Modules only (the scan also records `from x import y` as x.y, for the network rule).
        modules = {m for m in imported_modules(self.path) if not _is_from_name(m, self.path)}
        self.assertLessEqual(modules, TASKS_ALLOWED_IMPORTS)

    def test_no_io_clock_or_code_execution(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, TASKS_FORBIDDEN_CALLS, node.lineno)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, TASKS_FORBIDDEN_ATTRIBUTES, node.lineno)

    def test_no_module_level_mutable_state(self):
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                self.assertNotIsInstance(node.value, (ast.List, ast.Dict, ast.Set), node.lineno)


class Ownership(unittest.TestCase):
    def test_codeowners_covers_every_path(self):
        lines = [
            line.split()
            for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn(["*", "@DrZaff"], lines)
        # No later line may hand any path to someone else (the last match wins in CODEOWNERS).
        for parts in lines:
            self.assertEqual(parts[1:], ["@DrZaff"], parts)


if __name__ == "__main__":
    unittest.main()
