"""Demo 0 data for the A3 screens: synthetic tasks, read from `demo.json` in this package.

Every name, number and SHA in the file is made up. States are never stored: each task's state
comes from the A2 model (`tasks.derive`), so the screens show exactly what the model decides.

The file also holds the command templates for the command helper. They are placeholders: the
real review and publish commands name the server's accounts and paths, which this public
repository never holds, so from phase A4 the templates come from the server's own settings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import tasks
from .tasks import State, TaskStatus

DEMO_FILE = Path(__file__).with_name("demo.json")

TASK_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
# A branch name safe to show inside a command: no spaces, quotes, shell or template characters.
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
RISKS = ("low", "medium", "high")
COMMAND_KINDS = ("review", "publish")
PLACEHOLDERS = ("{repo}", "{repo_name}", "{branch}", "{sha}")


class DemoError(ValueError):
    """The demo file is malformed. (A single task's bad data is not an error: it is UNKNOWN.)"""


@dataclass(frozen=True)
class Entry:
    id: str
    title: str
    risk: str
    status: TaskStatus
    # From the validated task, or None when the task's data is invalid (state UNKNOWN).
    repo: str | None
    issue: int | None
    branch: str | None
    events: tuple[tuple[datetime, str], ...]


@dataclass(frozen=True)
class Command:
    kind: str  # "review" or "publish"
    sha: str
    text: str


@dataclass(frozen=True)
class Demo:
    refreshed_at: datetime
    stop_switch_on: bool
    stop_switch_changed_at: datetime
    templates: tuple[tuple[str, str], ...]
    entries: tuple[Entry, ...]

    def entry(self, task_id: str) -> Entry | None:
        return next((e for e in self.entries if e.id == task_id), None)

    def command(self, entry: Entry) -> Command | None:
        """The next command for the owner to run, for copying only: review a built commit, or
        publish a reviewed one. None for any other state, or if a value is unsafe to show."""
        status = entry.status
        kind = {State.BUILT: "review", State.REVIEWED: "publish"}.get(status.state)
        sha = status.head_sha
        if kind is None or sha is None or entry.repo is None or entry.branch is None:
            return None
        if not BRANCH.fullmatch(entry.branch) or ".." in entry.branch:
            return None
        values = {
            "{repo}": entry.repo,
            "{repo_name}": entry.repo.split("/", 1)[1],
            "{branch}": entry.branch,
            "{sha}": sha,
        }
        text = dict(self.templates)[kind]
        for placeholder, value in values.items():
            text = text.replace(placeholder, value)
        return Command(kind, sha, text)


def _req(condition: bool, message: str) -> None:
    if not condition:
        raise DemoError(message)


def _time(value: Any, name: str) -> datetime:
    _req(isinstance(value, str), f"{name} must be an ISO 8601 time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise DemoError(f"{name} must be an ISO 8601 time") from None
    _req(parsed.tzinfo is not None, f"{name} must include a time zone")
    return parsed


def _events(parsed: Any) -> tuple[tuple[datetime, str], ...]:
    """Everything recorded about a validated task, oldest first, in words."""
    items: list[tuple[datetime, int, str]] = []
    for e in parsed.timeline:
        what = f"{e.kind} {e.label}" if e.label else e.kind
        items.append((e.at, len(items), f"{what} by {e.actor}"))
    for r in parsed.runs or ():  # None: not read (A5a)
        parts = [f"{r.step}"]
        if r.step in ("build", "review"):
            parts.append(r.status)
        if r.sha:
            parts.append(f"at {r.sha[:12]}")
        if r.verdict:
            parts.append(f"({r.verdict.replace('_', ' ')})")
        if r.pr is not None:
            parts.append(f"as PR #{r.pr}")
        where = r.repo if r.repo != parsed.repo else r.branch
        if where:
            parts.append(f"[{where}]")
        items.append((r.at, len(items), " ".join(parts)))
    if parsed.pr is not None:
        for rv in parsed.pr.reviews or ():  # None: not known (A5a); the flag says so
            who = f"{rv.user} (bot)" if rv.is_bot else rv.user
            text = f"GitHub review {rv.state.lower()} by {who} at {rv.commit[:12]}"
            items.append((rv.at, len(items), text))
    items.sort(key=lambda item: (item[0], item[1]))
    return tuple((at, text) for at, _, text in items)


def _entry(raw: Any, i: int, stop_switch_on: bool) -> Entry:
    _req(isinstance(raw, dict), f"tasks[{i}] must be an object")
    task_id = raw.get("id")
    _req(isinstance(task_id, str) and bool(TASK_ID.fullmatch(task_id)), f"tasks[{i}].id")
    title = raw.get("title")
    _req(isinstance(title, str) and 0 < len(title) <= 200, f"tasks[{i}].title")
    risk = raw.get("risk")
    _req(isinstance(risk, str) and risk in RISKS, f"tasks[{i}].risk")
    _req("task" in raw, f"tasks[{i}].task is required")
    task = raw["task"]
    # The global stop switch pauses every task. A task can also be paused on its own.
    if stop_switch_on and isinstance(task, dict):
        task = {**task, "paused": True}
    status = tasks.derive(task)
    repo = issue = branch = None
    events: tuple[tuple[datetime, str], ...] = ()
    try:
        parsed = tasks.parse(task)
    except (tasks.InvalidInput, TypeError, ValueError, KeyError, AttributeError, OverflowError):
        parsed = None
    if parsed is not None:
        repo, branch = parsed.repo, parsed.branch
        issue = None if task["issue"] is None else task["issue"]["number"]  # null: not linked
        events = _events(parsed)
    return Entry(task_id, title, risk, status, repo, issue, branch, events)


def load(text: str) -> Demo:
    """Validate the demo file's text. Raises DemoError if the file itself is malformed."""
    try:
        data = json.loads(text)
    except ValueError:
        raise DemoError("demo data is not valid JSON") from None
    _req(isinstance(data, dict), "demo data must be an object")
    switch = data.get("stop_switch")
    _req(isinstance(switch, dict) and isinstance(switch.get("on"), bool), "stop_switch.on")
    templates = data.get("commands")
    _req(isinstance(templates, dict), "commands must be an object")
    pairs = []
    for kind in COMMAND_KINDS:
        template = templates.get(kind)
        _req(
            isinstance(template, str) and 0 < len(template) <= 300 and "\n" not in template,
            f"commands.{kind} must be one line",
        )
        _req("{sha}" in template, f"commands.{kind} must contain {{sha}}")
        pairs.append((kind, template))
    raw_tasks = data.get("tasks")
    _req(isinstance(raw_tasks, list), "tasks must be a list")
    entries = tuple(_entry(raw, i, switch["on"]) for i, raw in enumerate(raw_tasks))
    ids = [e.id for e in entries]
    _req(len(ids) == len(set(ids)), "task ids must be unique")
    return Demo(
        refreshed_at=_time(data.get("refreshed_at"), "refreshed_at"),
        stop_switch_on=switch["on"],
        stop_switch_changed_at=_time(switch.get("changed_at"), "stop_switch.changed_at"),
        templates=tuple(pairs),
        entries=entries,
    )


def load_file(path: Path = DEMO_FILE) -> Demo:
    return load(path.read_text(encoding="utf-8"))


def utc(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
