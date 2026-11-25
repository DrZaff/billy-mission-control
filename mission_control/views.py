"""Server-rendered HTML for the A3 screens: Home, Tasks, Task detail, Usage and Settings.

Every value from the data is HTML-escaped where it is written into the page. States and flags
are shown in words (never colour alone), and anything the A2 model says needs attention is
marked as such in text. Links go only to GitHub pages built from validated values.
"""

from __future__ import annotations

from html import escape

from . import PHASE
from .demo import Demo, Entry, utc
from .tasks import ATTENTION_FLAGS, Flag, State, TaskStatus

STATE_WORDS = {
    State.PROPOSED: "Proposed: not authorised",
    State.READY: "Ready: authorised, no work yet",
    State.BUILDING: "Building",
    State.BUILT: "Built: waiting for review",
    State.REVIEWING: "Review under way",
    State.CHANGES_NEEDED: "Changes needed",
    State.REVIEWED: "Reviewed: not published yet",
    State.PUBLISHED: "Published: checks not all passed",
    State.CLINICAL_REVIEW: "Waiting for a clinician's approval",
    State.AWAITING_OWNER: "Waiting for you",
    State.MERGED: "Merged",
    State.BLOCKED: "Blocked: a question for you",
    State.FAILED: "Failed",
    State.PAUSED: "Paused by the stop switch",
    State.CLOSED: "Closed without merging",
    State.UNSAFE: "UNSAFE: do not approve",
    State.UNKNOWN: "Unknown: the data can't be trusted",
    State.NOT_LINKED: "Not linked to an authorised issue",
}

FLAG_WORDS = {
    Flag.INVALID_INPUT: "The task's data is invalid",
    Flag.CONFLICTING_RECORDS: "Two reviews of the same commit disagree",
    Flag.LABEL_WITHOUT_OWNER: "agent:ready was added by someone other than you",
    Flag.UNAUTHORIZED_WORK: "Work exists that you never authorised",
    Flag.WRONG_REPO_RECORD: "A record for another repository was ignored",
    Flag.WRONG_BRANCH_RECORD: "A record for another branch was ignored",
    Flag.RECORD_BEFORE_AUTHORIZATION: "A record from before your authorisation was ignored",
    Flag.STALE_REVIEW: "The review is for an older commit",
    Flag.REVIEW_MISSING: "The current commit has no review",
    Flag.PR_BEFORE_REVIEW: "A pull request is open before any passing review",
    Flag.HEAD_MISMATCH: "The PR head is not the reviewed commit",
    Flag.FIX_ROUNDS_EXHAUSTED: "The fix rounds are used up",
    Flag.CHECKS_PASSED: "Required checks passed",
    Flag.CHECKS_PENDING: "Required checks still running",
    Flag.CHECKS_MISSING: "A required check has no result",
    Flag.CHECKS_STALE: "Check results are for another commit",
    Flag.CHECKS_FAILING: "A required check failed",
    Flag.CLINICAL: "Clinical files",
    Flag.CLINICAL_APPROVAL_MISSING: "No clinician has approved this commit",
    Flag.UNAUTHORIZED_MERGE: "Merged by someone other than you",
    Flag.MERGED_UNREVIEWED: "The merged commit never passed review",
    Flag.MERGED_WITHOUT_CLINICIAN: "Clinical files merged without a clinician's approval",
    Flag.MERGED_WITH_CHECKS_NOT_PASSED: "Merged before the required checks passed",
    Flag.RUNS_UNVERIFIED: "Billy's run records not read here (its review isn't shown)",
    Flag.CHECKS_UNVERIFIED: "Required checks not verified here (GitHub's merge box shows them)",
    Flag.FILES_UNVERIFIED: "Changed files not verified here (they may include clinical files)",
    Flag.REVIEWS_UNVERIFIED: "Reviews not verified here (no clinician's approval is assumed)",
    Flag.ISSUE_NOT_LINKED: "No readable, authorised issue is linked to this pull request",
    Flag.ISSUE_CLOSED_PR_OPEN: "The linked issue is closed, but this pull request is open",
    Flag.MERGER_UNKNOWN: "Merged by an account that can't be identified",
}

SECTIONS = (
    ("waiting", "Waiting for you"),
    ("active", "Running / queued"),
    ("alerts", "Alerts"),
    ("done", "Done"),
)

NAV = (("/", "Home"), ("/tasks", "Tasks"), ("/usage", "Usage"), ("/settings", "Settings"))

GITHUB = "https://github.com"

# States the model reaches only after confirming the owner's current authorisation. (PAUSED and
# CLOSED can also come before that check, and UNSAFE and UNKNOWN can mean anything.)
AUTHORISED_STATES = frozenset(
    {
        State.READY,
        State.BUILDING,
        State.BUILT,
        State.REVIEWING,
        State.CHANGES_NEEDED,
        State.REVIEWED,
        State.PUBLISHED,
        State.CLINICAL_REVIEW,
        State.AWAITING_OWNER,
        State.MERGED,
        State.BLOCKED,
        State.FAILED,
    }
)


def section(status: TaskStatus) -> str:
    """Where a task belongs on Home. UNSAFE, UNKNOWN and FAILED tasks, and any attention flag,
    are always alerts; every other task that needs the owner is under "Waiting for you"."""
    if status.state in (State.UNSAFE, State.UNKNOWN, State.FAILED) or (
        status.flags & ATTENTION_FLAGS
    ):
        return "alerts"
    if status.needs_attention or Flag.STALE_REVIEW in status.flags:
        return "waiting"
    if status.state in (State.MERGED, State.CLOSED):
        return "done"
    return "active"


def clinician_approved(status: TaskStatus) -> bool:
    """Whether the model established a clinician's approval of the head. It checks approval only
    on a safe merge, or as the last gate before the owner's decision, after review and checks
    pass. AWAITING_OWNER from exhausted fix rounds is decided earlier, so it proves nothing."""
    if Flag.CLINICAL not in status.flags or Flag.MERGED_WITHOUT_CLINICIAN in status.flags:
        return False
    if status.state is State.MERGED:
        return True
    return (
        status.state is State.AWAITING_OWNER
        and Flag.FIX_ROUNDS_EXHAUSTED not in status.flags
        and Flag.CHECKS_PASSED in status.flags
        and status.reviewed_sha is not None
        and status.reviewed_sha == status.head_sha
    )


def needs_you(status: TaskStatus) -> bool:
    return section(status) in ("alerts", "waiting")


def _where(entry: Entry) -> str:
    """The task's repository and issue; a PR with no linked issue (A5a) shows its PR number."""
    if entry.repo is None:
        return "Unreadable task data"
    if entry.issue is not None:
        return f"{entry.repo} #{entry.issue}"
    if entry.status.pr is not None:
        return f"{entry.repo} PR #{entry.status.pr} (no linked issue)"
    return entry.repo


def github_link(entry: Entry) -> tuple[str, str] | None:
    """(url, label) for the task's PR, else its issue. Built only from validated values."""
    if entry.repo is None:
        return None
    if entry.status.pr is not None:
        return f"{GITHUB}/{entry.repo}/pull/{entry.status.pr}", f"Open PR #{entry.status.pr}"
    if entry.issue is not None:
        return f"{GITHUB}/{entry.repo}/issues/{entry.issue}", f"Open issue #{entry.issue}"
    return None


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _link(url: str, label: str) -> str:
    return f'<a class="button" href="{_e(url)}" rel="noreferrer">{_e(label)}</a>'


def _short(sha: str | None) -> str:
    return sha[:12] if sha else "none"


def page(title: str, current: str, demo: Demo | None, body: str) -> str:
    nav = "".join(
        f'<a href="{href}"{' aria-current="page"' if href == current else ""}>{label}</a>'
        for href, label in NAV
    )
    banner = (
        f'<p class="banner">Demo data (synthetic) · as of {_e(utc(demo.refreshed_at))} · '
        f"Phase {_e(PHASE)}, read-only except the stop switch</p>"
        if demo
        else f'<p class="banner">Phase {_e(PHASE)}, read-only except the stop switch</p>'
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f"<title>{_e(title)} · Billy Mission Control</title>\n"
        '<link rel="stylesheet" href="/static/app.css">\n'
        "</head>\n<body>\n"
        '<header><p class="brand"><a href="/">[+] Billy Mission Control</a></p>'
        f'<nav aria-label="Main">{nav}</nav></header>\n'
        f"<main>\n{banner}\n{body}\n</main>\n</body>\n</html>\n"
    )


def _state_line(status: TaskStatus) -> str:
    marker = '<strong class="attention">Needs you: </strong>' if needs_you(status) else ""
    words = _e(STATE_WORDS[status.state])
    return f'<p class="state state-{_e(status.state.value)}">{marker}{words}</p>'


def _card(entry: Entry, with_github: bool) -> str:
    st = entry.status
    where = _where(entry)
    reason = st.reasons[0] if st.reasons else ""
    alerts = [FLAG_WORDS[f] for f in sorted(st.flags & ATTENTION_FLAGS)]
    extra = "".join(f"<li>{_e(a)}</li>" for a in alerts)
    gh = github_link(entry) if with_github else None
    return (
        '<li class="card">'
        f'<p class="title"><a href="/tasks/{_e(entry.id)}">{_e(entry.title)}</a></p>'
        f'<p class="meta">{_e(where)} · risk: {_e(entry.risk)}</p>'
        f"{_state_line(st)}"
        f'<p class="reason">{_e(reason)}</p>'
        + (f'<ul class="flags">{extra}</ul>' if extra else "")
        + (_link(*gh) if gh else "")
        + "</li>"
    )


def _section(anchor: str, heading: str, cards: str, count: int) -> str:
    return (
        f'<section aria-labelledby="{anchor}"><h2 id="{anchor}">{_e(heading)} '
        f'<span class="count">({count})</span></h2><ul class="cards">{cards}</ul></section>'
    )


def _group(demo: Demo) -> dict[str, list[Entry]]:
    groups: dict[str, list[Entry]] = {key: [] for key, _ in SECTIONS}
    for entry in demo.entries:
        groups[section(entry.status)].append(entry)
    return groups


def _stop_line(demo: Demo) -> str:
    if demo.stop_switch_on:
        state = "ON: no new runs start"
    else:
        state = "off: runs may start"
    return (
        f'<p class="stop">Stop switch: <strong>{_e(state)}</strong> '
        f"(since {_e(utc(demo.stop_switch_changed_at))})</p>"
    )


def home(demo: Demo) -> str:
    groups = _group(demo)
    summary = " ".join(
        f'<a href="#h-{key}">{_e(heading)}: {len(groups[key])}</a>' for key, heading in SECTIONS[:3]
    )
    parts = [f'<nav class="summary" aria-label="Sections">{summary}</nav>']
    for key, heading in SECTIONS[:3]:
        items = groups[key]
        cards = "".join(_card(e, key != "active") for e in items) or (
            '<li class="empty">Nothing here.</li>'
        )
        parts.append(_section(f"h-{key}", heading, cards, len(items)))
    done = len(groups["done"])
    parts.append(f'<p><a href="/tasks#done">{done} merged or closed: see Tasks</a></p>')
    # Not the demo's stop state: on the server it read like Billy's real state (A4c). The
    # stop switch lives on Settings.
    parts.append('<p class="stop"><a href="/settings#h-stop">Stop switch: on Settings</a></p>')
    return page("Home", "/", demo, "<h1>Home</h1>" + "".join(parts))


def task_list(demo: Demo) -> str:
    groups = _group(demo)
    parts = []
    for key, heading in SECTIONS:
        items = groups[key]
        cards = "".join(_card(e, True) for e in items) or '<li class="empty">Nothing here.</li>'
        parts.append(_section(key, heading, cards, len(items)))
    return page("Tasks", "/tasks", demo, "<h1>Tasks</h1>" + "".join(parts))


def _path(entry: Entry) -> str:
    """The task's way from authorisation to merge, one line per step, in words."""
    st, flags = entry.status, entry.status.flags
    rows: list[tuple[str, str, str]] = []  # (marker, step, detail)

    # Each row claims only what the model established. A "done" mark needs a state the model
    # reaches only after that gate passed; anything else says "not shown" rather than guess.
    if Flag.UNAUTHORIZED_WORK in flags:
        authorised = ("!", "no")
    elif st.state is State.PROPOSED:
        authorised = ("-", "not yet")
    elif st.state in AUTHORISED_STATES:
        authorised = ("done", "yes, by the owner")
    else:
        authorised = ("?", "not shown in this state")
    rows.append((authorised[0], "Authorised", authorised[1]))
    rows.append(
        (
            "done" if st.head_sha else "-",
            "Commit",
            _short(st.head_sha) if st.head_sha else "none yet",
        )
    )

    if st.reviewed_sha:
        review = ("done", f"passed for {_short(st.reviewed_sha)}")
    elif Flag.RUNS_UNVERIFIED in flags:
        review = ("?", "not shown: Billy's run records aren't read here")
    elif Flag.FIX_ROUNDS_EXHAUSTED in flags:
        review = ("!", "fix rounds used up; your decision")
    elif st.state is State.CHANGES_NEEDED:
        review = ("!", "blocking problems found")
    elif Flag.MERGED_UNREVIEWED in flags:
        review = ("!", "the merged commit never passed review")
    elif Flag.STALE_REVIEW in flags:
        review = ("!", "only for an older commit")
    elif st.state is State.REVIEWING:
        review = ("...", "under way")
    else:
        review = ("-", "not yet")
    rows.append((review[0], "Review", review[1]))

    if Flag.HEAD_MISMATCH in flags:
        rows.append(("!", "Pull request", f"#{st.pr}: head is NOT the reviewed commit"))
    elif st.pr is not None:
        rows.append(("done", "Pull request", f"#{st.pr}, head {_short(st.head_sha)}"))
    else:
        rows.append(("-", "Pull request", "none yet"))

    for flag, marker in (
        (Flag.CHECKS_FAILING, "!"),
        (Flag.CHECKS_STALE, "!"),
        (Flag.CHECKS_MISSING, "!"),
        (Flag.CHECKS_PENDING, "..."),
        (Flag.CHECKS_PASSED, "done"),
    ):
        if flag in flags:
            rows.append((marker, "Checks", FLAG_WORDS[flag].lower()))
            break
    else:
        rows.append(("-", "Checks", "not yet"))

    if Flag.CLINICAL in flags:
        if Flag.CLINICAL_APPROVAL_MISSING in flags or Flag.MERGED_WITHOUT_CLINICIAN in flags:
            rows.append(("!", "Clinician", "approval of this commit needed"))
        elif clinician_approved(st):
            rows.append(("done", "Clinician", "approved this commit"))
        else:
            rows.append(("-", "Clinician", "approval of the final commit needed, later"))

    if st.state is State.MERGED:
        rows.append(("done", "Owner", "merged"))
    elif st.state is State.UNSAFE and st.flags & {
        Flag.UNAUTHORIZED_MERGE,
        Flag.MERGED_UNREVIEWED,
        Flag.MERGED_WITHOUT_CLINICIAN,
    }:
        rows.append(("!", "Owner", "merged unsafely; see the reasons"))
    elif st.state is State.AWAITING_OWNER:
        rows.append(("...", "Owner", "your decision"))
    else:
        rows.append(("-", "Owner", "approve and merge, later"))

    items = "".join(
        f'<li><span class="mark">[{_e(m)}]</span> <span class="step">{_e(s)}</span> '
        f"<span>{_e(d)}</span></li>"
        for m, s, d in rows
    )
    return f'<ol class="path">{items}</ol>'


def task_detail(demo: Demo, entry: Entry) -> str:
    st = entry.status
    where = _where(entry)
    # A partial or unknown file list never shows "no" (Codex's review of 9537b08).
    if Flag.CLINICAL in st.flags:
        clinical = "yes"
    elif Flag.FILES_UNVERIFIED in st.flags:
        clinical = "not known"
    else:
        clinical = "no"
    reasons = "".join(f"<li>{_e(r)}</li>" for r in st.reasons)
    flags = "".join(
        f"<li>{'<strong>Attention:</strong> ' if f in ATTENTION_FLAGS else ''}{_e(FLAG_WORDS[f])}"
        f" <code>{_e(f.value)}</code></li>"
        for f in sorted(st.flags)
    )
    parts = [
        '<p><a href="/tasks">&lt; Tasks</a></p>',
        f"<h1>{_e(entry.title)}</h1>",
        f'<p class="meta">{_e(where)} · risk: {_e(entry.risk)} · clinical: {clinical}</p>',
        _state_line(st),
        f'<section aria-labelledby="h-why"><h2 id="h-why">Why</h2><ul>{reasons}</ul></section>',
    ]
    if flags:
        parts.append(
            f'<section aria-labelledby="h-flags"><h2 id="h-flags">Flags</h2>'
            f'<ul class="flags">{flags}</ul></section>'
        )
    shas = (
        f'<p>Current commit: <code class="sha">{_e(st.head_sha or "none")}</code></p>'
        f'<p>Reviewed commit: <code class="sha">{_e(st.reviewed_sha or "none")}</code></p>'
    )
    parts.append(
        f'<section aria-labelledby="h-path"><h2 id="h-path">Path</h2>{_path(entry)}{shas}</section>'
    )

    command = demo.command(entry)
    if command:
        what = "review" if command.kind == "review" else "publish the reviewed commit"
        parts.append(
            '<section aria-labelledby="h-next"><h2 id="h-next">Next: '
            f"{_e(what)}</h2>"
            f'<p>For commit <code class="sha">{_e(command.sha)}</code>:</p>'
            f'<pre class="command" aria-label="Command to copy">{_e(command.text)}</pre>'
            '<p class="note">Tap the command to select all of it, then copy. '
            "Mission Control runs nothing.</p></section>"
        )

    gh = github_link(entry)
    if gh:
        parts.append(f"<p>{_link(*gh)}</p>")

    events = "".join(f"<li><time>{_e(utc(at))}</time> {_e(text)}</li>" for at, text in entry.events)
    parts.append(
        f'<details class="events"><summary>Events ({len(entry.events)})</summary>'
        f"<ol>{events or '<li>No readable events.</li>'}</ol></details>"
    )
    return page(entry.title, "/tasks", demo, "".join(parts))


def usage(demo: Demo) -> str:
    body = (
        "<h1>Usage</h1>"
        "<p>Spending against each provider's cap will show here once Mission Control reads real "
        "usage. Nothing is tracked in this demo.</p>"
    )
    return page("Usage", "/usage", demo, body)


STOP_SCOPE = (
    "Stops new Billy review and publish steps. Work already running, cloud agents and GitHub "
    "Actions are not affected."
)
STOP_BACKUP = (
    "If this button fails, stop Billy from the server instead, as described in the main "
    'repository\'s docs/agents/billy.md, "The stop marker".'
)


def _stop_form(token: str) -> str:
    return (
        '<section aria-labelledby="h-stop"><h2 id="h-stop">Stop switch</h2>'
        f"<p><strong>{_e(STOP_SCOPE)}</strong></p>"
        '<form method="post" action="/stop">'
        f'<input type="hidden" name="token" value="{_e(token)}">'
        '<button type="submit" class="stop-button">Stop new runs</button>'
        "</form>"
        "<p>This can only turn the stop on. Only the owner clears it, on the server.</p>"
        f'<p class="note">{_e(STOP_BACKUP)}</p>'
        "<p class=\"note\">The marker's current state isn't shown yet: this page still runs on "
        "demo data.</p></section>"
    )


def settings(demo: Demo, stop_token: str | None = None, signed_in: bool = False) -> str:
    if stop_token is None:
        stop = (
            '<section aria-labelledby="h-stop"><h2 id="h-stop">Stop switch</h2>'
            f"{_stop_line(demo)}"
            "<p>Read-only here. Turning it on from this page arrives with phase A4, with its own "
            "tests and review.</p></section>"
        )
        account = "<p>Sign-in and sign-out arrive with phase A4.</p>"
    else:
        stop = _stop_form(stop_token)
        account = (
            "<p>Signed in as the owner: Tailscale and a passkey. Sessions end after 30 minutes "
            "idle, or 12 hours at most.</p>"
            '<form method="post" action="/signout">'
            f'<input type="hidden" name="token" value="{_e(stop_token)}">'
            '<button type="submit" class="plain-button">Sign out</button></form>'
            '<p class="note">Passkeys are added, listed and removed only from a shell on the '
            "server.</p>"
            if signed_in
            else "<p>Signed in through Tailscale as the owner.</p>"
        )
    body = (
        "<h1>Settings</h1>"
        f"{stop}"
        '<section aria-labelledby="h-sched"><h2 id="h-sched">Schedules</h2>'
        "<p>None. Nothing runs on a timer.</p></section>"
        f'<section aria-labelledby="h-account"><h2 id="h-account">Account</h2>{account}</section>'
    )
    return page("Settings", "/settings", demo, body)


def _signin_shell(title: str, mode: str, body: str) -> str:
    """A sign-in page: the app's own script, no navigation (nothing else is reachable yet)."""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f"<title>{_e(title)} · Billy Mission Control</title>\n"
        '<link rel="stylesheet" href="/static/app.css">\n'
        '<script src="/static/passkey.js" defer></script>\n'
        f'</head>\n<body data-mode="{_e(mode)}">\n'
        '<header><p class="brand">[+] Billy Mission Control</p></header>\n'
        f"<main>\n{body}\n"
        '<p id="status" class="status" role="status" aria-live="polite"></p>\n'
        "<noscript><p>Sign-in needs JavaScript for the passkey. Nothing else on this site "
        "uses it.</p></noscript>\n"
        "</main>\n</body>\n</html>\n"
    )


def signin_page() -> str:
    return _signin_shell(
        "Sign in",
        "signin",
        "<h1>Sign in</h1>"
        "<p>Use your passkey: Face ID on this iPhone, or your security key.</p>"
        '<button type="button" id="signin" class="plain-button">Sign in with a passkey</button>'
        '<p class="note">No passkey yet? Make a one-time code on the server, then '
        '<a href="/enroll">add a passkey</a>.</p>',
    )


def enroll_page() -> str:
    return _signin_shell(
        "Add a passkey",
        "enroll",
        "<h1>Add a passkey</h1>"
        "<p>Enter the one-time code from <code>passkey enroll</code> on the server. It works "
        "once, for 10 minutes. At most two passkeys: this iPhone and a backup security key.</p>"
        # POST, never GET: without the script, the code must not land in the address bar,
        # history or a referrer. The server refuses that POST (only the script's JSON call is
        # accepted), and it never logs a request body.
        '<form id="enroll" method="post" action="/enroll">'
        '<label for="code">One-time code</label>'
        '<input id="code" name="code" autocomplete="one-time-code" autocapitalize="characters" '
        'spellcheck="false" maxlength="11" required>'
        '<button type="submit" class="plain-button">Add passkey</button></form>'
        '<p><a href="/signin">Back to sign in</a></p>',
    )


def stop_result(stopped: bool) -> str:
    if stopped:
        body = (
            "<h1>Billy is stopped</h1>"
            f"<p><strong>{_e(STOP_SCOPE)}</strong></p>"
            "<p>The stop helper set the stop marker and confirmed it is on disk. Only the owner "
            "clears it, on the server.</p>"
        )
    else:
        body = (
            '<h1 class="attention">The stop could NOT be confirmed</h1>'
            "<p><strong>Billy may still be running.</strong> Stop it from the server now, as "
            'described in the main repository\'s docs/agents/billy.md, "The stop marker".</p>'
        )
    return page("Stop", "/settings", None, body + '<p><a href="/settings">Settings</a></p>')


def stop_refused() -> str:
    body = (
        '<h1 class="attention">Stop refused</h1>'
        "<p>The request didn't come from this app's own Settings page, or the page was out of "
        "date (the app restarted). Nothing was changed.</p>"
        f'<p>Reload <a href="/settings">Settings</a> and press the button again. {_e(STOP_BACKUP)}'
        "</p>"
    )
    return page("Stop refused", "/settings", None, body)


LOGGING_WARNING = (
    '<p class="banner attention" role="alert">Logging degraded: this request could not be '
    "recorded in the events log.</p>"
)


def with_logging_warning(html: str) -> str:
    """The page with a logging-failure banner at the top of its main content."""
    return html.replace("<main>\n", "<main>\n" + LOGGING_WARNING + "\n", 1)


def unavailable() -> str:
    body = (
        "<h1>Data unavailable</h1>"
        "<p>The demo data could not be read, so nothing is shown rather than a guess.</p>"
    )
    return page("Data unavailable", "", None, body)


def not_found() -> str:
    return page("Not found", "", None, '<h1>Not found</h1><p><a href="/">Home</a></p>')
