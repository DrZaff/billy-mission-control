# Owner settings

GitHub settings for this repository that only the owner can make. No agent, app or workflow changes them. Do them in this order. Re-read this page whenever the build plan adds a new required check or an app.

## 1. Actions (Settings > Actions > General)

- **Actions permissions:** "Allow DrZaff, and select non-DrZaff, actions and reusable workflows". Tick **Allow actions created by GitHub**, and **Require actions to be pinned to a full-length commit SHA**. CI uses `actions/checkout` and `actions/setup-python`, both GitHub-owned and pinned to commits.
- **Approval for running fork pull request workflows:** **Require approval for all external contributors**. The repository is public, so anyone can open a pull request.
- **Workflow permissions:** **Read repository contents and packages permissions**.
- **Untick** "Allow GitHub Actions to create and approve pull requests".
- **Secrets and environments:** none. CI needs none, and `tests/test_policy.py` fails if a workflow reads one.

## 2. Secret protection (Settings > Advanced Security)

Turn on **Secret scanning** and **Push protection**; both are free for public repositories. Push protection refuses a push that contains a known key format, before it becomes public.

## 3. First CI run

Open the A1 pull request. Under its **Checks**, confirm that **lint** and **test** both ran and passed. GitHub only offers a check as "required" after it has run once.

## 4. The `main` ruleset (Settings > Rules > Rulesets > New branch ruleset)

Least privilege, the same pattern as "Main - Owner Merge Only" on the main site's repository, without its digest bypass. GitHub enforces it because this repository is public; on a free account it would not be enforced on a private one.

| Setting | Value | Why |
| --- | --- | --- |
| Name | `Main - Owner Merge Only` | |
| Enforcement | **Active** | |
| Target | Default branch (`main`) | |
| Bypass list | **DrZaff: "For pull requests only".** No apps, no `github-actions`, no roles. | The owner merges through PRs; nobody pushes directly |
| Restrict updates | On | Only bypass actors can change `main`, so no app can merge |
| Restrict deletions | On | |
| Block force pushes | On | |
| Require a pull request before merging | On: **1** approval; **dismiss stale approvals**; **require review from Code Owners**; **require approval of the most recent reviewable push** | Approval covers the exact commit that merges |
| Require status checks to pass | On: **lint** and **test** (from GitHub Actions). "Require branches to be up to date": **off** | Updating a branch would add a commit nobody reviewed |
| Everything else | Off | |

**How merging works then.** PRs that Claude opens appear under the owner's account, and GitHub never lets anyone approve their own PR. Because "Restrict updates" is on, every owner merge goes through the bypass box anyway. Tick **"Merge without waiting for requirements to be met (bypass rules)"** only when the merge box shows **All checks have passed**, and, for a PR someone else opened, **Changes approved**. The box also skips failing checks.

**Check it** after saving: a direct push to `main` should be refused, and so should deleting `main`.

## 5. Apps and access

- **Do not install the Billy publisher app here.** Installing it is plan item E1's decision, made only once that onboarding checklist is met.
- **Mission Control's own read-only GitHub identity** comes in phase A5, created by the owner (design §7).
- **Optional:** turn off Wiki, Projects and Discussions if unused.

## 6. Codex review

Every commit here is reviewed by Codex at its exact SHA before the owner merges. The repository is public, so the review step on the agent server clones it without credentials, exactly as for the main site:

```sh
N=/home/agent/.nvm/versions/node/v26.13.0/bin; cd /tmp && \
sudo -H -u agent env PATH="$N:/usr/local/bin:/usr/bin:/bin" python3 /opt/billy/handoff.py review <branch> <sha> --repo billy-mission-control
```

This needs Billy's `handoff.py` to list `billy-mission-control` as public (a change in the main site's repository). The Billy publisher isn't installed here, so there is no publish step: after a passing review, Claude opens the PR, and its head must be the reviewed SHA.
