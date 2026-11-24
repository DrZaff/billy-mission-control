"""Mission Control's fetcher (phase A5a, issue #16): the only part that reads GitHub.

It runs as its own account, the only one that can read the read-only "Billy Reader" GitHub App's
key. The web app asks it to refresh over a local Unix socket; it then checks the App is still
read-only and limited to the two repositories, reads their pull requests, and writes a snapshot
file that the web app reads. The web app itself never has network access: `mission_control`
must never import this package (tests/test_policy.py), and inside this package only `github.py`
may talk to the network, and only to api.github.com.
"""
