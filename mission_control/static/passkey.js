// Mission Control's only script: the passkey ceremony on the sign-in and enrollment pages.
// It calls the browser's WebAuthn API and posts the result to this app, nowhere else. It
// writes text with textContent only, and keeps nothing: no storage, no cookies of its own.
"use strict";

(function () {
  function fromB64url(text) {
    const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
    const raw = atob(b64 + pad);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  function toB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let raw = "";
    for (let i = 0; i < bytes.length; i += 1) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function say(text) {
    const status = document.getElementById("status");
    if (status) status.textContent = text;
  }

  async function post(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    let data = {};
    try {
      data = await response.json();
    } catch (error) {
      data = {};
    }
    return { ok: response.ok, status: response.status, data: data };
  }

  // What a refused step means, by the server's status. The server keeps the reasons generic
  // (the events log has the detail); the page only tells apart the cases the owner acts on
  // differently. Each step names its own message for each status, and "other" for the rest:
  // no status falls through to a message meant for another (Codex, A4c).
  const UNAVAILABLE = "Sign-in is unavailable right now (a problem on the server). Try again " +
    "later. To stop Billy meanwhile, use the stop marker on the server.";
  const RELOAD = "The request was refused. Reload this page and try again.";
  const NEW_CODE = "The one-time code is used up. Make a new one on the server, then reload " +
    "this page.";

  // The outcome of a completed enrollment isn't known: the server may have saved the passkey
  // before the answer was lost.
  const MAYBE_ADDED = "The passkey may or may not have been added. Try signing in. If that " +
    "fails and passkey list on the server doesn't show it: ";

  function explain(result, cases) {
    return cases[result.status] || cases.other;
  }

  // Once enrollment has begun, the code is spent, whatever happens next: the form goes away
  // so it can't be sent again (a second press was refused as a reused code and read like a
  // failure, in A4c).
  function finishEnroll() {
    const form = document.getElementById("enroll");
    if (form) form.hidden = true;
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return { type: c.type, id: fromB64url(c.id), transports: c.transports };
    });
  }

  async function enroll(code) {
    let begin;
    try {
      begin = await post("/enroll/begin", { code: code });
    } catch (error) {
      return say("Couldn't reach Mission Control. Check that Tailscale is on, then try again. " +
        "If the code is then refused, make a new one on the server.");
    }
    if (!begin.ok) {
      // The code is spent only when this step succeeds, so it may be tried again here.
      return say(explain(begin, {
        // Two passkeys already: the server issues no new code until one is revoked (Codex,
        // 5fadcd2), so the two causes get different next steps.
        400: "That code didn't work. If passkey list on the server shows two passkeys, " +
          "revoke one there first. Otherwise the code was mistyped, used already or more " +
          "than 10 minutes old: make a new one on the server.",
        429: "Too many tries. Wait a minute, then try again.",
        // The server may have spent the code before its store failed (Codex, 0c4fa76).
        503: UNAVAILABLE + " The code may be used up: if it's refused once this works again, " +
          "make a new one on the server.",
        other: RELOAD,
      }));
    }
    // From here on the code is spent, whatever happens, so the form goes now: every way out
    // below asks for a new code, or says the passkey was added (Codex, A4c).
    finishEnroll();
    let credential;
    try {
      const o = begin.data.options;
      const publicKey = Object.assign({}, o, {
        challenge: fromB64url(o.challenge),
        user: Object.assign({}, o.user, { id: fromB64url(o.user.id) }),
        excludeCredentials: descriptors(o.excludeCredentials),
      });
      credential = await navigator.credentials.create({ publicKey: publicKey });
    } catch (error) {
      // The browser lists this device's passkey as already added (excludeCredentials).
      if (error && error.name === "InvalidStateError") {
        return say("This device already has a passkey for Mission Control. Nothing was " +
          "added; sign in with the one you have.");
      }
      return say("Cancelled, or the passkey didn't respond. Nothing was added. " + NEW_CODE);
    }
    let done;
    try {
      done = await post("/enroll/complete", {
        ticket: begin.data.ticket,
        credential: {
          id: credential.id,
          rawId: toB64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: toB64url(credential.response.clientDataJSON),
            attestationObject: toB64url(credential.response.attestationObject),
          },
        },
      });
    } catch (error) {
      // The server may have added it before the connection dropped: say so, don't guess.
      return say("The connection dropped before Mission Control answered. " + MAYBE_ADDED +
        NEW_CODE);
    }
    if (done.ok) return say("Passkey added. You can sign in now.");
    // Only these statuses come from the app itself, and each means nothing was saved. Any
    // other (a gateway's 502, say) may arrive after the app saved it (Codex, 785bcf2).
    say(explain(done, {
      // 400 includes a racing enrollment that took the last of the two slots: the server
      // issues no new code at the limit, so that case comes first (Codex, 785bcf2).
      400: "The passkey was not added. If passkey list on the server shows two passkeys, " +
        "revoke one there first. Otherwise: " + NEW_CODE,
      403: "The passkey was not added. " + NEW_CODE,
      429: "Too many tries. Nothing was added. Wait a minute. " + NEW_CODE,
      503: UNAVAILABLE + " Nothing was added; once it works again: " + NEW_CODE,
      other: "Mission Control didn't answer normally. " + MAYBE_ADDED + NEW_CODE,
    }));
  }

  async function signin() {
    const begin = await post("/signin/begin", {});
    if (!begin.ok) {
      return say(explain(begin, {
        400: "No passkey is set up yet. Make a one-time code on the server, then add a " +
          "passkey.",
        429: "Too many tries. Wait a minute, then try again.",
        503: UNAVAILABLE,
        other: RELOAD,
      }));
    }
    const o = begin.data.options;
    const publicKey = Object.assign({}, o, {
      challenge: fromB64url(o.challenge),
      allowCredentials: descriptors(o.allowCredentials),
    });
    const credential = await navigator.credentials.get({ publicKey: publicKey });
    const r = credential.response;
    const done = await post("/signin/complete", {
      ticket: begin.data.ticket,
      credential: {
        id: credential.id,
        rawId: toB64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toB64url(r.clientDataJSON),
          authenticatorData: toB64url(r.authenticatorData),
          signature: toB64url(r.signature),
          userHandle: r.userHandle ? toB64url(r.userHandle) : null,
        },
      },
    });
    if (done.ok) {
      window.location.assign("/");
    } else {
      say(explain(done, {
        429: "Too many tries. Wait a minute, then try again.",
        503: UNAVAILABLE,
        other: "Sign-in failed. Try again.",
      }));
    }
  }

  // One ceremony at a time: a second tap while one is under way is ignored, so a later
  // answer (a code refused as reused) can't overwrite the first one's (Codex, 0c4fa76).
  function guard(task) {
    let busy = false;
    return function (event) {
      if (event) event.preventDefault();
      if (busy) return;
      if (!window.PublicKeyCredential) return say("This browser doesn't support passkeys.");
      busy = true;
      say("Waiting for your passkey…");
      task()
        .catch(function () {
          say("Cancelled, or the passkey didn't respond. Try again.");
        })
        .finally(function () {
          busy = false;
        });
    };
  }

  document.addEventListener("DOMContentLoaded", function () {
    const mode = document.body.dataset.mode;
    if (mode === "signin") {
      document.getElementById("signin").addEventListener("click", guard(signin));
    } else if (mode === "enroll") {
      document.getElementById("enroll").addEventListener(
        "submit",
        guard(function () {
          return enroll(document.getElementById("code").value);
        })
      );
    }
  });
})();
