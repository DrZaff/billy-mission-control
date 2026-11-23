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
  // (the events log has the detail); these only tell apart the cases the owner acts on
  // differently. 503: the sign-in store is unavailable, so nobody can sign in or enroll.
  function refused(result, otherwise) {
    if (result.status === 503) {
      return "Sign-in is unavailable right now (a problem on the server). Try again later. " +
        "To stop Billy meanwhile, use the stop marker on the server.";
    }
    if (result.status === 429) return "Too many tries. Wait a minute, then try again.";
    return otherwise;
  }

  // After a passkey is added, the code is spent: the form goes away so it can't be sent again
  // (a second press was refused as a reused code and read like a failure, in A4c).
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
    const begin = await post("/enroll/begin", { code: code });
    if (!begin.ok) {
      return say(refused(begin, "That code didn't work: it was mistyped, used already, or " +
        "more than 10 minutes old. Make a new one on the server."));
    }
    const o = begin.data.options;
    const publicKey = Object.assign({}, o, {
      challenge: fromB64url(o.challenge),
      user: Object.assign({}, o.user, { id: fromB64url(o.user.id) }),
      excludeCredentials: descriptors(o.excludeCredentials),
    });
    let credential;
    try {
      credential = await navigator.credentials.create({ publicKey: publicKey });
    } catch (error) {
      // The browser lists this device's passkey as already added (excludeCredentials).
      if (error && error.name === "InvalidStateError") {
        finishEnroll();
        return say("This device already has a passkey for Mission Control. Nothing was " +
          "added; sign in with the one you have.");
      }
      throw error;
    }
    const done = await post("/enroll/complete", {
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
    if (done.ok) {
      finishEnroll();
      return say("Passkey added. You can sign in now.");
    }
    say(refused(done, "The passkey was not added. Make a new code on the server and try again."));
  }

  async function signin() {
    const begin = await post("/signin/begin", {});
    if (!begin.ok) {
      return say(refused(begin, "No passkey is set up yet. Make a one-time code on the " +
        "server, then add a passkey."));
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
      say(refused(done, "Sign-in failed. Try again."));
    }
  }

  function guard(task) {
    return function (event) {
      if (event) event.preventDefault();
      if (!window.PublicKeyCredential) return say("This browser doesn't support passkeys.");
      say("Waiting for your passkey…");
      task().catch(function () {
        say("Cancelled, or the passkey didn't respond. Try again.");
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
