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
    return { ok: response.ok, data: data };
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return { type: c.type, id: fromB64url(c.id), transports: c.transports };
    });
  }

  async function enroll(code) {
    const begin = await post("/enroll/begin", { code: code });
    if (!begin.ok) return say("That code didn't work. Make a new one on the server.");
    const o = begin.data.options;
    const publicKey = Object.assign({}, o, {
      challenge: fromB64url(o.challenge),
      user: Object.assign({}, o.user, { id: fromB64url(o.user.id) }),
      excludeCredentials: descriptors(o.excludeCredentials),
    });
    const credential = await navigator.credentials.create({ publicKey: publicKey });
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
    say(done.ok ? "Passkey added. You can sign in now." : "The passkey was not added.");
  }

  async function signin() {
    const begin = await post("/signin/begin", {});
    if (!begin.ok) return say("Sign-in isn't available. Add a passkey first.");
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
      say("Sign-in failed. Try again.");
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
