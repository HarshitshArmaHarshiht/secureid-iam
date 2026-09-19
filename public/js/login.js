/**
 * SecureID — Login Journey
 *
 *   credentials  →  MFA  →  session
 *
 * Two deliberate properties:
 *   1. A correct password alone does NOT log you in. It returns a
 *      short-lived pendingToken; only /api/login/mfa issues the session.
 *   2. The session cookie is HttpOnly, so nothing here can read it. The
 *      page discovers who you are by asking GET /api/me.
 */

(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  async function api(method, path, body) {
    let res, data;
    try {
      res = await fetch(`/api${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin", // carry the session cookie
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      data = await res.json().catch(() => ({}));
    } catch {
      return { status: 0, data: { message: "Could not reach the server." } };
    }
    return { status: res.status, data };
  }

  const post = (path, body) => api("POST", path, body || {});
  const get = (path) => api("GET", path);

  /* ------------------------------------------------------------------ */
  /* Shared UI helpers                                                   */
  /* ------------------------------------------------------------------ */

  const state = { pendingToken: null, challengeId: null, method: "authenticator" };
  let countdownId = null;

  function showScreen(name) {
    $$(".screen").forEach((s) => s.classList.toggle("active", s.dataset.screen === name));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function setFieldError(field, message) {
    const el = $(`[data-error="${field}"]`);
    const input = $(`#${field}`);
    if (el) el.textContent = message || "";
    if (input) input.closest(".field")?.classList.toggle("has-error", Boolean(message));
  }

  function setBusy(button, busy) {
    if (!button) return;
    button.disabled = busy;
    const spinner = button.querySelector(".spinner");
    const label = button.querySelector(".btn-label");
    if (spinner) spinner.hidden = !busy;
    if (label) label.style.opacity = busy ? "0.6" : "1";
  }

  let toastTimer = null;
  function toast(message, kind = "") {
    let el = $("#toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.className = `toast show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
  }

  /* ------------------------------------------------------------------ */
  /* OTP boxes — same behaviour as the registration screens              */
  /* ------------------------------------------------------------------ */

  function buildOtpBoxes(container) {
    const tpl = $("#otpBoxTemplate");
    container.innerHTML = "";
    const boxes = [];
    for (let i = 0; i < 6; i++) {
      const node = tpl.content.firstElementChild.cloneNode(true);
      container.appendChild(node);
      boxes.push(node);
    }

    boxes.forEach((box, i) => {
      box.addEventListener("input", (e) => {
        const digit = e.target.value.replace(/\D/g, "").slice(-1);
        e.target.value = digit;
        boxes.forEach((b) => b.classList.remove("error"));
        if (digit && i < boxes.length - 1) boxes[i + 1].focus();
        if (boxes.every((b) => b.value.length === 1)) container.closest("form")?.requestSubmit();
      });

      box.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !box.value && i > 0) {
          boxes[i - 1].focus();
          boxes[i - 1].value = "";
        } else if (e.key === "ArrowLeft" && i > 0) {
          boxes[i - 1].focus();
        } else if (e.key === "ArrowRight" && i < boxes.length - 1) {
          boxes[i + 1].focus();
        }
      });

      box.addEventListener("paste", (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData("text");
        text.replace(/\D/g, "").split("").slice(0, 6).forEach((d, idx) => {
          if (boxes[idx]) boxes[idx].value = d;
        });
        if (boxes.every((b) => b.value.length === 1)) container.closest("form")?.requestSubmit();
        else (boxes.find((b) => !b.value) || boxes[5]).focus();
      });
    });

    if (boxes[0]) boxes[0].focus();
    return boxes;
  }

  const otpValue = (container) => $$(".otp-box", container).map((b) => b.value).join("");

  function startCountdown(ms) {
    const wrap = $("#mfaTimerWrap");
    const timerEl = $("#mfaTimer");
    wrap.hidden = false;
    clearInterval(countdownId);

    let remaining = ms;
    const render = () => {
      const total = Math.max(0, Math.ceil(remaining / 1000));
      timerEl.textContent = `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
    };
    render();

    countdownId = setInterval(() => {
      remaining -= 1000;
      if (remaining <= 0) {
        clearInterval(countdownId);
        timerEl.textContent = "00:00";
        $("#mfaStatus").textContent = "This code has expired. Please log in again.";
        $$(".otp-box").forEach((b) => (b.disabled = true));
        return;
      }
      render();
    }, 1000);
  }

  /* ------------------------------------------------------------------ */
  /* Show / hide password                                                */
  /* ------------------------------------------------------------------ */

  const passwordInput = $("#loginPassword");
  const eyeToggle = $("#loginEyeToggle");

  eyeToggle.addEventListener("click", () => {
    const nowVisible = passwordInput.type === "password";
    passwordInput.type = nowVisible ? "text" : "password";
    eyeToggle.textContent = nowVisible ? "🙈" : "👁";
    eyeToggle.setAttribute("aria-label", nowVisible ? "Hide password" : "Show password");
    eyeToggle.setAttribute("aria-pressed", String(nowVisible));
    passwordInput.focus();
  });

  /* ------------------------------------------------------------------ */
  /* Step 1 — credentials                                                */
  /* ------------------------------------------------------------------ */

  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    setFieldError("loginEmail", "");
    setFieldError("loginPassword", "");

    const email = $("#loginEmail").value.trim();
    const password = passwordInput.value;

    if (!email) return setFieldError("loginEmail", "Enter your email address.");
    if (!password) return setFieldError("loginPassword", "Enter your password.");

    const submit = $("#loginSubmit");
    setBusy(submit, true);
    const { status, data } = await post("/login", { email, password });
    setBusy(submit, false);

    if (status === 200 && data.mfaRequired) {
      state.pendingToken = data.pendingToken;
      state.challengeId = data.challengeId || null;
      state.method = data.method || "authenticator";

      $("#mfaSubtitle").textContent =
        state.method === "authenticator"
          ? "Enter the code from your authenticator app"
          : data.message || "Enter the code we just sent you.";

      buildOtpBoxes($('[data-otp-group="login-mfa"]'));
      $("#mfaStatus").textContent = "";

      if (state.method === "authenticator") {
        $("#mfaTimerWrap").hidden = true;
      } else {
        startCountdown(data.expiresInMs || 165000);
      }

      showScreen("mfa");
      return;
    }

    // One message for both wrong password and unknown account — the
    // server deliberately does not reveal which.
    if (status === 401) {
      setFieldError("loginPassword", data.message || "Incorrect email or password.");
      return;
    }
    if (status === 403) {
      toast(data.message || "Finish creating your account first.", "error");
      setTimeout(() => (window.location.href = "/index.html"), 1800);
      return;
    }
    toast(data.message || "Could not log you in. Please try again.", "error");
  });

  /* ------------------------------------------------------------------ */
  /* Step 2 — MFA                                                        */
  /* ------------------------------------------------------------------ */

  $("#loginMfaForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const container = $('[data-otp-group="login-mfa"]');
    const code = otpValue(container);
    if (code.length !== 6) return;

    const submit = $("#mfaSubmit");
    setBusy(submit, true);
    const { status, data } = await post("/login/mfa", {
      pendingToken: state.pendingToken,
      challengeId: state.challengeId,
      code,
    });
    setBusy(submit, false);

    if (status === 200 && data.authenticated) {
      clearInterval(countdownId);
      $$(".otp-box", container).forEach((b) => b.classList.add("success"));
      await loadAccount();
      showScreen("dashboard");
      return;
    }

    $$(".otp-box", container).forEach((b) => b.classList.add("error"));
    const statusEl = $("#mfaStatus");

    if (data.error === "wrong_code") {
      statusEl.textContent = `Incorrect code. You have ${data.attemptsLeft} attempt${data.attemptsLeft === 1 ? "" : "s"} left.`;
      $$(".otp-box", container).forEach((b) => (b.value = ""));
      $$(".otp-box", container)[0].focus();
    } else if (data.error === "pending_expired") {
      statusEl.textContent = "Your login attempt expired. Please sign in again.";
      setTimeout(() => showScreen("credentials"), 1500);
    } else {
      statusEl.textContent = data.message || "Could not verify that code.";
      $$(".otp-box", container).forEach((b) => (b.disabled = true));
    }
  });

  $("#backToLogin").addEventListener("click", () => {
    clearInterval(countdownId);
    state.pendingToken = null;
    showScreen("credentials");
  });

  /* ------------------------------------------------------------------ */
  /* Step 3 — the authenticated view                                     */
  /* ------------------------------------------------------------------ */

  async function loadAccount() {
    const { status, data } = await get("/me");
    if (status !== 200 || !data.user) return false;

    const u = data.user;
    const rows = [
      ["Name", u.fullName],
      ["Email", u.email],
      ["Mobile", "+91 " + u.mobile],
      ["MFA method", u.mfaMethod === "authenticator" ? "Authenticator app" : u.mfaMethod],
      ["Email verified", u.emailVerified ? "Yes" : "No"],
      ["Mobile verified", u.mobileVerified ? "Yes" : "No"],
    ];

    $("#accountSummary").innerHTML = rows
      .map(([k, v]) => `<dt>${k}</dt><dd>${escapeHtml(String(v))}</dd>`)
      .join("");
    return true;
  }

  /** Values come from our own API, but escaping is cheap insurance. */
  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  $("#logoutBtn").addEventListener("click", async () => {
    const btn = $("#logoutBtn");
    setBusy(btn, true);
    await post("/logout");
    setBusy(btn, false);

    $("#loginForm").reset();
    state.pendingToken = null;
    state.challengeId = null;
    showScreen("credentials");
    toast("You have been logged out.", "success");
  });

  /* ------------------------------------------------------------------ */
  /* On load: if a valid session cookie is already present, skip ahead.  */
  /* ------------------------------------------------------------------ */

  (async () => {
    if (await loadAccount()) showScreen("dashboard");
  })();
})();
