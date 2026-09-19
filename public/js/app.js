/**
 * SecureID — Registration Journey
 *
 * Screen state machine + OTP widgets + API calls.
 *
 * Identity note: after POST /api/register the server sets a signed,
 * HttpOnly `reg_session` cookie and reads the user id from that on every
 * later step. This file therefore does NOT send a userId — it could not
 * read the cookie even if it wanted to, which is the point.
 */

(() => {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Small utilities                                                     */
  /* ------------------------------------------------------------------ */

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  async function api(path, body) {
    let res, data;
    try {
      res = await fetch(`/api${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // Send the HttpOnly reg_session cookie with every step.
        credentials: "same-origin",
        body: JSON.stringify(body || {}),
      });
      data = await res.json().catch(() => ({}));
    } catch (err) {
      return { status: 0, data: { error: "network_error", message: "Could not reach the server. Is it running?" } };
    }
    return { status: res.status, data };
  }

  function formatTime(ms) {
    const totalSec = Math.max(0, Math.ceil(ms / 1000));
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }

  let toastTimer = null;
  function toast(message, kind = "") {
    let el = $("#toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.className = `toast show ${kind}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
  }


  /* ------------------------------------------------------------------ */
  /* App state                                                           */
  /* ------------------------------------------------------------------ */

  const state = {
    userId: null,
    email: null,
    mobile: null,
    emailChallengeId: null,
    smsChallengeId: null,
    mfaMethod: "authenticator",
    mfaChallengeId: null,
  };

  const STEP_FOR_SCREEN = {
    register: 1,
    "email-otp": 2,
    "sms-otp": 3,
    "mfa-select": 4,
    "mfa-qr": 4,
    "mfa-verify": 4,
    success: 5,
  };

  function showScreen(name) {
    $$(".screen").forEach((s) => s.classList.toggle("active", s.dataset.screen === name));
    updateStepper(STEP_FOR_SCREEN[name] || 1);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function updateStepper(activeStep) {
    $$("#brandSteps li").forEach((li) => {
      const step = Number(li.dataset.step);
      li.classList.toggle("done", step < activeStep);
      li.classList.toggle("active", step === activeStep);
    });
    $$("#mobileStepper .mstep").forEach((el) => {
      const step = Number(el.dataset.step);
      el.classList.toggle("done", step < activeStep);
      el.classList.toggle("active", step === activeStep);
    });
  }

  function setFieldError(fieldName, message) {
    const errorEl = $(`[data-error="${fieldName}"]`);
    const inputEl = $(`#${fieldName}`);
    if (errorEl) errorEl.textContent = message || "";
    if (inputEl) inputEl.closest(".field")?.classList.toggle("has-error", Boolean(message));
  }

  function clearFieldErrors() {
    ["fullName", "email", "mobile", "password"].forEach((f) => setFieldError(f, ""));
  }

  function setBusy(buttonEl, busy) {
    if (!buttonEl) return;
    buttonEl.disabled = busy;
    const spinner = buttonEl.querySelector(".spinner");
    const label = buttonEl.querySelector(".btn-label");
    if (spinner) spinner.hidden = !busy;
    if (label) label.style.opacity = busy ? "0.6" : "1";
  }

  /* ------------------------------------------------------------------ */
  /* OTP box widget                                                      */
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
        clearOtpErrorState(boxes);
        if (digit && i < boxes.length - 1) boxes[i + 1].focus();
        maybeAutoSubmit(container);
      });

      box.addEventListener("keydown", (e) => {
        if (e.key === "Backspace") {
          if (!box.value && i > 0) {
            boxes[i - 1].focus();
            boxes[i - 1].value = "";
          }
          clearOtpErrorState(boxes);
        } else if (e.key === "ArrowLeft" && i > 0) {
          boxes[i - 1].focus();
        } else if (e.key === "ArrowRight" && i < boxes.length - 1) {
          boxes[i + 1].focus();
        } else if (e.key === "Enter") {
          e.preventDefault();
          container.closest("form")?.requestSubmit();
        }
      });

      box.addEventListener("paste", (e) => {
        e.preventDefault();
        const text = (e.clipboardData || window.clipboardData).getData("text");
        const digits = text.replace(/\D/g, "").split("").slice(0, boxes.length);
        digits.forEach((d, idx) => {
          if (boxes[idx]) boxes[idx].value = d;
        });
        const nextEmpty = boxes.findIndex((b) => !b.value);
        (nextEmpty === -1 ? boxes[boxes.length - 1] : boxes[nextEmpty]).focus();
        maybeAutoSubmit(container);
      });
    });

    return boxes;
  }

  function maybeAutoSubmit(container) {
    const boxes = $$(".otp-box", container);
    if (boxes.every((b) => b.value.length === 1)) {
      container.closest("form")?.requestSubmit();
    }
  }

  function getOtpValue(container) {
    return $$(".otp-box", container).map((b) => b.value).join("");
  }

  function clearOtpBoxes(container, { focus = true } = {}) {
    const boxes = $$(".otp-box", container);
    boxes.forEach((b) => {
      b.value = "";
      b.classList.remove("error", "success");
      b.disabled = false;
    });
    if (focus && boxes[0]) boxes[0].focus();
  }

  function markOtpError(container) {
    $$(".otp-box", container).forEach((b) => b.classList.add("error"));
  }

  function clearOtpErrorState(boxes) {
    boxes.forEach((b) => b.classList.remove("error"));
  }

  function disableOtpBoxes(container) {
    $$(".otp-box", container).forEach((b) => (b.disabled = true));
  }

  /* ------------------------------------------------------------------ */
  /* Countdown timer helper                                              */
  /* ------------------------------------------------------------------ */

  function makeCountdown({ timerEl, wrapEl, onExpire, durationMs }) {
    let remaining = durationMs;
    let intervalId = null;

    function tick() {
      remaining -= 1000;
      if (remaining <= 0) {
        stop();
        if (timerEl) timerEl.textContent = "00:00";
        onExpire && onExpire();
        return;
      }
      if (timerEl) timerEl.textContent = formatTime(remaining);
      if (wrapEl) wrapEl.classList.toggle("warn", remaining <= 20000);
    }

    function start() {
      stop();
      if (timerEl) timerEl.textContent = formatTime(remaining);
      intervalId = setInterval(tick, 1000);
    }

    function stop() {
      if (intervalId) clearInterval(intervalId);
      intervalId = null;
    }

    start();
    return { stop, restart: (newDuration) => { remaining = newDuration; start(); } };
  }

  /* ------------------------------------------------------------------ */
  /* Resend cooldown helper (disables the "Resend code" link briefly)    */
  /* ------------------------------------------------------------------ */

  function startResendCooldown(linkEl, cooldownEl, seconds = 25) {
    let remaining = seconds;
    linkEl.disabled = true;
    cooldownEl.textContent = `(${String(remaining).padStart(2, "0")}s)`;
    const id = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(id);
        linkEl.disabled = false;
        cooldownEl.textContent = "";
        return;
      }
      cooldownEl.textContent = `(${String(remaining).padStart(2, "0")}s)`;
    }, 1000);
  }

  /* ------------------------------------------------------------------ */
  /* Password: show/hide toggle                                          */
  /*                                                                     */
  /* Flipping the input's `type` between "password" and "text" is the    */
  /* whole trick — the browser does the masking, so there is nothing to  */
  /* re-render and the caret position is preserved.                      */
  /* ------------------------------------------------------------------ */

  const passwordInput = $("#password");
  const eyeToggle = $("#eyeToggle");

  eyeToggle.addEventListener("click", () => {
    const nowVisible = passwordInput.type === "password";
    passwordInput.type = nowVisible ? "text" : "password";

    eyeToggle.textContent = nowVisible ? "🙈" : "👁";
    eyeToggle.setAttribute("aria-label", nowVisible ? "Hide password" : "Show password");
    eyeToggle.setAttribute("aria-pressed", String(nowVisible));

    // Keep focus in the field so typing can continue uninterrupted.
    passwordInput.focus();
  });

  /* ------------------------------------------------------------------ */
  /* Password: live strength indicator                                   */
  /*                                                                     */
  /* On every keystroke: recompute, tick the four rules, move the bar,   */
  /* and enable/disable the submit button. The scoring itself lives in   */
  /* js/password-strength.js and is mirrored on the server — the browser */
  /* copy is feedback, the server copy is the actual gate.               */
  /* ------------------------------------------------------------------ */

  const strengthWrap = $("#pwStrength");
  const strengthFill = $("#pwStrengthFill");
  const strengthLabel = $("#pwStrengthLabel");
  const checklist = $("#pwChecklist");
  const registerSubmit = $("#registerSubmit");

  function updatePasswordUi() {
    const value = passwordInput.value;
    const result = PasswordStrength.strength(value);
    const rules = PasswordStrength.checks(value);

    // Tick each rule in the checklist.
    $$("li", checklist).forEach((li) => {
      li.classList.toggle("met", Boolean(rules[li.dataset.rule]));
    });

    // The bar only appears once the user starts typing.
    strengthWrap.hidden = value.length === 0;
    strengthWrap.dataset.level = result.level;
    strengthFill.style.width = result.percent + "%";
    strengthLabel.textContent = result.label;

    // Block submission until all four rules pass AND the minimum
    // strength is reached. The server enforces the same thing.
    const acceptable = PasswordStrength.allRulesPass(value) && PasswordStrength.meetsMinimum(value);
    registerSubmit.disabled = value.length > 0 && !acceptable;

    if (value && !acceptable) {
      setFieldError(
        "password",
        PasswordStrength.allRulesPass(value)
          ? `Password is too weak — aim for at least ${PasswordStrength.MINIMUM} strength.`
          : ""
      );
    } else {
      setFieldError("password", "");
    }
  }

  passwordInput.addEventListener("input", updatePasswordUi);
  updatePasswordUi();

  /* ------------------------------------------------------------------ */
  /* SCREEN: Register                                                    */
  /* ------------------------------------------------------------------ */

  const registerForm = $("#registerForm");
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearFieldErrors();

    const fullName = $("#fullName").value.trim();
    const email = $("#email").value.trim();
    const mobile = $("#mobile").value.trim();
    const password = $("#password").value;

    if (!$("#terms").checked) {
      toast("Please accept the Terms & Conditions to continue.", "error");
      return;
    }

    // Final client-side strength gate. The server checks this again.
    if (!PasswordStrength.allRulesPass(password)) {
      setFieldError("password", "Your password does not meet all four requirements yet.");
      passwordInput.focus();
      return;
    }
    if (!PasswordStrength.meetsMinimum(password)) {
      setFieldError(
        "password",
        `Password is too weak — aim for at least ${PasswordStrength.MINIMUM} strength.`
      );
      passwordInput.focus();
      return;
    }

    const submitBtn = $("#registerSubmit");
    setBusy(submitBtn, true);

    const { status, data } = await api("/register", { fullName, email, mobile, password });

    setBusy(submitBtn, false);

    if (status === 201) {
      state.userId = data.userId;
      state.email = email;
      state.mobile = mobile;
      state.emailChallengeId = data.challengeId;

      $("#emailDestination").textContent = email;
      const container = $('[data-otp-group="email"]');
      buildOtpBoxes(container);
      $("#emailOtpStatus").textContent = "";
      $("#emailOtpSubmit").hidden = false;
      $("#emailResendBtn").hidden = true;

      startEmailTimer(data.expiresInMs);
      showScreen("email-otp");
      return;
    }

    if (status === 400 && data.fields) {
      Object.entries(data.fields).forEach(([field, msg]) => setFieldError(field, msg));
      return;
    }

    if (status === 409) {
      setFieldError("email", data.message || "This email is already registered.");
      return;
    }

    toast(data.message || "Something went wrong. Please try again.", "error");
  });

  /* ------------------------------------------------------------------ */
  /* SCREEN: Email OTP                                                   */
  /* ------------------------------------------------------------------ */

  let emailCountdown = null;

  function startEmailTimer(durationMs) {
    emailCountdown = makeCountdown({
      timerEl: $("#emailTimer"),
      wrapEl: $("#emailTimer").closest(".otp-timer"),
      durationMs,
      onExpire: () => {
        $("#emailOtpStatus").textContent = "This code has expired.";
        $("#emailOtpStatus").classList.remove("success");
        disableOtpBoxes($('[data-otp-group="email"]'));
        $("#emailOtpSubmit").hidden = true;
        $("#emailResendBtn").hidden = false;
      },
    });
  }

  $("#emailOtpForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const container = $('[data-otp-group="email"]');
    const otp = getOtpValue(container);
    if (otp.length !== 6) return;

    const submitBtn = $("#emailOtpSubmit");
    setBusy(submitBtn, true);

    const { status, data } = await api("/verify-email-otp", { challengeId: state.emailChallengeId, otp });

    setBusy(submitBtn, false);

    if (status === 200 && data.verified) {
      emailCountdown?.stop();
      $("#emailOtpStatus").textContent = "";
      $$(".otp-box", container).forEach((b) => b.classList.add("success"));

      // Kick off SMS OTP per the guideline flow.
      const smsRes = await api("/send-sms-otp");
      if (smsRes.status === 200) {
        state.smsChallengeId = smsRes.data.challengeId;
        $("#smsDestination").textContent = `+91 ${state.mobile}`;
        const smsContainer = $('[data-otp-group="sms"]');
        buildOtpBoxes(smsContainer);
        $("#smsOtpStatus").textContent = "";
        $("#smsOtpSubmit").hidden = false;
        $("#smsResendBtn").hidden = true;
        startSmsTimer(smsRes.data.expiresInMs);
        showScreen("sms-otp");
      } else {
        toast(smsRes.data.message || "Could not send SMS OTP.", "error");
      }
      return;
    }

    handleOtpError(status, data, container, $("#emailOtpStatus"), {
      onMaxAttempts: () => {
        $("#emailOtpSubmit").hidden = true;
        $("#emailResendBtn").hidden = false;
      },
      onExpired: () => {
        $("#emailOtpSubmit").hidden = true;
        $("#emailResendBtn").hidden = false;
      },
    });
  });

  function handleOtpError(status, data, container, statusEl, { onMaxAttempts, onExpired } = {}) {
    markOtpError(container);
    if (data.error === "wrong_code") {
      statusEl.textContent = `Incorrect code. Please try again. You have ${data.attemptsLeft} attempt${data.attemptsLeft === 1 ? "" : "s"} left.`;
      statusEl.classList.remove("success");
      clearOtpBoxes(container);
    } else if (data.error === "max_attempts") {
      statusEl.textContent = "Maximum attempts reached. Please request a new code.";
      disableOtpBoxes(container);
      onMaxAttempts && onMaxAttempts();
    } else if (data.error === "expired") {
      statusEl.textContent = "This code has expired.";
      disableOtpBoxes(container);
      onExpired && onExpired();
    } else {
      statusEl.textContent = data.message || "Something went wrong.";
    }
  }

  $("#emailResendLink").addEventListener("click", () => resendEmailOtp());
  $("#emailResendBtn").addEventListener("click", () => resendEmailOtp());

  async function resendEmailOtp() {
    const { status, data } = await api("/send-email-otp");
    if (status !== 200) return toast(data.message || "Could not resend code.", "error");

    state.emailChallengeId = data.challengeId;
    const container = $('[data-otp-group="email"]');
    clearOtpBoxes(container);
    $("#emailOtpStatus").textContent = "";
    $("#emailOtpSubmit").hidden = false;
    $("#emailResendBtn").hidden = true;
    startEmailTimer(data.expiresInMs);
    startResendCooldown($("#emailResendLink"), $("#emailResendCooldown"));
    toast("A new code was sent to your email.", "success");
  }

  /* ------------------------------------------------------------------ */
  /* SCREEN: SMS OTP                                                     */
  /* ------------------------------------------------------------------ */

  let smsCountdown = null;

  function startSmsTimer(durationMs) {
    smsCountdown = makeCountdown({
      timerEl: $("#smsTimer"),
      wrapEl: $("#smsTimerWrap"),
      durationMs,
      onExpire: () => {
        $("#smsOtpStatus").textContent = "This code has expired.";
        disableOtpBoxes($('[data-otp-group="sms"]'));
        $("#smsOtpSubmit").hidden = true;
        $("#smsResendBtn").hidden = false;
      },
    });
  }

  $("#smsOtpForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const container = $('[data-otp-group="sms"]');
    const otp = getOtpValue(container);
    if (otp.length !== 6) return;

    const submitBtn = $("#smsOtpSubmit");
    setBusy(submitBtn, true);

    const { status, data } = await api("/verify-sms-otp", { challengeId: state.smsChallengeId, otp });

    setBusy(submitBtn, false);

    if (status === 200 && data.verified) {
      smsCountdown?.stop();
      $$(".otp-box", container).forEach((b) => b.classList.add("success"));
      showScreen("mfa-select");
      return;
    }

    handleOtpError(status, data, container, $("#smsOtpStatus"), {
      onMaxAttempts: () => {
        $("#smsOtpSubmit").hidden = true;
        $("#smsResendBtn").hidden = false;
      },
      onExpired: () => {
        $("#smsOtpSubmit").hidden = true;
        $("#smsResendBtn").hidden = false;
      },
    });
  });

  $("#smsResendLink").addEventListener("click", () => resendSmsOtp());
  $("#smsResendBtn").addEventListener("click", () => resendSmsOtp());

  async function resendSmsOtp() {
    const { status, data } = await api("/send-sms-otp");
    if (status !== 200) return toast(data.message || "Could not resend code.", "error");

    state.smsChallengeId = data.challengeId;
    const container = $('[data-otp-group="sms"]');
    clearOtpBoxes(container);
    $("#smsOtpStatus").textContent = "";
    $("#smsOtpSubmit").hidden = false;
    $("#smsResendBtn").hidden = true;
    startSmsTimer(data.expiresInMs);
    startResendCooldown($("#smsResendLink"), $("#smsResendCooldown"));
    toast("A new code was sent to your mobile.", "success");
  }

  $("#smsChangeNumber").addEventListener("click", () => {
    smsCountdown?.stop();
    showScreen("register");
    $("#mobile").focus();
  });

  /* ------------------------------------------------------------------ */
  /* SCREEN: MFA method select                                           */
  /* ------------------------------------------------------------------ */

  $$('input[name="mfaMethod"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      $$(".option-row").forEach((row) => row.classList.toggle("selected", row.querySelector("input").checked));
    });
  });

  $("#mfaSelectForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const method = $$('input[name="mfaMethod"]').find((r) => r.checked)?.value || "authenticator";
    state.mfaMethod = method;

    const submitBtn = $("#mfaSelectSubmit");
    setBusy(submitBtn, true);

    const { status, data } = await api("/mfa/setup", { method });

    setBusy(submitBtn, false);

    if (status !== 200) return toast(data.message || "Could not start MFA setup.", "error");

    if (method === "authenticator") {
      $("#qrImage").src = data.qrDataUrl;
      $("#setupKey").textContent = data.setupKey;
      showScreen("mfa-qr");
    } else {
      state.mfaChallengeId = data.challengeId;
      prepareMfaVerifyScreen(method, data.expiresInMs);
      showScreen("mfa-verify");
    }
  });

  $("#qrContinueBtn").addEventListener("click", () => {
    prepareMfaVerifyScreen("authenticator");
    showScreen("mfa-verify");
  });

  /* ------------------------------------------------------------------ */
  /* SCREEN: MFA verify                                                   */
  /* ------------------------------------------------------------------ */

  let mfaCountdown = null;

  function prepareMfaVerifyScreen(method, expiresInMs) {
    const container = $('[data-otp-group="mfa"]');
    buildOtpBoxes(container);
    $("#mfaOtpStatus").textContent = "";
    $("#mfaVerifySubmit").hidden = false;

    const subtitle = $("#mfaVerifySubtitle");
    const timerWrap = $("#mfaTimerWrap");
    mfaCountdown?.stop();

    if (method === "authenticator") {
      subtitle.textContent = "Enter the code from your authenticator app";
      timerWrap.hidden = true;
      $("#mfaCantAccess").textContent = "Can't access your app?";
    } else if (method === "sms") {
      subtitle.textContent = `Enter the code sent to +91 ${state.mobile}`;
      timerWrap.hidden = false;
      mfaCountdown = makeCountdown({
        timerEl: $("#mfaTimer"),
        wrapEl: timerWrap,
        durationMs: expiresInMs,
        onExpire: () => {
          $("#mfaOtpStatus").textContent = "This code has expired.";
          disableOtpBoxes(container);
          $("#mfaVerifySubmit").hidden = true;
        },
      });
      $("#mfaCantAccess").textContent = "Resend code";
    } else if (method === "email") {
      subtitle.textContent = `Enter the code sent to ${state.email}`;
      timerWrap.hidden = false;
      mfaCountdown = makeCountdown({
        timerEl: $("#mfaTimer"),
        wrapEl: timerWrap,
        durationMs: expiresInMs,
        onExpire: () => {
          $("#mfaOtpStatus").textContent = "This code has expired.";
          disableOtpBoxes(container);
          $("#mfaVerifySubmit").hidden = true;
        },
      });
      $("#mfaCantAccess").textContent = "Resend code";
    }
  }

  $("#mfaVerifyForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const container = $('[data-otp-group="mfa"]');
    const code = getOtpValue(container);
    if (code.length !== 6) return;

    const submitBtn = $("#mfaVerifySubmit");
    setBusy(submitBtn, true);

    const { status, data } = await api("/mfa/verify", {
      method: state.mfaMethod,
      code,
      challengeId: state.mfaChallengeId,
    });

    setBusy(submitBtn, false);

    if (status === 200 && data.verified) {
      mfaCountdown?.stop();
      $$(".otp-box", container).forEach((b) => b.classList.add("success"));
      setTimeout(() => showScreen("success"), 300);
      return;
    }

    handleOtpError(status, data, container, $("#mfaOtpStatus"), {
      onMaxAttempts: () => {
        $("#mfaVerifySubmit").hidden = true;
      },
      onExpired: () => {
        $("#mfaVerifySubmit").hidden = true;
      },
    });
  });

  $("#mfaCantAccess").addEventListener("click", async () => {
    if (state.mfaMethod === "authenticator") {
      // Regenerate the secret / QR and let the user re-scan.
      const { status, data } = await api("/mfa/setup", { method: "authenticator" });
      if (status !== 200) return toast("Could not regenerate setup.", "error");
      $("#qrImage").src = data.qrDataUrl;
      $("#setupKey").textContent = data.setupKey;
      showScreen("mfa-qr");
    } else {
      const { status, data } = await api("/mfa/setup", { method: state.mfaMethod });
      if (status !== 200) return toast(data.message || "Could not resend code.", "error");
      state.mfaChallengeId = data.challengeId;
      prepareMfaVerifyScreen(state.mfaMethod, data.expiresInMs);
      toast("A new code was sent.", "success");
    }
  });

  /* ------------------------------------------------------------------ */
  /* Init                                                                 */
  /* ------------------------------------------------------------------ */

  updateStepper(1);
})();
