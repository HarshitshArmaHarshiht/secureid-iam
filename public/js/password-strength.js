/**
 * Password strength — the browser half.
 *
 * This is deliberately the SAME algorithm as server/lib/validate.js.
 * The browser copy exists to give instant feedback while typing; the
 * server copy is the one that actually decides. Client-side checks are
 * a convenience, never a security control — anyone can skip them by
 * calling the API directly, which is why the server re-runs them.
 *
 * Scoring, 0..6 — one point each:
 *   at least 8 characters
 *   at least 12 characters
 *   has a lowercase letter
 *   has an uppercase letter
 *   has a digit
 *   has a symbol
 *
 * Penalties:
 *   -2  three identical characters in a row   ("aaa")
 *   -2  a run of 4+ sequential characters     ("abcd", "1234")
 *   -2  built on a common word                ("Passw0rd!")  → also capped at Weak
 *
 * Buckets:  0-2 Weak · 3-4 Medium · 5-6 Strong
 */

window.PasswordStrength = (function () {
  "use strict";

  var COMMON_PATTERNS = [
    /^p[a@]ssw[o0]rd/i,
    /^qwerty/i,
    /^letmein/i,
    /^welcome/i,
    /^admin/i,
    /^iloveyou/i,
    /^abc123/i,
    /^secret/i,
    /^monkey/i,
    /^dragon/i,
  ];

  /** The four hard rules shown as the checklist under the field. */
  function checks(password) {
    password = password || "";
    return {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
    };
  }

  function allRulesPass(password) {
    var c = checks(password);
    return c.length && c.uppercase && c.number && c.special;
  }

  /** True if the string contains `len` consecutive characters: "cde", "3456". */
  function hasSequentialRun(str, len) {
    var s = (str || "").toLowerCase();
    var run = 1;
    for (var i = 1; i < s.length; i++) {
      if (s.charCodeAt(i) === s.charCodeAt(i - 1) + 1) {
        run += 1;
        if (run >= len) return true;
      } else {
        run = 1;
      }
    }
    return false;
  }

  function strength(password) {
    password = password || "";
    if (!password) return { score: 0, level: "empty", label: "", percent: 0 };

    var score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    if (/(.)\1{2,}/.test(password)) score -= 2;
    if (hasSequentialRun(password, 4)) score -= 2;

    var isCommon = COMMON_PATTERNS.some(function (re) {
      return re.test(password);
    });
    if (isCommon) score -= 2;

    if (score < 1) score = 1;
    if (score > 6) score = 6;

    // A common base word is always Weak, however much is bolted onto it.
    var level = isCommon || score <= 2 ? "weak" : score <= 4 ? "medium" : "strong";

    return {
      score: score,
      level: level,
      label: level.charAt(0).toUpperCase() + level.slice(1),
      percent: Math.round((score / 6) * 100),
    };
  }

  var RANK = { empty: 0, weak: 1, medium: 2, strong: 3 };

  /** Minimum bar to allow registration. Must match the server's default. */
  var MINIMUM = "medium";

  function meetsMinimum(password) {
    return RANK[strength(password).level] >= RANK[MINIMUM];
  }

  return {
    checks: checks,
    allRulesPass: allRulesPass,
    strength: strength,
    meetsMinimum: meetsMinimum,
    MINIMUM: MINIMUM,
  };
})();
