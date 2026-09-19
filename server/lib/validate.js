const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MOBILE_RE = /^[6-9]\d{9}$/; // 10-digit Indian mobile, matches the mock's +91 field

/**
 * The four hard requirements shown as the checklist in the UI.
 * All four must pass before an account can be created.
 */
function passwordChecks(password = "") {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
  };
}

function passwordIsValid(password) {
  const c = passwordChecks(password);
  return c.length && c.uppercase && c.number && c.special;
}

/**
 * Password strength — scored 0..6, bucketed into weak / medium / strong.
 *
 * Kept as plain arithmetic on purpose (no zxcvbn, no dependency): the
 * whole rule set is readable in one screen and easy to defend out loud.
 *
 * Points earned:
 *   +1  at least 8 characters
 *   +1  at least 12 characters
 *   +1  has a lowercase letter
 *   +1  has an uppercase letter
 *   +1  has a digit
 *   +1  has a symbol
 *
 * Penalties (applied after, floored at 1 so a non-empty password never
 * scores 0 and silently looks like "empty"):
 *   -2  three or more of the same character in a row  ("aaa")
 *   -2  a run of 4+ sequential characters             ("abcd", "1234")
 *   -2  matches a common-password pattern             ("password1!")
 *
 * Buckets:  0-2 weak · 3-4 medium · 5-6 strong
 */
const COMMON_PATTERNS = [
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

function passwordStrength(password = "") {
  if (!password) {
    return { score: 0, level: "empty", label: "", percent: 0 };
  }

  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  if (/(.)\1{2,}/.test(password)) score -= 2;
  if (hasSequentialRun(password, 4)) score -= 2;

  // A common base word is always weak, whatever else is bolted on.
  // "Passw0rd!" satisfies all four rules and is still one of the most
  // guessed passwords there is, so it is capped rather than just docked.
  const isCommon = COMMON_PATTERNS.some((re) => re.test(password));
  if (isCommon) score -= 2;

  score = Math.max(1, Math.min(6, score));

  const level = isCommon ? "weak" : score <= 2 ? "weak" : score <= 4 ? "medium" : "strong";
  const label = level.charAt(0).toUpperCase() + level.slice(1);

  return { score, level, label, percent: Math.round((score / 6) * 100) };
}

/** True if the string contains `len` consecutive characters, e.g. "cde" or "3456". */
function hasSequentialRun(str, len) {
  const s = str.toLowerCase();
  let run = 1;
  for (let i = 1; i < s.length; i++) {
    if (s.charCodeAt(i) === s.charCodeAt(i - 1) + 1) {
      run += 1;
      if (run >= len) return true;
    } else {
      run = 1;
    }
  }
  return false;
}

/**
 * Minimum strength a new account must reach.
 * "medium" by default — the four hard rules already force a decent
 * password, so demanding "strong" would reject reasonable choices.
 */
const MIN_STRENGTH_LEVEL = process.env.MIN_PASSWORD_STRENGTH || "medium";
const LEVEL_RANK = { empty: 0, weak: 1, medium: 2, strong: 3 };

function meetsMinimumStrength(password) {
  return LEVEL_RANK[passwordStrength(password).level] >= LEVEL_RANK[MIN_STRENGTH_LEVEL];
}

function validateRegistration({ fullName, email, mobile, password }) {
  const errors = {};

  if (!fullName || !String(fullName).trim()) {
    errors.fullName = "Full name is required.";
  } else if (String(fullName).trim().length > 100) {
    errors.fullName = "Full name is too long.";
  }

  if (!email || !EMAIL_RE.test(String(email).trim())) {
    errors.email = "Enter a valid email address.";
  }

  if (!mobile || !MOBILE_RE.test(String(mobile).trim())) {
    errors.mobile = "Enter a valid 10-digit mobile number.";
  }

  if (!passwordIsValid(password)) {
    errors.password =
      "Password must be at least 8 characters and include an uppercase letter, a number, and a special character.";
  } else if (!meetsMinimumStrength(password)) {
    errors.password = `Password is too weak. Aim for at least ${MIN_STRENGTH_LEVEL} strength.`;
  } else if (String(password).length > 200) {
    // bcrypt only reads the first 72 bytes; cap the input so a huge body
    // cannot be used to burn CPU.
    errors.password = "Password is too long.";
  }

  return { valid: Object.keys(errors).length === 0, errors };
}

module.exports = {
  EMAIL_RE,
  MOBILE_RE,
  passwordChecks,
  passwordIsValid,
  passwordStrength,
  meetsMinimumStrength,
  MIN_STRENGTH_LEVEL,
  validateRegistration,
};
