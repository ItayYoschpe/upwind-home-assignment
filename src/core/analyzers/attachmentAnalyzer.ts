import type { AttachmentInfo, ParsedEmail, Signal } from "../types.js";

const RISKY_EXTENSIONS = new Set([
  ".exe",
  ".scr",
  ".js",
  ".vbs",
  ".bat",
  ".cmd",
  ".ps1",
  ".msi",
  ".com",
  ".pif",
  ".hta",
  ".cpl",
  ".wsf",
  ".jar",
  ".zip",
  ".rar",
  ".7z",
  ".gz",
  ".tar",
  ".docm",
  ".xlsm",
  ".pptm",
  ".dotm",
]);

const ARCHIVE_EXTENSIONS = new Set([".zip", ".rar", ".7z", ".gz", ".tar"]);
const COMMON_BENIGN_EXTENSIONS = new Set([
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".txt",
  ".jpg",
  ".png",
]);
const MENTIONS_PASSWORD_PATTERN = /password[:\s]+\S|password is|the password|use password/i;

/**
 * Unicode bidirectional-control characters used in the "RLO" (right-to-left
 * override) filename spoofing technique: an attacker inserts U+202E before
 * a reversed extension so `"gpj.exe"` renders on screen as `"exe.jpg"`. This
 * has been used in real malware campaigns (e.g. Sathurbot, various Locky
 * spam waves) to defeat visual extension checks.
 */
const BIDI_CONTROL_CHARS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/;

export function analyzeAttachments(email: ParsedEmail): Signal[] {
  const attachments = email.attachments;
  if (attachments.length === 0) {
    return [];
  }

  const signals: Signal[] = [];

  const rloSignal = checkRightToLeftOverride(attachments);
  if (rloSignal) signals.push(rloSignal);

  const doubleExtensionSignal = checkDoubleExtensions(attachments);
  if (doubleExtensionSignal) signals.push(doubleExtensionSignal);

  const riskyTypeSignal = checkRiskyExtensions(attachments);
  if (riskyTypeSignal) signals.push(riskyTypeSignal);

  const passwordArchiveSignal = checkPasswordProtectedArchivePattern(attachments, email.bodyPlain);
  if (passwordArchiveSignal) signals.push(passwordArchiveSignal);

  return signals;
}

function checkRightToLeftOverride(attachments: AttachmentInfo[]): Signal | null {
  const spoofedNames = attachments
    .filter((att) => BIDI_CONTROL_CHARS.test(att.name))
    .map((att) => att.name);
  if (spoofedNames.length === 0) {
    return null;
  }

  return {
    name: "Unicode filename spoofing",
    score: 0.95,
    detail: `File name(s) contain right-to-left override characters used to disguise the real file extension: ${spoofedNames.join(", ")}.`,
  };
}

function checkDoubleExtensions(attachments: AttachmentInfo[]): Signal | null {
  const flagged = attachments
    .filter((att) => {
      const parts = att.name.toLowerCase().split(".");
      if (parts.length <= 2) return false;
      const secondToLastExt = `.${parts[parts.length - 2]}`;
      return RISKY_EXTENSIONS.has(secondToLastExt) || COMMON_BENIGN_EXTENSIONS.has(secondToLastExt);
    })
    .map((att) => att.name);

  if (flagged.length === 0) {
    return null;
  }

  return {
    name: "Double file extension",
    score: 0.9,
    detail: `File(s) with double extensions detected: ${flagged.join(", ")}. This is a common technique to disguise executable files.`,
  };
}

function checkRiskyExtensions(attachments: AttachmentInfo[]): Signal | null {
  const flagged = attachments
    .filter((att) => RISKY_EXTENSIONS.has(getExtension(att.name)))
    .map((att) => att.name);
  if (flagged.length === 0) {
    return null;
  }

  return {
    name: "Risky attachment type",
    score: 0.7,
    detail: `Potentially dangerous file type(s): ${flagged.join(", ")}.`,
  };
}

function checkPasswordProtectedArchivePattern(
  attachments: AttachmentInfo[],
  bodyPlain: string,
): Signal | null {
  const mentionsPassword = MENTIONS_PASSWORD_PATTERN.test(bodyPlain.toLowerCase());
  const hasArchive = attachments.some((att) => ARCHIVE_EXTENSIONS.has(getExtension(att.name)));

  if (!mentionsPassword || !hasArchive) {
    return null;
  }

  return {
    name: "Password-protected archive pattern",
    score: 0.8,
    detail:
      "Email body mentions a password and includes an archive attachment. Malware is often distributed as password-protected archives to bypass scanners.",
  };
}

function getExtension(fileName: string): string {
  const lower = fileName.toLowerCase();
  return lower.includes(".") ? `.${lower.split(".").pop()}` : "";
}
