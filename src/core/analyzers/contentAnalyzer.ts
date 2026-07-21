import type { ParsedEmail, Signal } from "../types.js";

const URGENCY_PHRASES = [
  "urgent",
  "act now",
  "immediate action",
  "click immediately",
  "verify your account",
  "confirm your identity",
  "suspended",
  "account will be closed",
  "unauthorized activity",
  "unusual sign-in",
  "reset your password",
  "expire",
  "within 24 hours",
  "within 48 hours",
  "final warning",
  "last chance",
  "limited time",
];

const CREDENTIAL_REQUEST_PHRASES = [
  "enter your password",
  "enter your credentials",
  "provide your password",
  "confirm your password",
  "verify your password",
  "update your payment",
  "social security number",
  "ssn",
  "credit card number",
  "bank account",
  "wire transfer",
  "send payment",
  "bitcoin",
  "cryptocurrency",
  "gift card",
];

const MIN_WORDS_FOR_CAPS_CHECK = 10;
const EXCESSIVE_CAPS_RATIO = 0.3;

export function analyzeContent(email: ParsedEmail): Signal[] {
  const combinedText = `${email.bodyPlain} ${email.bodyHtml}`.toLowerCase();
  if (!combinedText.trim()) {
    return [];
  }

  const signals: Signal[] = [];

  const urgencySignal = checkPhraseList(
    combinedText,
    URGENCY_PHRASES,
    "Urgency language",
    (count) => Math.min(count * 0.2, 0.8),
  );
  if (urgencySignal) signals.push(urgencySignal);

  const credentialSignal = checkPhraseList(
    combinedText,
    CREDENTIAL_REQUEST_PHRASES,
    "Credential / payment request",
    (count) => Math.min(0.4 + count * 0.15, 0.9),
    "Email asks for sensitive information",
  );
  if (credentialSignal) signals.push(credentialSignal);

  const capsSignal = checkExcessiveCapitalization(email.bodyPlain);
  if (capsSignal) signals.push(capsSignal);

  return signals;
}

function checkPhraseList(
  combinedText: string,
  phrases: string[],
  signalName: string,
  scoreFromHitCount: (count: number) => number,
  detailPrefix = "Found",
): Signal | null {
  const hits = phrases.filter((phrase) => combinedText.includes(phrase));
  if (hits.length === 0) {
    return null;
  }

  const preview = hits.slice(0, 5).join('", "');
  const detail =
    detailPrefix === "Found"
      ? `Found ${hits.length} urgency phrase(s): "${preview}".`
      : `${detailPrefix}: "${preview}".`;

  return {
    name: signalName,
    score: scoreFromHitCount(hits.length),
    detail,
  };
}

function checkExcessiveCapitalization(bodyPlain: string): Signal | null {
  const words = bodyPlain.split(/\s+/).filter((word) => word.length > 2);
  if (words.length <= MIN_WORDS_FOR_CAPS_CHECK) {
    return null;
  }

  const capsWordCount = words.filter(
    (word) => word === word.toUpperCase() && /[A-Z]/.test(word),
  ).length;
  const capsRatio = capsWordCount / words.length;
  if (capsRatio <= EXCESSIVE_CAPS_RATIO) {
    return null;
  }

  return {
    name: "Excessive capitalization",
    score: 0.3,
    detail: `${Math.round(capsRatio * 100)}% of words are fully capitalized.`,
  };
}
