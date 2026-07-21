import type { ParsedEmail, Signal } from "../types.js";
import { getDomain, parseEmailAddress } from "../utils/email.js";

const FREE_EMAIL_PROVIDERS = new Set([
  "gmail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "hotmail.com",
  "outlook.com",
  "aol.com",
  "icloud.com",
  "mail.com",
  "protonmail.com",
  "zoho.com",
  "yandex.com",
  "gmx.com",
  "live.com",
]);

const CLAIMS_BUSINESS_IDENTITY =
  /official|security team|billing|invoice|helpdesk|support team|IT department/i;

export function analyzeSender(email: ParsedEmail): Signal[] {
  const signals: Signal[] = [];
  const from = parseEmailAddress(email.from);

  const nameMismatch = checkDisplayNameMismatch(from);
  if (nameMismatch) signals.push(nameMismatch);

  const freeProviderSignal = checkFreeProviderClaimingBusiness(from, email.bodyPlain);
  if (freeProviderSignal) signals.push(freeProviderSignal);

  const replyToSignal = checkReplyToMismatch(from, email.replyTo);
  if (replyToSignal) signals.push(replyToSignal);

  const returnPathSignal = checkReturnPathMismatch(from, email.returnPath);
  if (returnPathSignal) signals.push(returnPathSignal);

  return signals;
}

function checkDisplayNameMismatch(from: ReturnType<typeof parseEmailAddress>): Signal | null {
  if (!from.displayName || !from.address) {
    return null;
  }

  const addressLocalPart = from.address.toLowerCase().split("@")[0] ?? "";
  const nameParts = from.displayName
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, "")
    .split(/\s+/);

  const nameMatchesAddress = nameParts.some(
    (part) => part.length > 2 && addressLocalPart.includes(part),
  );
  if (nameMatchesAddress) {
    return null;
  }

  return {
    name: "Display name / address mismatch",
    score: 0.4,
    detail: `Display name "${from.displayName}" does not resemble the email address <${from.address}>.`,
  };
}

function checkFreeProviderClaimingBusiness(
  from: ReturnType<typeof parseEmailAddress>,
  bodyPlain: string,
): Signal | null {
  if (!from.address) {
    return null;
  }

  const domain = getDomain(from.address);
  const isFreeProvider = FREE_EMAIL_PROVIDERS.has(domain);
  const claimsBusiness = CLAIMS_BUSINESS_IDENTITY.test(bodyPlain);

  if (!isFreeProvider || !claimsBusiness) {
    return null;
  }

  return {
    name: "Free provider claiming business identity",
    score: 0.5,
    detail: `Sender uses free provider (${domain}) but email content claims to be from an official entity.`,
  };
}

function checkReplyToMismatch(
  from: ReturnType<typeof parseEmailAddress>,
  replyTo: string,
): Signal | null {
  if (!replyTo || !from.address) {
    return null;
  }

  const replyToParsed = parseEmailAddress(replyTo);
  if (
    !replyToParsed.address ||
    replyToParsed.address.toLowerCase() === from.address.toLowerCase()
  ) {
    return null;
  }

  return {
    name: "Reply-To mismatch",
    score: 0.5,
    detail: `Reply-To <${replyToParsed.address}> differs from From <${from.address}>.`,
  };
}

function checkReturnPathMismatch(
  from: ReturnType<typeof parseEmailAddress>,
  returnPath: string,
): Signal | null {
  if (!returnPath || !from.address) {
    return null;
  }

  const returnPathDomain = getDomain(parseEmailAddress(returnPath).address);
  const fromDomain = getDomain(from.address);
  if (!returnPathDomain || !fromDomain || returnPathDomain === fromDomain) {
    return null;
  }

  return {
    name: "Return-Path domain mismatch",
    score: 0.5,
    detail: `Return-Path domain (${returnPathDomain}) differs from From domain (${fromDomain}).`,
  };
}
