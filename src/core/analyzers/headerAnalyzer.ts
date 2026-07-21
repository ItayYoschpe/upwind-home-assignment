import type { HeaderValue, ParsedEmail, Signal } from "../types.js";
import { getDomain, isDomainAligned } from "../utils/email.js";

interface AuthCheck {
  protocol: "SPF" | "DKIM" | "DMARC";
  passPattern: RegExp;
  failPattern: RegExp;
}

const AUTH_CHECKS: AuthCheck[] = [
  {
    protocol: "SPF",
    passPattern: /spf=pass/i,
    failPattern: /spf=(fail|softfail|neutral|none|temperror|permerror)/i,
  },
  {
    protocol: "DKIM",
    passPattern: /dkim=pass/i,
    failPattern: /dkim=(fail|neutral|none|temperror|permerror)/i,
  },
  {
    protocol: "DMARC",
    passPattern: /dmarc=pass/i,
    failPattern: /dmarc=(fail|none|temperror|permerror)/i,
  },
];

/**
 * Authentication header analysis: SPF, DKIM, DMARC pass/fail, plus DMARC
 * "identifier alignment" - the actual mechanism DMARC uses to decide whether
 * a passing SPF/DKIM result is even meaningful. A message can pass SPF for
 * an unrelated sending domain while still spoofing the visible From address;
 * DMARC only counts a pass if the authenticated domain is aligned with the
 * From domain, so we check that explicitly rather than trusting a bare
 * `spf=pass` / `dkim=pass`.
 */
export function analyzeHeaders(email: ParsedEmail): Signal[] {
  const signals: Signal[] = [];
  const combined =
    joinHeaderValue(email.authenticationResults) + " " + joinHeaderValue(email.receivedSpf);
  const normalized = combined.toLowerCase();

  if (!normalized.trim()) {
    return [
      {
        name: "Missing authentication headers",
        score: 0.6,
        detail:
          "No Authentication-Results or Received-SPF headers found. Cannot verify sender authentication.",
      },
    ];
  }

  for (const check of AUTH_CHECKS) {
    if (check.passPattern.test(normalized)) {
      signals.push({
        name: `${check.protocol} passed`,
        score: 0,
        detail: `${check.protocol} authentication passed.`,
      });
    } else if (check.failPattern.test(normalized)) {
      signals.push({
        name: `${check.protocol} failed`,
        score: 0.8,
        detail: `${check.protocol} authentication did not pass, which may indicate spoofing.`,
      });
    } else {
      signals.push({
        name: `${check.protocol} not found`,
        score: 0.3,
        detail: `${check.protocol} result not present in headers.`,
      });
    }
  }

  const alignmentSignal = checkDmarcAlignment(email, normalized);
  if (alignmentSignal) {
    signals.push(alignmentSignal);
  }

  return signals;
}

function checkDmarcAlignment(email: ParsedEmail, normalizedAuthResults: string): Signal | null {
  const fromDomain = getDomain(email.from.match(/<([^>]+)>/)?.[1] ?? email.from);
  if (!fromDomain) {
    return null;
  }

  const dkimDomain = normalizedAuthResults.match(/dkim=pass[^;]*header\.d=([a-z0-9.-]+)/i)?.[1];

  // `smtp.mailfrom` may be a bare domain or a full `local-part@domain` address;
  // stop at the first whitespace/`;`/`)` so trailing free-text (e.g. a
  // Received-SPF comment) can't be swept into the match.
  const spfMailfrom = normalizedAuthResults.match(/spf=pass[^;]*smtp\.mailfrom=([^\s;)]+)/i)?.[1];
  const spfDomain = spfMailfrom?.includes("@") ? spfMailfrom.split("@").pop() : spfMailfrom;

  const misaligned: string[] = [];
  if (dkimDomain && !isDomainAligned(dkimDomain, fromDomain)) {
    misaligned.push(`DKIM-authenticated domain "${dkimDomain}"`);
  }
  if (spfDomain && !isDomainAligned(spfDomain, fromDomain)) {
    misaligned.push(`SPF-authenticated domain "${spfDomain}"`);
  }

  if (misaligned.length === 0) {
    return null;
  }

  return {
    name: "DMARC identifier misalignment",
    score: 0.6,
    detail:
      `${misaligned.join(" and ")} do not align with the visible From domain "${fromDomain}". ` +
      "A passing SPF or DKIM check is only meaningful if it is authenticating the domain shown to the user.",
  };
}

function joinHeaderValue(value: HeaderValue): string {
  return Array.isArray(value) ? value.join(" ") : value;
}
