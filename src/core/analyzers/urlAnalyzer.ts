import type { ParsedEmail, Signal } from "../types.js";
import {
  extractHostname,
  extractLinks,
  looksLikeDomain,
  type ExtractedLink,
} from "../utils/url.js";

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rb.gy",
  "cutt.ly",
  "shorturl.at",
  "tiny.cc",
];

/**
 * TLDs that are disproportionately abused for phishing and malware delivery,
 * either because they're sold for pennies with minimal vetting (`.top`,
 * `.xyz`, `.click`, `.click`) or because they collide with common file
 * extensions and trick users into treating a link as a local file
 * (`.zip`, `.mov`), a technique documented in real 2023-2024 phishing
 * campaigns after Google introduced these TLDs.
 */
const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "top",
  "xyz",
  "click",
  "country",
  "work",
  "loan",
  "men",
  "review",
]);

const IP_ADDRESS_HOST_PATTERN = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
const PUNYCODE_HOST_PATTERN = /xn--/;
const MANY_UNIQUE_DOMAINS_THRESHOLD = 5;

export function analyzeUrls(email: ParsedEmail): Signal[] {
  const links = extractLinks(email.bodyHtml, email.bodyPlain);
  if (links.length === 0) {
    return [];
  }

  const hostnames = links.map((link) => extractHostname(link.href)).filter(Boolean);
  const uniqueDomains = new Set(hostnames);

  const signals: Signal[] = [];

  const mismatchSignal = checkLinkTextMismatch(links);
  if (mismatchSignal) signals.push(mismatchSignal);

  const shortenerSignal = checkUrlShorteners(links);
  if (shortenerSignal) signals.push(shortenerSignal);

  const ipSignal = checkIpAddressLinks(links);
  if (ipSignal) signals.push(ipSignal);

  const punycodeSignal = checkPunycodeLinks(links);
  if (punycodeSignal) signals.push(punycodeSignal);

  const suspiciousTldSignal = checkSuspiciousTlds(hostnames);
  if (suspiciousTldSignal) signals.push(suspiciousTldSignal);

  if (uniqueDomains.size > MANY_UNIQUE_DOMAINS_THRESHOLD) {
    signals.push({
      name: "Many unique link domains",
      score: 0.3,
      detail: `Email contains links to ${uniqueDomains.size} different domains, which is unusual.`,
    });
  }

  return signals;
}

function checkLinkTextMismatch(links: ExtractedLink[]): Signal | null {
  const mismatches = links
    .map((link) => ({
      link,
      hostname: extractHostname(link.href),
      textHost: extractHostname(link.text) || link.text,
    }))
    .filter(
      ({ link, hostname, textHost }) =>
        link.text && link.href && hostname && textHost !== hostname && looksLikeDomain(textHost),
    );

  if (mismatches.length === 0) {
    return null;
  }

  const first = mismatches[0]!;
  return {
    name: "Link text / URL mismatch",
    score: 0.9,
    detail:
      `${mismatches.length} link(s) where visible text shows a different domain than the actual URL. ` +
      `Example: text shows "${first.textHost}" but links to "${first.hostname}".`,
  };
}

function checkUrlShorteners(links: ExtractedLink[]): Signal | null {
  const shortened = links.filter((link) => isUrlShortener(extractHostname(link.href)));
  if (shortened.length === 0) {
    return null;
  }

  return {
    name: "URL shortener used",
    score: 0.4,
    detail: `${shortened.length} shortened URL(s) detected (${shortened
      .slice(0, 3)
      .map((l) => l.href)
      .join(", ")}). These hide the real destination.`,
  };
}

function checkIpAddressLinks(links: ExtractedLink[]): Signal | null {
  const ipLinks = links.filter((link) => IP_ADDRESS_HOST_PATTERN.test(extractHostname(link.href)));
  if (ipLinks.length === 0) {
    return null;
  }

  return {
    name: "IP-address URL",
    score: 0.7,
    detail: `${ipLinks.length} link(s) point to a raw IP address instead of a domain name.`,
  };
}

function checkPunycodeLinks(links: ExtractedLink[]): Signal | null {
  const punycodeLinks = links.filter((link) =>
    PUNYCODE_HOST_PATTERN.test(extractHostname(link.href)),
  );
  if (punycodeLinks.length === 0) {
    return null;
  }

  return {
    name: "Internationalized (punycode) domain",
    score: 0.6,
    detail: `${punycodeLinks.length} link(s) use punycode encoding, which can disguise homograph attacks.`,
  };
}

function checkSuspiciousTlds(hostnames: string[]): Signal | null {
  const flagged = hostnames.filter((hostname) => {
    const tld = hostname.split(".").pop() ?? "";
    return SUSPICIOUS_TLDS.has(tld);
  });

  if (flagged.length === 0) {
    return null;
  }

  return {
    name: "Suspicious top-level domain",
    score: 0.4,
    detail: `${flagged.length} link(s) use a TLD commonly abused for phishing (${[...new Set(flagged)].join(", ")}).`,
  };
}

function isUrlShortener(hostname: string): boolean {
  return URL_SHORTENERS.some(
    (shortener) => hostname === shortener || hostname.endsWith(`.${shortener}`),
  );
}
