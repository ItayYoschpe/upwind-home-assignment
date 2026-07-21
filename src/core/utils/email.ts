export interface ParsedAddress {
  displayName: string;
  address: string;
}

/**
 * Parses a raw address header like `Display Name <user@example.com>` into
 * its components. Falls back to extracting a bare email address if there is
 * no angle-bracket form, and finally to the raw string if nothing matches.
 */
export function parseEmailAddress(raw: string): ParsedAddress {
  const bracketMatch = raw.match(/^(.*?)\s*<([^>]+)>/);
  if (bracketMatch) {
    return {
      displayName: (bracketMatch[1] ?? "").replace(/^["']|["']$/g, "").trim(),
      address: (bracketMatch[2] ?? "").trim(),
    };
  }

  const bareEmailMatch = raw.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
  return {
    displayName: "",
    address: bareEmailMatch ? bareEmailMatch[0] : raw.trim(),
  };
}

export function getDomain(emailAddress: string): string {
  return (emailAddress.split("@")[1] ?? "").toLowerCase();
}

/**
 * Compares two domains for DMARC-style "relaxed" alignment: exact match, or
 * one is a subdomain of the other's organizational domain (approximated
 * here as same registrable domain - the last two labels).
 */
export function isDomainAligned(domainA: string, domainB: string): boolean {
  if (!domainA || !domainB) {
    return false;
  }
  if (domainA === domainB) {
    return true;
  }
  return organizationalDomain(domainA) === organizationalDomain(domainB);
}

function organizationalDomain(domain: string): string {
  const labels = domain.split(".");
  return labels.slice(-2).join(".");
}
