export interface ExtractedLink {
  href: string;
  text: string;
}

const HREF_PATTERN = /<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
const PLAIN_URL_PATTERN = /https?:\/\/[^\s<>"']+/gi;
const HOSTNAME_PATTERN = /^https?:\/\/([^/?#:]+)/i;

/**
 * Extracts links from HTML `href` attributes and bare URLs in plain text,
 * de-duplicating by exact URL.
 */
export function extractLinks(html: string, plainText: string): ExtractedLink[] {
  const links: ExtractedLink[] = [];
  const seen = new Set<string>();

  for (const match of html.matchAll(HREF_PATTERN)) {
    const href = (match[1] ?? "").trim();
    const text = (match[2] ?? "").replace(/<[^>]+>/g, "").trim();
    if (href && !seen.has(href)) {
      seen.add(href);
      links.push({ href, text });
    }
  }

  for (const match of plainText.matchAll(PLAIN_URL_PATTERN)) {
    const href = match[0];
    if (!seen.has(href)) {
      seen.add(href);
      links.push({ href, text: "" });
    }
  }

  return links;
}

export function extractHostname(url: string): string {
  const match = url.match(HOSTNAME_PATTERN);
  return match ? (match[1] ?? "").toLowerCase() : "";
}

export function looksLikeDomain(text: string): boolean {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text);
}
