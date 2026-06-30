// 1. Header Analyzer - SPF, DKIM, DMARC from Authentication-Results

function analyzeHeaders(emailData) {
  const signals = [];
  let authResults = emailData.authenticationResults;
  if (Array.isArray(authResults)) {
    authResults = authResults.join(" ");
  }
  let receivedSpf = emailData.receivedSpf;
  if (Array.isArray(receivedSpf)) {
    receivedSpf = receivedSpf.join(" ");
  }

  const combined = ((authResults || "") + " " + (receivedSpf || "")).toLowerCase();

  if (!combined.trim()) {
    signals.push({
      name: "Missing authentication headers",
      score: 0.6,
      detail: "No Authentication-Results or Received-SPF headers found. " +
              "Cannot verify sender authentication."
    });
    return signals;
  }

  const checks = [
    { protocol: "SPF",  passRe: /spf=pass/i,  failRe: /spf=(fail|softfail|neutral|none|temperror|permerror)/i },
    { protocol: "DKIM", passRe: /dkim=pass/i,  failRe: /dkim=(fail|neutral|none|temperror|permerror)/i },
    { protocol: "DMARC", passRe: /dmarc=pass/i, failRe: /dmarc=(fail|none|temperror|permerror)/i }
  ];

  checks.forEach((check) => {
    if (check.passRe.test(combined)) {
      signals.push({
        name: check.protocol + " passed",
        score: 0.0,
        detail: check.protocol + " authentication passed."
      });
    } else if (check.failRe.test(combined)) {
      signals.push({
        name: check.protocol + " failed",
        score: 0.8,
        detail: check.protocol + " authentication did not pass, which may indicate spoofing."
      });
    } else {
      signals.push({
        name: check.protocol + " not found",
        score: 0.3,
        detail: check.protocol + " result not present in headers."
      });
    }
  });

  return signals;
}


// 2. Sender Analyzer

const FREE_EMAIL_PROVIDERS_ = [
  "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
  "aol.com", "icloud.com", "mail.com", "protonmail.com", "zoho.com",
  "yandex.com", "gmx.com", "live.com"
];

function analyzeSender(emailData) {
  const signals = [];
  const from = emailData.from || "";
  const parsed = parseEmailAddress_(from);

  if (parsed.displayName && parsed.address) {
    const nameLC = parsed.displayName.toLowerCase();
    const addrLC = parsed.address.toLowerCase();
    const addrLocal = addrLC.split("@")[0];
    const nameParts = nameLC.replace(/[^a-z0-9 ]/g, "").split(/\s+/);

    const nameMatchesAddr = nameParts.some((p) =>
      p.length > 2 && addrLocal.indexOf(p) !== -1
    );

    if (!nameMatchesAddr) {
      signals.push({
        name: "Display name / address mismatch",
        score: 0.4,
        detail: "Display name \"" + parsed.displayName +
                "\" does not resemble the email address <" + parsed.address + ">."
      });
    }
  }

  if (parsed.address) {
    const domain = parsed.address.split("@")[1] || "";
    const isFree = FREE_EMAIL_PROVIDERS_.indexOf(domain.toLowerCase()) !== -1;
    const bodyLC = (emailData.bodyPlain || "").toLowerCase();
    const claimsBusiness = /official|security team|billing|invoice|helpdesk|support team|IT department/i.test(bodyLC);

    if (isFree && claimsBusiness) {
      signals.push({
        name: "Free provider claiming business identity",
        score: 0.5,
        detail: "Sender uses free provider (" + domain +
                ") but email content claims to be from an official entity."
      });
    }
  }

  const replyTo = emailData.replyTo || "";
  if (replyTo) {
    const replyParsed = parseEmailAddress_(replyTo);
    if (replyParsed.address && parsed.address &&
        replyParsed.address.toLowerCase() !== parsed.address.toLowerCase()) {
      signals.push({
        name: "Reply-To mismatch",
        score: 0.5,
        detail: "Reply-To <" + replyParsed.address +
                "> differs from From <" + parsed.address + ">."
      });
    }
  }

  const returnPath = emailData.returnPath || "";
  if (returnPath && parsed.address) {
    const rpParsed = parseEmailAddress_(returnPath);
    const fromDomain = (parsed.address.split("@")[1] || "").toLowerCase();
    const rpDomain = (rpParsed.address ? rpParsed.address.split("@")[1] || "" : "").toLowerCase();
    if (rpDomain && fromDomain && rpDomain !== fromDomain) {
      signals.push({
        name: "Return-Path domain mismatch",
        score: 0.5,
        detail: "Return-Path domain (" + rpDomain +
                ") differs from From domain (" + fromDomain + ")."
      });
    }
  }

  return signals;
}

/**
 * Parses "Display Name <user@example.com>" into components.
 */
function parseEmailAddress_(raw) {
  const match = raw.match(/^(.*?)\s*<([^>]+)>/);
  if (match) {
    return {
      displayName: match[1].replace(/^["']|["']$/g, "").trim(),
      address: match[2].trim()
    };
  }
  const emailOnly = raw.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);
  return {
    displayName: "",
    address: emailOnly ? emailOnly[0] : raw.trim()
  };
}


// 3. Content Analyzer

const URGENCY_PHRASES_ = [
  "urgent", "act now", "immediate action", "click immediately",
  "verify your account", "confirm your identity", "suspended",
  "account will be closed", "unauthorized activity", "unusual sign-in",
  "reset your password", "expire", "within 24 hours", "within 48 hours",
  "final warning", "last chance", "limited time"
];

const CREDENTIAL_PHRASES_ = [
  "enter your password", "enter your credentials", "provide your password",
  "confirm your password", "verify your password", "update your payment",
  "social security number", "ssn", "credit card number", "bank account",
  "wire transfer", "send payment", "bitcoin", "cryptocurrency",
  "gift card"
];

function analyzeContent(emailData) {
  const signals = [];
  const text = (emailData.bodyPlain || "").toLowerCase();
  const html = (emailData.bodyHtml || "").toLowerCase();
  const combined = text + " " + html;

  if (!combined.trim()) {
    return signals;
  }

  const urgencyHits = [];
  URGENCY_PHRASES_.forEach((phrase) => {
    if (combined.indexOf(phrase) !== -1) {
      urgencyHits.push(phrase);
    }
  });

  if (urgencyHits.length > 0) {
    const severity = Math.min(urgencyHits.length * 0.2, 0.8);
    signals.push({
      name: "Urgency language",
      score: severity,
      detail: "Found " + urgencyHits.length + " urgency phrase(s): \"" +
              urgencyHits.slice(0, 5).join("\", \"") + "\"."
    });
  }

  const credentialHits = [];
  CREDENTIAL_PHRASES_.forEach((phrase) => {
    if (combined.indexOf(phrase) !== -1) {
      credentialHits.push(phrase);
    }
  });

  if (credentialHits.length > 0) {
    const severity = Math.min(0.4 + credentialHits.length * 0.15, 0.9);
    signals.push({
      name: "Credential / payment request",
      score: severity,
      detail: "Email asks for sensitive information: \"" +
              credentialHits.slice(0, 5).join("\", \"") + "\"."
    });
  }

  const rawBody = emailData.bodyPlain || "";
  const words = rawBody.split(/\s+/).filter((w) => w.length > 2);
  if (words.length > 10) {
    const capsWords = words.filter((w) =>
      w === w.toUpperCase() && /[A-Z]/.test(w)
    );
    const capsRatio = capsWords.length / words.length;
    if (capsRatio > 0.3) {
      signals.push({
        name: "Excessive capitalization",
        score: 0.3,
        detail: Math.round(capsRatio * 100) + "% of words are fully capitalized."
      });
    }
  }

  return signals;
}


// 4. URL Analyzer

const URL_SHORTENERS_ = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc"
];

function analyzeUrls(emailData) {
  const signals = [];
  const html = emailData.bodyHtml || "";
  const plain = emailData.bodyPlain || "";

  const links = extractLinks_(html, plain);

  if (links.length === 0) {
    return signals;
  }

  const shortenedLinks = [];
  const ipLinks = [];
  const mismatchedLinks = [];
  const punycodeLinks = [];
  const domains = {};

  links.forEach((link) => {
    const hostname = extractHostname_(link.href);

    if (hostname) {
      domains[hostname] = true;
    }

    if (isUrlShortener_(hostname)) {
      shortenedLinks.push(link.href);
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
      ipLinks.push(link.href);
    }

    if (hostname && /xn--/.test(hostname)) {
      punycodeLinks.push(link.href);
    }

    if (link.text && link.href) {
      const textHost = extractHostname_(link.text);
      if (textHost && hostname && textHost !== hostname &&
          looksLikeDomain_(textHost)) {
        mismatchedLinks.push({
          text: link.text,
          href: link.href,
          textHost: textHost,
          hrefHost: hostname
        });
      }
    }
  });

  if (mismatchedLinks.length > 0) {
    signals.push({
      name: "Link text / URL mismatch",
      score: 0.9,
      detail: mismatchedLinks.length + " link(s) where visible text shows a different domain than the actual URL. " +
              "Example: text shows \"" + mismatchedLinks[0].textHost +
              "\" but links to \"" + mismatchedLinks[0].hrefHost + "\"."
    });
  }

  if (shortenedLinks.length > 0) {
    signals.push({
      name: "URL shortener used",
      score: 0.4,
      detail: shortenedLinks.length + " shortened URL(s) detected (" +
              shortenedLinks.slice(0, 3).join(", ") + "). These hide the real destination."
    });
  }

  if (ipLinks.length > 0) {
    signals.push({
      name: "IP-address URL",
      score: 0.7,
      detail: ipLinks.length + " link(s) point to a raw IP address instead of a domain name."
    });
  }

  if (punycodeLinks.length > 0) {
    signals.push({
      name: "Internationalized (punycode) domain",
      score: 0.6,
      detail: punycodeLinks.length + " link(s) use punycode encoding, which can disguise homograph attacks."
    });
  }

  const domainCount = Object.keys(domains).length;
  if (domainCount > 5) {
    signals.push({
      name: "Many unique link domains",
      score: 0.3,
      detail: "Email contains links to " + domainCount +
              " different domains, which is unusual."
    });
  }

  return signals;
}

/**
 * Extracts links from HTML hrefs and plain-text URLs.
 * Returns array of { text, href }.
 */
function extractLinks_(html, plain) {
  const links = [];
  const seen = {};

  const hrefRe = /<a[^>]+href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = hrefRe.exec(html)) !== null) {
    const href = match[1].trim();
    const text = match[2].replace(/<[^>]+>/g, "").trim();
    if (href && !seen[href]) {
      seen[href] = true;
      links.push({ href: href, text: text });
    }
  }

  const urlRe = /https?:\/\/[^\s<>"']+/gi;
  const plainUrls = plain.match(urlRe) || [];
  plainUrls.forEach((u) => {
    if (!seen[u]) {
      seen[u] = true;
      links.push({ href: u, text: "" });
    }
  });

  return links;
}

function extractHostname_(url) {
  const m = url.match(/^https?:\/\/([^\/\?#:]+)/i);
  return m ? m[1].toLowerCase() : "";
}

function isUrlShortener_(hostname) {
  return URL_SHORTENERS_.some((s) =>
    hostname === s || hostname.endsWith("." + s)
  );
}

function looksLikeDomain_(text) {
  return /^[a-z0-9.\-]+\.[a-z]{2,}$/i.test(text);
}


// 5. Attachment Analyzer

const RISKY_EXTENSIONS_ = [
  ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".msi",
  ".com", ".pif", ".hta", ".cpl", ".wsf", ".jar",
  ".zip", ".rar", ".7z", ".gz", ".tar",
  ".docm", ".xlsm", ".pptm", ".dotm"
];

function analyzeAttachments(emailData) {
  const signals = [];
  const attachments = emailData.attachments || [];

  if (attachments.length === 0) {
    return signals;
  }

  const riskyFiles = [];
  const doubleExtFiles = [];

  attachments.forEach((att) => {
    const name = (att.name || "").toLowerCase();
    const ext = name.indexOf(".") !== -1
      ? "." + name.split(".").pop()
      : "";

    if (RISKY_EXTENSIONS_.indexOf(ext) !== -1) {
      riskyFiles.push(att.name);
    }

    const parts = name.split(".");
    if (parts.length > 2) {
      const secondToLast = "." + parts[parts.length - 2];
      if (RISKY_EXTENSIONS_.indexOf(secondToLast) !== -1 ||
          /^\.(pdf|doc|docx|xls|xlsx|txt|jpg|png)$/.test(secondToLast)) {
        doubleExtFiles.push(att.name);
      }
    }
  });

  if (doubleExtFiles.length > 0) {
    signals.push({
      name: "Double file extension",
      score: 0.9,
      detail: "File(s) with double extensions detected: " +
              doubleExtFiles.join(", ") +
              ". This is a common technique to disguise executable files."
    });
  }

  if (riskyFiles.length > 0) {
    signals.push({
      name: "Risky attachment type",
      score: 0.7,
      detail: "Potentially dangerous file type(s): " +
              riskyFiles.join(", ") + "."
    });
  }

  const bodyLC = (emailData.bodyPlain || "").toLowerCase();
  const mentionsPassword = /password[:\s]+\S|password is|the password|use password/i.test(bodyLC);
  const hasArchive = attachments.some((att) => {
    const ext = "." + (att.name || "").toLowerCase().split(".").pop();
    return [".zip", ".rar", ".7z", ".gz", ".tar"].indexOf(ext) !== -1;
  });

  if (mentionsPassword && hasArchive) {
    signals.push({
      name: "Password-protected archive pattern",
      score: 0.8,
      detail: "Email body mentions a password and includes an archive attachment. " +
              "Malware is often distributed as password-protected archives to bypass scanners."
    });
  }

  return signals;
}
