import { describe, expect, it } from "vitest";
import { analyzeAttachments } from "../src/core/analyzers/attachmentAnalyzer.js";
import { analyzeHeaders } from "../src/core/analyzers/headerAnalyzer.js";
import { analyzeUrls } from "../src/core/analyzers/urlAnalyzer.js";
import type { ParsedEmail } from "../src/core/types.js";

function baseEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    headers: {},
    from: "",
    to: "",
    replyTo: "",
    returnPath: "",
    subject: "",
    authenticationResults: "",
    receivedSpf: "",
    bodyHtml: "",
    bodyPlain: "",
    attachments: [],
    date: "",
    ...overrides,
  };
}

describe("analyzeHeaders", () => {
  it("flags missing authentication headers", () => {
    const signals = analyzeHeaders(baseEmail());
    expect(signals).toEqual([expect.objectContaining({ name: "Missing authentication headers" })]);
  });

  it("flags DMARC identifier misalignment even when SPF/DKIM report a pass", () => {
    const signals = analyzeHeaders(
      baseEmail({
        from: "Support <support@legit-bank.com>",
        authenticationResults:
          "spf=pass smtp.mailfrom=attacker.com; dkim=pass header.d=attacker.com",
      }),
    );

    expect(signals.some((signal) => signal.name === "DMARC identifier misalignment")).toBe(true);
  });
});

describe("analyzeUrls", () => {
  it("detects link text / URL domain mismatch", () => {
    const html = '<a href="http://evil.example.net/login">https://bank.com/login</a>';
    const signals = analyzeUrls(baseEmail({ bodyHtml: html }));

    expect(signals.some((signal) => signal.name === "Link text / URL mismatch")).toBe(true);
  });

  it("flags suspicious top-level domains", () => {
    const html = '<a href="http://free-prize.top/claim">claim</a>';
    const signals = analyzeUrls(baseEmail({ bodyHtml: html }));

    expect(signals.some((signal) => signal.name === "Suspicious top-level domain")).toBe(true);
  });
});

describe("analyzeAttachments", () => {
  it("flags right-to-left override filename spoofing", () => {
    const signals = analyzeAttachments(
      baseEmail({
        attachments: [
          { name: "invoice\u202Ecod.exe", contentType: "application/octet-stream", size: 1 },
        ],
      }),
    );

    expect(signals.some((signal) => signal.name === "Unicode filename spoofing")).toBe(true);
  });
});
