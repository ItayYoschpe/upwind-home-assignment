import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { analyzeEmail } from "../src/core/index.js";
import { parseEml } from "../src/parsing/emlParser.js";

const fixturesDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

async function analyzeFixture(fileName: string) {
  const raw = await readFile(path.join(fixturesDir, fileName));
  const email = await parseEml(raw);
  return analyzeEmail(email);
}

describe("end-to-end fixture analysis", () => {
  it("flags a spoofed bank phishing email as Malicious", async () => {
    const result = await analyzeFixture("phishing-bank-alert.eml");
    expect(result.verdict).toBe("Malicious");
  });

  it("flags a credential-harvesting helpdesk email as at least Suspicious", async () => {
    const result = await analyzeFixture("phishing-it-helpdesk.eml");
    expect(result.verdict).not.toBe("Safe");
  });

  it("does not flag a routine authenticated newsletter as Malicious", async () => {
    const result = await analyzeFixture("legit-newsletter.eml");
    expect(result.verdict).not.toBe("Malicious");
  });
});
