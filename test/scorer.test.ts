import { describe, expect, it } from "vitest";
import { computeScore } from "../src/core/scorer.js";
import type { CategorizedSignals } from "../src/core/types.js";

function emptySignals(): CategorizedSignals {
  return { headers: [], sender: [], content: [], urls: [], attachments: [] };
}

describe("computeScore", () => {
  it("returns a Safe verdict when there are no signals", () => {
    expect(computeScore(emptySignals())).toEqual({ score: 0, verdict: "Safe" });
  });

  it("takes the dominant signal plus a fraction of additional signals within a category", () => {
    const signals = emptySignals();
    signals.urls = [
      { name: "a", score: 0.9, detail: "" },
      { name: "b", score: 0.5, detail: "" },
    ];

    // dominant 0.9 + (0.5 * 0.3) = 1.05, capped at 1.0 -> 1.0 * 0.25 weight * 100 = 25
    expect(computeScore(signals)).toEqual({ score: 25, verdict: "Safe" });
  });

  it("classifies a high combined score across categories as Malicious", () => {
    const signals = emptySignals();
    signals.headers = [{ name: "SPF failed", score: 0.8, detail: "" }];
    signals.content = [{ name: "Urgency language", score: 0.95, detail: "" }];
    signals.urls = [{ name: "Link text / URL mismatch", score: 0.9, detail: "" }];

    expect(computeScore(signals).verdict).toBe("Malicious");
  });
});
