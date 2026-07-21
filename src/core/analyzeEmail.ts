import {
  analyzeAttachments,
  analyzeContent,
  analyzeHeaders,
  analyzeSender,
  analyzeUrls,
} from "./analyzers/index.js";
import type { ScoringConfig } from "./config.js";
import { computeScore } from "./scorer.js";
import type { AnalysisResult, ParsedEmail } from "./types.js";

/**
 * Runs every analyzer against a parsed email and combines the results into
 * a single explainable score. This is the one function a consumer (CLI,
 * Gmail add-on, HTTP handler, etc.) needs to call.
 */
export function analyzeEmail(email: ParsedEmail, config?: ScoringConfig): AnalysisResult {
  const signals = {
    headers: analyzeHeaders(email),
    sender: analyzeSender(email),
    content: analyzeContent(email),
    urls: analyzeUrls(email),
    attachments: analyzeAttachments(email),
  };

  const { score, verdict } = computeScore(signals, config);

  return { score, verdict, signals };
}
