import type { SignalCategory, Verdict } from "./types.js";

export interface VerdictThreshold {
  verdict: Verdict;
  minScore: number;
}

export interface ScoringConfig {
  /** Relative weight of each analyzer category. Should sum to 1.0. */
  categoryWeights: Record<SignalCategory, number>;
  /**
   * Ordered from highest to lowest `minScore`. The first threshold whose
   * `minScore` is at or below the final score wins.
   */
  verdictThresholds: VerdictThreshold[];
}

export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  categoryWeights: {
    headers: 0.25,
    sender: 0.2,
    content: 0.2,
    urls: 0.25,
    attachments: 0.1,
  },
  verdictThresholds: [
    { verdict: "Malicious", minScore: 60 },
    { verdict: "Suspicious", minScore: 30 },
    { verdict: "Safe", minScore: 0 },
  ],
};
