import { DEFAULT_SCORING_CONFIG, type ScoringConfig } from "./config.js";
import type { CategorizedSignals, ScoreResult, SignalCategory } from "./types.js";

/** Each additional signal within a category contributes this fraction of its score. */
const ADDITIONAL_SIGNAL_WEIGHT = 0.3;

/**
 * Computes a 0-100 maliciousness score from categorized signals.
 *
 * Within a category, the dominant (highest) signal score is taken in full
 * and each additional signal adds `ADDITIONAL_SIGNAL_WEIGHT` of its score
 * (capped at 1.0 combined). This rewards the strongest evidence in a
 * category without letting many weak, possibly-correlated signals stack
 * into an unrealistically high score on their own.
 */
export function computeScore(
  signals: CategorizedSignals,
  config: ScoringConfig = DEFAULT_SCORING_CONFIG,
): ScoreResult {
  let totalScore = 0;

  for (const [category, weight] of Object.entries(config.categoryWeights) as [
    SignalCategory,
    number,
  ][]) {
    const categorySignals = signals[category] ?? [];
    if (categorySignals.length === 0) {
      continue;
    }

    const scores = categorySignals.map((s) => s.score).sort((a, b) => b - a);
    const [dominant, ...rest] = scores;
    const combined = Math.min(
      (dominant ?? 0) + rest.reduce((sum, s) => sum + s * ADDITIONAL_SIGNAL_WEIGHT, 0),
      1,
    );

    totalScore += combined * weight * 100;
  }

  const finalScore = Math.round(Math.min(totalScore, 100));

  return {
    score: finalScore,
    verdict: resolveVerdict(finalScore, config),
  };
}

function resolveVerdict(score: number, config: ScoringConfig) {
  const match = config.verdictThresholds.find((threshold) => score >= threshold.minScore);
  return match?.verdict ?? config.verdictThresholds[config.verdictThresholds.length - 1]!.verdict;
}
