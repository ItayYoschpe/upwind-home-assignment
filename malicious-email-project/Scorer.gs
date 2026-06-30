const CATEGORY_WEIGHTS_ = {
  headers:     0.25,
  sender:      0.20,
  content:     0.20,
  urls:        0.25,
  attachments: 0.10
};

const VERDICTS_ = {
  SAFE:       { label: "Safe",       minScore: 0,  maxScore: 29 },
  SUSPICIOUS: { label: "Suspicious", minScore: 30, maxScore: 59 },
  MALICIOUS:  { label: "Malicious",  minScore: 60, maxScore: 100 }
};

/**
 * Computes a 0-100 maliciousness score from categorized signals.
 *
 * Each category's worst-case contribution is its weight * 100.
 * Within a category, individual signal scores (0.0-1.0) are combined
 * by taking the maximum (dominant signal) plus a smaller additive
 * contribution from remaining signals, to avoid unbounded stacking.
 *
 * @param {Object} allSignals - { headers: [...], sender: [...], ... }
 * @returns {Object} { score, verdict, verdictLabel }
 */
function computeScore(allSignals) {
  let totalScore = 0;

  Object.keys(CATEGORY_WEIGHTS_).forEach((category) => {
    const weight = CATEGORY_WEIGHTS_[category];
    const signals = allSignals[category] || [];

    if (signals.length === 0) {
      return;
    }

    const scores = signals
      .map((s) => s.score || 0)
      .sort((a, b) => b - a);

    // Dominant signal + 30% of each additional signal, capped at 1.0
    let combined = scores[0];
    for (let i = 1; i < scores.length; i++) {
      combined += scores[i] * 0.3;
    }
    combined = Math.min(combined, 1.0);

    totalScore += combined * weight * 100;
  });

  const finalScore = Math.round(Math.min(totalScore, 100));

  let verdictLabel;
  if (finalScore >= VERDICTS_.MALICIOUS.minScore) {
    verdictLabel = VERDICTS_.MALICIOUS.label;
  } else if (finalScore >= VERDICTS_.SUSPICIOUS.minScore) {
    verdictLabel = VERDICTS_.SUSPICIOUS.label;
  } else {
    verdictLabel = VERDICTS_.SAFE.label;
  }

  return {
    score: finalScore,
    verdict: verdictLabel
  };
}
