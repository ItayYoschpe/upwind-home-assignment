export { analyzeEmail } from "./analyzeEmail.js";
export { computeScore } from "./scorer.js";
export { DEFAULT_SCORING_CONFIG } from "./config.js";
export type { ScoringConfig, VerdictThreshold } from "./config.js";
export * from "./analyzers/index.js";
export type {
  AnalysisResult,
  AttachmentInfo,
  CategorizedSignals,
  HeaderValue,
  ParsedEmail,
  ScoreResult,
  Signal,
  SignalCategory,
  Verdict,
} from "./types.js";
export { SIGNAL_CATEGORIES } from "./types.js";
