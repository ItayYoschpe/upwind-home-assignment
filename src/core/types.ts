/**
 * A single or multi-valued raw header, mirroring how a message can legally
 * carry the same header name more than once (e.g. multiple `Received-SPF`
 * hops).
 */
export type HeaderValue = string | string[];

export interface AttachmentInfo {
  name: string;
  contentType: string;
  size: number;
}

/**
 * The normalized shape every analyzer operates on. This is intentionally
 * decoupled from any specific mail source (Gmail API, raw .eml, etc.) so the
 * analysis engine has no runtime dependency on where the email came from.
 */
export interface ParsedEmail {
  headers: Record<string, HeaderValue>;
  from: string;
  to: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  authenticationResults: HeaderValue;
  receivedSpf: HeaderValue;
  bodyHtml: string;
  bodyPlain: string;
  attachments: AttachmentInfo[];
  date: string;
}

/**
 * A single risk indicator produced by an analyzer.
 *
 * `score` is normalized to 0.0-1.0 so analyzers never need to know about the
 * final 0-100 scale or category weights - that's the scorer's job.
 */
export interface Signal {
  name: string;
  score: number;
  detail: string;
}

export const SIGNAL_CATEGORIES = ["headers", "sender", "content", "urls", "attachments"] as const;

export type SignalCategory = (typeof SIGNAL_CATEGORIES)[number];

export type CategorizedSignals = Record<SignalCategory, Signal[]>;

export type Verdict = "Safe" | "Suspicious" | "Malicious";

export interface ScoreResult {
  score: number;
  verdict: Verdict;
}

export interface AnalysisResult extends ScoreResult {
  signals: CategorizedSignals;
}
