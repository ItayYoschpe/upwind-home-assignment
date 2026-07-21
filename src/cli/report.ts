import type { AnalysisResult, Signal, SignalCategory } from "../core/types.js";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
};

const CATEGORY_LABELS: Record<SignalCategory, string> = {
  headers: "Authentication Headers",
  sender: "Sender Analysis",
  content: "Content Analysis",
  urls: "URL Analysis",
  attachments: "Attachment Analysis",
};

const CATEGORY_ORDER: SignalCategory[] = ["headers", "sender", "content", "urls", "attachments"];

export function formatReport(fileLabel: string, result: AnalysisResult): string {
  const lines: string[] = [];

  lines.push(`${ANSI.bold}Malicious Email Analyzer${ANSI.reset}`);
  lines.push(`File: ${fileLabel}`);
  lines.push("");
  lines.push(
    `${ANSI.bold}Score: ${result.score} / 100   [${colorizeVerdict(result.verdict)}]${ANSI.reset}`,
  );
  lines.push("");

  for (const category of CATEGORY_ORDER) {
    const signals = result.signals[category];
    lines.push(`${ANSI.bold}${CATEGORY_LABELS[category]}${ANSI.reset}`);
    if (signals.length === 0) {
      lines.push(`  ${ANSI.dim}No signals detected.${ANSI.reset}`);
    } else {
      for (const signal of signals) {
        lines.push(
          `  ${severityIcon(signal)} ${ANSI.bold}${signal.name}${ANSI.reset} - ${signal.detail}`,
        );
      }
    }
    lines.push("");
  }

  lines.push(
    `${ANSI.dim}This is a heuristic assessment, not a definitive security verdict.${ANSI.reset}`,
  );

  return lines.join("\n");
}

function colorizeVerdict(verdict: AnalysisResult["verdict"]): string {
  const color =
    verdict === "Malicious" ? ANSI.red : verdict === "Suspicious" ? ANSI.yellow : ANSI.green;
  return `${color}${verdict.toUpperCase()}${ANSI.reset}${ANSI.bold}`;
}

function severityIcon(signal: Signal): string {
  if (signal.score >= 0.7) return `${ANSI.red}\u26D4${ANSI.reset}`;
  if (signal.score >= 0.4) return `${ANSI.yellow}\u26A0${ANSI.reset}`;
  return `${ANSI.dim}\u2139${ANSI.reset}`;
}
