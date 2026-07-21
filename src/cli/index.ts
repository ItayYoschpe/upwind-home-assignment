#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { analyzeEmail } from "../core/index.js";
import { parseEml } from "../parsing/emlParser.js";
import { formatReport } from "./report.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const filePath = args.find((arg) => !arg.startsWith("--"));

  if (!filePath) {
    printUsage();
    process.exitCode = 1;
    return;
  }

  const rawEmail = await readFile(filePath);
  const email = await parseEml(rawEmail);
  const result = analyzeEmail(email);

  console.log(jsonOutput ? JSON.stringify(result, null, 2) : formatReport(filePath, result));
}

function printUsage(): void {
  console.log("Usage: analyze-email <path-to-email.eml> [--json]");
}

main().catch((error: unknown) => {
  console.error(
    `Failed to analyze email: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
