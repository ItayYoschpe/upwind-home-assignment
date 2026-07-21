import { simpleParser } from "mailparser";
import type { HeaderValue, ParsedEmail } from "../core/types.js";

/**
 * Parses a raw RFC 5322 email (a `.eml` file's contents) into the
 * `ParsedEmail` shape the analysis engine consumes.
 *
 * MIME parsing (multipart bodies, transfer encodings, attachment decoding)
 * is delegated to `mailparser` rather than hand-rolled - it's a mature,
 * widely used library and reimplementing a MIME parser would add risk
 * without adding value to this project.
 */
export async function parseEml(source: string | Buffer): Promise<ParsedEmail> {
  const parsed = await simpleParser(source);

  const headers: Record<string, HeaderValue> = {};
  for (const [key, value] of parsed.headers) {
    headers[key] = toHeaderValue(value);
  }

  return {
    headers,
    from: toSingleLine(parsed.headers.get("from")) || parsed.from?.text || "",
    to: toSingleLine(parsed.headers.get("to")),
    replyTo: toSingleLine(parsed.headers.get("reply-to")),
    returnPath: toSingleLine(parsed.headers.get("return-path")),
    subject: parsed.subject ?? "",
    authenticationResults: toHeaderValue(parsed.headers.get("authentication-results")),
    receivedSpf: toHeaderValue(parsed.headers.get("received-spf")),
    bodyHtml: typeof parsed.html === "string" ? parsed.html : "",
    bodyPlain: parsed.text ?? "",
    attachments: parsed.attachments.map((attachment) => ({
      name: attachment.filename ?? "unnamed",
      contentType: attachment.contentType,
      size: attachment.size,
    })),
    date: parsed.date ? parsed.date.toISOString() : "",
  };
}

function toHeaderValue(value: unknown): HeaderValue {
  if (value === undefined || value === null) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.map((entry) => toSingleLine(entry));
  }
  return toSingleLine(value);
}

function toSingleLine(value: unknown): string {
  if (value === undefined || value === null) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Array.isArray(value)) {
    return value.map((entry) => toSingleLine(entry)).join(", ");
  }
  if (
    typeof value === "object" &&
    "text" in value &&
    typeof (value as { text: unknown }).text === "string"
  ) {
    return (value as { text: string }).text;
  }
  return String(value);
}
