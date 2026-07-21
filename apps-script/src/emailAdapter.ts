import type { AttachmentInfo, HeaderValue, ParsedEmail } from "../../src/core/types.js";

interface GmailApiHeader {
  name?: string;
  value?: string;
}

/** Minimal shape of the Gmail Advanced Service `Messages.get` response we rely on. */
export interface GmailApiMessage {
  payload?: {
    headers?: GmailApiHeader[];
  };
}

/**
 * Maps a Gmail message (from `GmailApp` and the Gmail Advanced Service)
 * into the source-agnostic `ParsedEmail` shape the core analysis engine
 * expects. This is the only place in the add-on that touches Gmail-specific
 * APIs - everything downstream is the same engine that powers this add-on.
 */
export function extractEmailData(
  message: GoogleAppsScript.Gmail.GmailMessage,
  fullMessage: GmailApiMessage,
): ParsedEmail {
  const headers = collectHeaders(fullMessage.payload?.headers ?? []);

  const attachments: AttachmentInfo[] = message.getAttachments().map((attachment) => ({
    name: attachment.getName(),
    contentType: attachment.getContentType(),
    size: attachment.getSize(),
  }));

  return {
    headers,
    from: asSingleString(headers["from"]),
    to: asSingleString(headers["to"]),
    replyTo: asSingleString(headers["reply-to"]),
    returnPath: asSingleString(headers["return-path"]),
    subject: asSingleString(headers["subject"]),
    authenticationResults: headers["authentication-results"] ?? "",
    receivedSpf: headers["received-spf"] ?? "",
    bodyHtml: message.getBody() ?? "",
    bodyPlain: message.getPlainBody() ?? "",
    attachments,
    date: asSingleString(headers["date"]),
  };
}

function collectHeaders(rawHeaders: GmailApiHeader[]): Record<string, HeaderValue> {
  const headers: Record<string, HeaderValue> = {};

  for (const header of rawHeaders) {
    if (!header.name || header.value === undefined) {
      continue;
    }

    const key = header.name.toLowerCase();
    const existing = headers[key];

    if (existing === undefined) {
      headers[key] = header.value;
    } else if (Array.isArray(existing)) {
      existing.push(header.value);
    } else {
      headers[key] = [existing, header.value];
    }
  }

  return headers;
}

function asSingleString(value: HeaderValue | undefined): string {
  if (value === undefined) {
    return "";
  }
  return Array.isArray(value) ? (value[0] ?? "") : value;
}
