import { analyzeEmail } from "../../src/core/index.js";
import { buildCard, buildErrorCard } from "./cardBuilder.js";
import { extractEmailData } from "./emailAdapter.js";

interface GmailAddOnEvent {
  gmail: {
    messageId: string;
    accessToken: string;
  };
}

/**
 * Gmail contextual trigger entry point, registered in `appsscript.json`.
 * This is the add-on's main entry point: it fetches the open message,
 * delegates all analysis to the shared core engine (`src/core`), and
 * renders the result as a Card in the Gmail sidebar.
 */
function onGmailMessage(e: GmailAddOnEvent): GoogleAppsScript.Card_Service.Card {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

    const message = GmailApp.getMessageById(e.gmail.messageId);
    // Gmail.Users.Messages is always defined once the Gmail advanced service
    // is enabled in appsscript.json, but its generated types mark it optional.
    const fullMessage = Gmail.Users!.Messages!.get("me", e.gmail.messageId, { format: "full" });

    const email = extractEmailData(message, fullMessage);
    const result = analyzeEmail(email);

    return buildCard(result);
  } catch (error) {
    return buildErrorCard(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Apps Script's trigger dispatcher resolves handler functions by name on
 * the global object. Bundling this file with esbuild wraps everything in
 * an IIFE, which would otherwise hide `onGmailMessage` inside a closure -
 * so it's republished on `globalThis` explicitly after bundling.
 */
(globalThis as Record<string, unknown>).onGmailMessage = onGmailMessage;
