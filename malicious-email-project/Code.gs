/**
 * Gmail contextual trigger handler.
 * Called when the user opens an email with the add-on active.
 *
 * @param {Object} e - Gmail add-on event object
 * @returns {Card} Card displaying the analysis result
 */
function onGmailMessage(e) {
  try {
    const messageId = e.gmail.messageId;
    const accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);

    const message = GmailApp.getMessageById(messageId);
    const fullMessage = Gmail.Users.Messages.get("me", messageId, { format: "full" });

    const emailData = extractEmailData_(message, fullMessage);

    const headerSignals = analyzeHeaders(emailData);
    const senderSignals = analyzeSender(emailData);
    const contentSignals = analyzeContent(emailData);
    const urlSignals = analyzeUrls(emailData);
    const attachmentSignals = analyzeAttachments(emailData);

    const allSignals = {
      headers: headerSignals,
      sender: senderSignals,
      content: contentSignals,
      urls: urlSignals,
      attachments: attachmentSignals
    };

    const result = computeScore(allSignals);

    return buildCard(result, allSignals);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

/**
 * Extracts all relevant data from a Gmail message into a flat object
 * that the analyzers can consume.
 */
function extractEmailData_(message, fullMessage) {
  const headers = {};
  if (fullMessage.payload && fullMessage.payload.headers) {
    fullMessage.payload.headers.forEach((h) => {
      const key = h.name.toLowerCase();
      if (headers[key]) {
        if (Array.isArray(headers[key])) {
          headers[key].push(h.value);
        } else {
          headers[key] = [headers[key], h.value];
        }
      } else {
        headers[key] = h.value;
      }
    });
  }

  const bodyHtml = message.getBody() || "";
  const bodyPlain = message.getPlainBody() || "";

  const attachments = message.getAttachments() || [];
  const attachmentInfo = attachments.map((att) => ({
    name: att.getName(),
    contentType: att.getContentType(),
    size: att.getSize()
  }));

  return {
    headers: headers,
    from: headers["from"] || "",
    to: headers["to"] || "",
    replyTo: headers["reply-to"] || "",
    returnPath: headers["return-path"] || "",
    subject: headers["subject"] || "",
    authenticationResults: headers["authentication-results"] || "",
    receivedSpf: headers["received-spf"] || "",
    bodyHtml: bodyHtml,
    bodyPlain: bodyPlain,
    attachments: attachmentInfo,
    date: headers["date"] || ""
  };
}
