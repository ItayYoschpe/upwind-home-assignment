const CATEGORY_LABELS_ = {
  headers:     "Authentication Headers",
  sender:      "Sender Analysis",
  content:     "Content Analysis",
  urls:        "URL Analysis",
  attachments: "Attachment Analysis"
};

/**
 * Builds the main add-on Card displaying score, verdict, and signals.
 */
function buildCard(result, allSignals) {
  const card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Malicious Email Scorer")
      .setSubtitle("Heuristic risk assessment")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl("https://www.gstatic.com/images/icons/material/system/1x/security_white_48dp.png")
  );

  // --- Score and verdict section ---
  const scoreSection = CardService.newCardSection();

  const verdictColor = getVerdictColor_(result.verdict);
  const scoreText = "<b>Score: " + result.score + " / 100</b>";
  const verdictText = "<font color=\"" + verdictColor + "\"><b>" +
                    result.verdict.toUpperCase() + "</b></font>";

  scoreSection.addWidget(
    CardService.newDecoratedText()
      .setText(scoreText)
      .setBottomLabel(verdictText)
      .setWrapText(true)
  );

  scoreSection.addWidget(
    CardService.newTextParagraph()
      .setText(getVerdictDescription_(result.verdict))
  );

  card.addSection(scoreSection);

  // --- Signal breakdown sections ---
  const categoryOrder = ["headers", "sender", "content", "urls", "attachments"];

  categoryOrder.forEach((category) => {
    const signals = allSignals[category] || [];
    const section = CardService.newCardSection()
      .setHeader(CATEGORY_LABELS_[category]);

    if (signals.length === 0) {
      section.addWidget(
        CardService.newTextParagraph()
          .setText("<i>No signals detected.</i>")
      );
    } else {
      signals.forEach((signal) => {
        const icon = signalSeverityIcon_(signal.score);
        section.addWidget(
          CardService.newDecoratedText()
            .setTopLabel(icon + " " + signal.name)
            .setText(signal.detail)
            .setWrapText(true)
        );
      });
    }

    section.setCollapsible(true);
    section.setNumUncollapsibleWidgets(0);
    card.addSection(section);
  });

  // --- Disclaimer ---
  const disclaimerSection = CardService.newCardSection();
  disclaimerSection.addWidget(
    CardService.newTextParagraph()
      .setText("<i>This is a heuristic assessment, not a definitive security verdict. " +
               "Use your judgment for any action taken on this email.</i>")
  );
  card.addSection(disclaimerSection);

  return card.build();
}

/**
 * Builds an error card shown when analysis fails.
 */
function buildErrorCard(errorMessage) {
  const card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Malicious Email Scorer")
      .setSubtitle("Error")
  );

  const section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph()
      .setText("An error occurred during analysis:\n\n" + errorMessage)
  );
  card.addSection(section);

  return card.build();
}

function getVerdictColor_(verdict) {
  switch (verdict) {
    case "Safe":       return "#1e8e3e";
    case "Suspicious": return "#e37400";
    case "Malicious":  return "#d93025";
    default:           return "#5f6368";
  }
}

function getVerdictDescription_(verdict) {
  switch (verdict) {
    case "Safe":
      return "No significant risk indicators found. " +
             "The email appears legitimate based on the analyzed signals.";
    case "Suspicious":
      return "Some risk indicators detected. " +
             "Review the signals below before trusting this email.";
    case "Malicious":
      return "Multiple high-risk indicators detected. " +
             "This email shows strong signs of being malicious.";
    default:
      return "";
  }
}

function signalSeverityIcon_(score) {
  if (score >= 0.7) return "\u26D4";  // no entry
  if (score >= 0.4) return "\u26A0";  // warning
  return "\u2139";                     // info
}
