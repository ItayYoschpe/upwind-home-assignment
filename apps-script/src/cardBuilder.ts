import type { AnalysisResult, Signal, SignalCategory, Verdict } from "../../src/core/types.js";

const CATEGORY_LABELS: Record<SignalCategory, string> = {
  headers: "Authentication Headers",
  sender: "Sender Analysis",
  content: "Content Analysis",
  urls: "URL Analysis",
  attachments: "Attachment Analysis",
};

const CATEGORY_ORDER: SignalCategory[] = ["headers", "sender", "content", "urls", "attachments"];

export function buildCard(result: AnalysisResult): GoogleAppsScript.Card_Service.Card {
  const card = CardService.newCardBuilder();

  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Malicious Email Scorer")
      .setSubtitle("Heuristic risk assessment")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
      .setImageUrl(
        "https://www.gstatic.com/images/icons/material/system/1x/security_white_48dp.png",
      ),
  );

  card.addSection(buildScoreSection(result));
  for (const category of CATEGORY_ORDER) {
    card.addSection(buildCategorySection(category, result.signals[category]));
  }
  card.addSection(buildDisclaimerSection());

  return card.build();
}

export function buildErrorCard(errorMessage: string): GoogleAppsScript.Card_Service.Card {
  const card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader().setTitle("Malicious Email Scorer").setSubtitle("Error"),
  );
  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        `An error occurred during analysis:\n\n${errorMessage}`,
      ),
    ),
  );
  return card.build();
}

function buildScoreSection(result: AnalysisResult): GoogleAppsScript.Card_Service.CardSection {
  const section = CardService.newCardSection();

  section.addWidget(
    CardService.newDecoratedText()
      .setText(`<b>Score: ${result.score} / 100</b>`)
      .setBottomLabel(
        `<font color="${verdictColor(result.verdict)}"><b>${result.verdict.toUpperCase()}</b></font>`,
      )
      .setWrapText(true),
  );
  section.addWidget(CardService.newTextParagraph().setText(verdictDescription(result.verdict)));

  return section;
}

function buildCategorySection(
  category: SignalCategory,
  signals: Signal[],
): GoogleAppsScript.Card_Service.CardSection {
  const section = CardService.newCardSection().setHeader(CATEGORY_LABELS[category]);

  if (signals.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText("<i>No signals detected.</i>"));
  } else {
    for (const signal of signals) {
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(`${severityIcon(signal.score)} ${signal.name}`)
          .setText(signal.detail)
          .setWrapText(true),
      );
    }
  }

  section.setCollapsible(true).setNumUncollapsibleWidgets(0);
  return section;
}

function buildDisclaimerSection(): GoogleAppsScript.Card_Service.CardSection {
  return CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(
      "<i>This is a heuristic assessment, not a definitive security verdict. " +
        "Use your judgment for any action taken on this email.</i>",
    ),
  );
}

function verdictColor(verdict: Verdict): string {
  switch (verdict) {
    case "Safe":
      return "#1e8e3e";
    case "Suspicious":
      return "#e37400";
    case "Malicious":
      return "#d93025";
  }
}

function verdictDescription(verdict: Verdict): string {
  switch (verdict) {
    case "Safe":
      return "No significant risk indicators found. The email appears legitimate based on the analyzed signals.";
    case "Suspicious":
      return "Some risk indicators detected. Review the signals below before trusting this email.";
    case "Malicious":
      return "Multiple high-risk indicators detected. This email shows strong signs of being malicious.";
  }
}

function severityIcon(score: number): string {
  if (score >= 0.7) return "\u26D4";
  if (score >= 0.4) return "\u26A0";
  return "\u2139";
}
