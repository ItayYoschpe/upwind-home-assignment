# Part 1 - Gmail Add-on: Malicious Email Scorer

A Gmail Card-based add-on that analyzes an opened email and produces a
maliciousness score (0-100), a clear verdict (Safe / Suspicious / Malicious),
and an explainable breakdown of the contributing signals.

All analysis is performed locally with heuristic rules - no external APIs,
no data leaves the user's mailbox.

## Architecture

```
┌────────────────────────────────────────────────────┐
│  Gmail  →  contextual trigger  →  onGmailMessage() │
│                                                    │
│  Code.gs        Orchestrator                       │
│       │                                            │
│       ├─► Analyzers.gs                             │
│       │     ├ analyzeHeaders()                     │
│       │     ├ analyzeSender()                      │
│       │     ├ analyzeContent()                     │
│       │     ├ analyzeUrls()                        │
│       │     └ analyzeAttachments()                 │
│       │                                            │
│       ├─► Scorer.gs         computeScore()         │
│       │                                            │
│       └─► CardBuilder.gs    buildCard()            │
│                 ↓                                  │
│           Card UI (score + verdict + signals)      │
└────────────────────────────────────────────────────┘
```

When a user opens an email, Gmail fires the contextual trigger defined in
`appsscript.json`. The entry point `onGmailMessage(e)` in `Code.gs`:

1. Retrieves the message via `GmailApp` and the Gmail Advanced Service.
2. Extracts headers, body, and attachment metadata into a flat `emailData`
   object.
3. Passes `emailData` through five independent analyzers, each returning an
   array of signal objects `{ name, score, detail }`.
4. Feeds all signals into `computeScore()` which produces a weighted 0-100
   score and a verdict.
5. Builds and returns a Card UI via `buildCard()`.

### Scoring model

Each analyzer category has a fixed weight:

| Category     | Weight |
|-------------|--------|
| Headers      | 25 %   |
| Sender       | 20 %   |
| Content      | 20 %   |
| URLs         | 25 %   |
| Attachments  | 10 %   |

Within a category, the dominant (highest) signal score is taken in full and
each additional signal adds 30 % of its score (capped at 1.0 combined) to
prevent unbounded stacking. The final score is
`sum(category_combined × weight × 100)`, capped at 100.

Verdict thresholds:

| Score  | Verdict    |
|--------|-----------|
| 0-29   | Safe       |
| 30-59  | Suspicious |
| 60-100 | Malicious  |

## APIs Used

| API | Purpose |
|-----|---------|
| **GmailApp** (`GmailApp.getMessageById()`) | Read message body, plain text, attachments |
| **Gmail Advanced Service** (`Gmail.Users.Messages.get()`) | Access full message payload and raw headers (SPF, DKIM, DMARC, Return-Path, etc.) |
| **CardService** | Build the add-on UI cards with sections, decorated text, and collapsible signal groups |

OAuth scopes requested:

- `gmail.addons.execute` - run as a Gmail add-on
- `gmail.addons.current.message.readonly` - read the currently open message
- `gmail.readonly` - required by the Advanced Gmail Service to fetch full headers

## Implemented Features

### 1. Header Authentication Analysis
- Parses `Authentication-Results` and `Received-SPF` headers
- Checks SPF, DKIM, and DMARC pass/fail/none status
- Flags missing authentication as a risk signal

### 2. Sender Analysis
- Detects display-name vs. email-address mismatch
- Flags free email providers that claim to be official/business entities
- Detects Reply-To vs. From mismatch
- Detects Return-Path domain vs. From domain mismatch

### 3. Content Analysis
- Scans for urgency/phishing phrases (17 patterns)
- Detects credential and payment request language (15 patterns)
- Flags excessive capitalization

### 4. URL Analysis
- Extracts links from HTML `href` attributes and plain-text URLs
- Detects link-text vs. actual-URL domain mismatch (a strong phishing signal)
- Flags URL shorteners (11 known services)
- Flags IP-address-based URLs
- Detects punycode/IDN homograph domains
- Flags excessive unique domains

### 5. Attachment Analysis
- Flags risky file extensions (executables, scripts, macro-enabled Office docs, archives)
- Detects double file extensions (e.g., `invoice.pdf.exe`)
- Detects password-protected archive pattern (body mentions password + archive attached)

### UI
- Score displayed prominently with color-coded verdict
- Signal breakdown organized by category in collapsible sections
- Each signal shows severity icon, name, and human-readable explanation
- Disclaimer clarifying this is a heuristic assessment


## Known Limitations

- **Heuristic only**: All checks are pattern-based. There is no machine
  learning, no threat intelligence feeds, and no external API enrichment.
  False positives and false negatives are expected.
- **No external reputation lookups**: URLs and domains are not checked
  against any blocklist. This keeps the add-on self-contained and private but
  limits detection of known-bad infrastructure.
- **Header availability varies**: Email authentication headers
  (`Authentication-Results`, `Received-SPF`) are added by the receiving
  mail server and may not always be present or complete.
- **Limited content analysis**: The keyword lists cover common phishing
  patterns but will miss novel or non-English social engineering.
- **Attachment content not inspected**: Only file names and extensions are
  checked. The add-on does not open, decompress, or scan attachment
  contents.
- **No persistent state**: There is no scan history, no blocklist storage,
  and no user configuration. Each scan is independent.
