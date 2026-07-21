# Malicious Email Scorer - Gmail Add-on

A Gmail add-on that analyzes the email you have open and shows an
explainable 0-100 phishing/malicious risk score, right in the Gmail
sidebar.

It parses the message, runs it through five risk analyzers
(authentication headers, sender identity, content, URLs, attachments),
and renders a `Safe` / `Suspicious` / `Malicious` verdict with a
human-readable reason for every signal it flags - not just a number.

All analysis is local and heuristic - no external APIs, no reputation
lookups, no data leaves your Google account.

## Sample analysis

This is the same score, verdict, and signal list the add-on renders as a
card in Gmail (shown here via the CLI's plain-text output, which is
useful for development - see [Local development](#local-development-optional)):

```text
$ npm run analyze -- test/fixtures/phishing-bank-alert.eml

Malicious Email Analyzer
File: test/fixtures/phishing-bank-alert.eml

Score: 87 / 100   [MALICIOUS]

Authentication Headers
  ⛔ SPF failed - SPF authentication did not pass, which may indicate spoofing.
  ⛔ DKIM failed - DKIM authentication did not pass, which may indicate spoofing.
  ⛔ DMARC failed - DMARC authentication did not pass, which may indicate spoofing.

Sender Analysis
  ⚠ Reply-To mismatch - Reply-To <chase-support@mail.ru> differs from From <security-alerts@chase-support.com>.
  ⚠ Return-Path domain mismatch - Return-Path domain (totally-different.ru) differs from From domain (chase-support.com).

Content Analysis
  ⛔ Urgency language - Found 6 urgency phrase(s): "urgent", "act now", "verify your account", "suspended", "unusual sign-in".

URL Analysis
  ⛔ Link text / URL mismatch - 1 link(s) where visible text shows a different domain than the actual URL. Example: text shows "chase.com" but links to "chase-support.verify-now.ru".

Attachment Analysis
  ⛔ Double file extension - File(s) with double extensions detected: Statement.pdf.exe.
  ⛔ Risky attachment type - Potentially dangerous file type(s): Statement.pdf.exe.

This is a heuristic assessment, not a definitive security verdict.
```

In Gmail, the same score/verdict/signals are rendered as a collapsible
card in the right-hand sidebar instead of a terminal block.

## Why a Gmail add-on

Most "email security" demos are a script you run against a sample file
after the fact. That's not how anyone actually triages suspicious email -
they open it in their inbox and want an answer immediately. This project
is built as a real Gmail contextual add-on so the analysis happens where
the decision actually gets made: next to the message, in Gmail, with one
click.

Under the hood it demonstrates the kind of transparent, rule-based triage
logic that real mail security products (and SOC analysts) rely on as a
first line of defense: SPF/DKIM/DMARC evaluation with **identifier
alignment** (not just pass/fail), link-vs-text domain mismatches,
homograph and punycode detection, suspicious TLDs, double-extension and
Unicode filename-spoofing detection, and more.

## Install the Gmail add-on

This deploys your own private copy of the add-on to your own Google
account using [`clasp`](https://github.com/google/clasp), Google's CLI
for Apps Script. Nothing is published or shared - it only runs for you.

### Prerequisites

- Node.js 20+
- A Google account
- ~10 minutes

### 1. Clone the repository

```bash
git clone https://github.com/ItayYoschpe/malicious-email-project.git
cd malicious-email-project
npm install
```

### 2. Install and authenticate clasp

```bash
npm install -g @google/clasp
clasp login
```

`clasp login` opens a browser window - sign in with the Google account
you want the add-on installed on and grant the requested permissions.

Before logging in for the first time, enable the Apps Script API for
your account at <https://script.google.com/home/usersettings> (toggle
"Google Apps Script API" on). `clasp` cannot create or push projects
without this.

### 3. Build and deploy to Apps Script

```bash
# Bundle the add-on into a single Apps Script-compatible file
npm run build:gas

# The manifest (permissions, triggers, Gmail config) has to ship alongside it
cp apps-script/appsscript.json apps-script/dist/

cd apps-script/dist

# First time only - creates a new Apps Script project bound to your account
clasp create --type gmail-addon --title "Malicious Email Scorer"

# Uploads the code to that project
clasp push
```

### 4. Install it into Gmail

```bash
clasp open
```

This opens the Apps Script project in your browser. From there:

1. Click **Deploy** > **Test deployments**.
2. Click **Install**.
3. Review the permissions and click **Allow** (see [Permissions](#permissions-it-asks-for-and-why)
   and [authorization screens](#authorization-screens-you-may-see) below - this is expected).

### 5. Try it out

1. Open [Gmail](https://mail.google.com) in your browser (reload the tab
   if it was already open).
2. Open any email.
3. Look for the add-on's icon (a shield) in the right-hand sidebar and
   click it.
4. You'll see the risk score, verdict, and a breakdown of every signal
   that contributed to it.

Try it on one of the bundled test fixtures by forwarding
[`test/fixtures/phishing-bank-alert.eml`](test/fixtures/phishing-bank-alert.eml)
to yourself, or just open any real email in your inbox.

### Permissions it asks for, and why

The install step above will prompt for these scopes, defined in
[`apps-script/appsscript.json`](apps-script/appsscript.json):

| Scope                                   | Why the add-on needs it                                                                                                                                        |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gmail.addons.execute`                  | Lets the script run as a Gmail add-on and render a Card in the sidebar.                                                                                        |
| `gmail.addons.current.message.readonly` | Lets it read the specific message you have open when you click the add-on.                                                                                     |
| `gmail.readonly`                        | Lets it fetch the full message (including raw auth headers like SPF/DKIM/DMARC) via the Gmail Advanced Service, which the basic message object doesn't expose. |

The add-on only ever reads the message you explicitly open it on - it has
no background triggers, doesn't send mail, and doesn't modify or delete
anything.

### Authorization screens you may see

Because this is a personal deployment rather than a Google-verified
public add-on, Google shows a couple of extra warnings that are expected
and safe to proceed through for your own script:

- **OAuth consent screen** - lists the permissions above. Click **Allow**.
- **"Google hasn't verified this app"** - shown because the project isn't
  submitted for Google's app-verification review (unnecessary for a
  personal, single-user deployment). Click **Advanced**, then
  **Go to Malicious Email Scorer (unsafe)**, then **Allow**. This is
  standard for any Apps Script project you deploy for yourself.
- **Advanced Gmail Service** - already enabled for you via
  `enabledAdvancedServices` in `appsscript.json`; you shouldn't need to
  enable anything manually in the Apps Script editor or a Cloud project.

### Troubleshooting

| Symptom                                                       | Likely cause / fix                                                                                                                                                                       |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clasp login` / `clasp create` fails with a permissions error | Enable "Google Apps Script API" at <https://script.google.com/home/usersettings>, then retry.                                                                                            |
| Add-on doesn't appear in Gmail's sidebar                      | Make sure you clicked **Install** under **Test deployments** (not just pushed code), then fully reload the Gmail tab.                                                                    |
| Runtime error mentioning `Gmail is not defined`               | The manifest wasn't pushed. `npm run build:gas` only emits `Code.gs` - re-run step 3 including `cp apps-script/appsscript.json apps-script/dist/` and `clasp push`.                      |
| Card shows "An error occurred during analysis"                | Open the Apps Script project (`clasp open`) and check **Executions** for the stack trace. Reopening the email retriggers with a fresh access token, which fixes most transient failures. |
| Code changes don't show up after `clasp push`                 | Gmail caches add-on cards per session - close and reopen the email, or reload Gmail entirely.                                                                                            |
| Stuck on "This app isn't verified"                            | Expected for a personal deployment - click **Advanced** > **Go to \[app name\] (unsafe)** > **Allow**. See [above](#authorization-screens-you-may-see).                                  |

See [`apps-script/README.md`](apps-script/README.md) for more detail on
how the add-on itself is built and bundled.

## How it works

```
┌──────────────────────────────────────────────────────────────────┐
│  Input: a Gmail message (add-on) or a raw .eml file (local CLI)  │
│           │                                                      │
│           ▼                                                      │
│  extractEmailData() / parseEml()  →  ParsedEmail (transport-     │
│                                       agnostic shape)             │
│           │                                                      │
│           ▼                                                      │
│  analyzeEmail()  (src/core - the shared analysis engine)         │
│       ├─► analyzeHeaders()      SPF / DKIM / DMARC + alignment   │
│       ├─► analyzeSender()       display name, Reply-To, Return-P.│
│       ├─► analyzeContent()      urgency & credential-harvest text│
│       ├─► analyzeUrls()         mismatch, shorteners, IP, TLDs   │
│       └─► analyzeAttachments()  risky ext., double ext., RLO     │
│           │                                                      │
│           ▼                                                      │
│  computeScore()  →  { score: 0-100, verdict, signals }           │
│           │                                                      │
│           ▼                                                      │
│  Gmail Card UI (apps-script/)  •  CLI report / JSON (dev/test)   │
└──────────────────────────────────────────────────────────────────┘
```

The Gmail add-on in [`apps-script/`](apps-script/) is the primary
application - it's what a user installs and interacts with. It's a thin
layer (an adapter that maps a Gmail message into `ParsedEmail`, plus a
Card renderer) around the shared analysis engine in `src/core`, which
contains all the actual detection logic and has no dependency on Gmail
at all. That decoupling is what makes the engine unit-testable with
Vitest and reusable by the local CLI described under
[Local development](#local-development-optional) - the exact same
analyzers, scorer, and verdict logic run behind both.

### Scoring model

Each analyzer category has a fixed weight (`src/core/config.ts`):

| Category    | Weight |
| ----------- | ------ |
| Headers     | 25%    |
| Sender      | 20%    |
| Content     | 20%    |
| URLs        | 25%    |
| Attachments | 10%    |

Within a category, the dominant (highest) signal score is taken in full and
each additional signal in that category adds 30% of its score (capped at
1.0 combined), so one strong signal drives the score while several weak,
possibly-correlated signals can't stack unboundedly. The final score is
`sum(category_combined × weight × 100)`, capped at 100.

| Score  | Verdict    |
| ------ | ---------- |
| 0-29   | Safe       |
| 30-59  | Suspicious |
| 60-100 | Malicious  |

Weights and thresholds are plain data (`ScoringConfig`) that can be
overridden per call to `analyzeEmail(email, customConfig)` - no code
changes required to retune the model.

## Detection capabilities

**Authentication headers** - parses `Authentication-Results` /
`Received-SPF`, checks SPF/DKIM/DMARC pass/fail/missing, and independently
checks **DMARC identifier alignment**: a message can present a passing SPF
or DKIM result for a domain that has nothing to do with the visible `From`
address, which is exactly the gap DMARC alignment closes and bare pass/fail
parsing misses.

**Sender analysis** - display-name/address mismatch, free email providers
impersonating a business identity, Reply-To and Return-Path domain
mismatches.

**Content analysis** - urgency/pressure language, credential and
payment-harvesting phrases, excessive capitalization.

**URL analysis** - link-text vs. actual-URL domain mismatch, known URL
shorteners, raw IP-address links, punycode/homograph domains, TLDs
disproportionately abused for phishing (`.zip`, `.top`, `.xyz`, `.click`,
etc.), and an unusually high number of unique link domains.

**Attachment analysis** - risky file extensions, double extensions (e.g.
`invoice.pdf.exe`), Unicode right-to-left-override filename spoofing (the
technique behind `"gpj.exe"` rendering as `"exe.jpg"`), and the
password-protected-archive delivery pattern.

## Local development (optional)

Everything below is a **developer/testing interface for the same
analysis engine** that powers the Gmail add-on - useful for iterating on
detection logic without redeploying to Apps Script, but not required to
use the add-on itself.

### Run the CLI against a sample email

Requires Node.js 20+.

```bash
npm install

# Analyze a sample email
npm run analyze -- test/fixtures/phishing-bank-alert.eml

# Machine-readable output
npm run analyze -- test/fixtures/phishing-bank-alert.eml --json
```

| Fixture                    | Verdict   |
| -------------------------- | --------- |
| `phishing-bank-alert.eml`  | Malicious |
| `phishing-it-helpdesk.eml` | Malicious |
| `legit-newsletter.eml`     | Safe      |
| `legit-personal.eml`       | Safe      |

Drop any other `.eml` file into `test/fixtures/` (or point the CLI at any
path) to try the engine against it.

### Using the engine as a library

```ts
import { analyzeEmail, parseEml } from "malicious-email-project";
import { readFile } from "node:fs/promises";

const raw = await readFile("email.eml");
const email = await parseEml(raw);
const result = analyzeEmail(email);

console.log(result.score, result.verdict);
```

`ParsedEmail` is a plain interface - any source (an IMAP client, a webhook
payload, a test fixture, or Gmail itself) can be adapted to it without
touching the engine.

### Running the tests

```bash
npm test          # Vitest unit + integration tests for src/core
npm run typecheck  # type-checks both the CLI package and apps-script/
npm run lint
npm run format:check
```

## Project structure

```
apps-script/              The Gmail add-on - the primary application
  src/
    main.ts                onGmailMessage trigger: ties everything together
    emailAdapter.ts         Gmail message -> ParsedEmail
    cardBuilder.ts          AnalysisResult -> Gmail Card UI
  appsscript.json           Manifest: OAuth scopes, triggers, Advanced Services
  README.md                 Add-on build/deploy details

src/
  core/                    Shared analysis engine that powers the add-on
    types.ts                Shared types (ParsedEmail, Signal, AnalysisResult, ...)
    config.ts                Category weights & verdict thresholds
    analyzeEmail.ts           Orchestrator: runs analyzers -> computeScore
    scorer.ts                 0-100 scoring + verdict resolution
    analyzers/                One file per analyzer category
    utils/                    Address parsing, domain alignment, link extraction
  parsing/
    emlParser.ts              Raw .eml -> ParsedEmail (via mailparser) - used by the CLI
  cli/
    index.ts, report.ts       Local developer CLI: `analyze-email` entry point + report formatting
  index.ts                  Public package entry point (for the "as a library" use case)

test/
  fixtures/                Synthetic sample emails (phishing + legitimate)
  *.test.ts                Vitest unit + end-to-end tests
```

## Known limitations

- **Heuristic only** - pattern-based checks, no machine learning and no
  threat-intelligence feeds. False positives and false negatives are
  expected, as with any rule-based triage system.
- **No external reputation lookups** - URLs and domains aren't checked
  against a blocklist, by design: this keeps the tool self-contained and
  privacy-preserving, at the cost of missing known-bad infrastructure.
- **Header availability varies** - `Authentication-Results` and
  `Received-SPF` are added by the receiving mail server and aren't always
  present or complete.
- **Attachment content isn't inspected** - only file names, extensions, and
  metadata are checked; nothing is decompressed or scanned.
- **Stateless** - each analysis is independent; there's no scan history or
  learned allow/deny list.
- **Personal deployment only** - as shipped, the add-on is meant to be
  deployed by each user to their own Google account (see
  [Install the Gmail add-on](#install-the-gmail-add-on)); it isn't
  published to the Google Workspace Marketplace.

## Tech stack

TypeScript (strict, ESM, `NodeNext` resolution) - `mailparser` for MIME
parsing - Vitest for tests - ESLint (flat config) + Prettier - esbuild for
the Gmail add-on bundle - `clasp` for Apps Script deployment - GitHub
Actions for CI.
