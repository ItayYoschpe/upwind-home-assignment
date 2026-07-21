# Gmail Add-on

This folder **is the product** - a real Gmail contextual add-on that
renders a risk-scored analysis card for whatever email you have open. See
the root [`README.md`](../README.md) for the full install/deploy
walkthrough; this file covers the add-on's internals and build process.

It lives in its own folder because it depends on Google Apps Script
runtime globals (`GmailApp`, `CardService`, the Gmail Advanced Service)
that only exist inside the Apps Script sandbox and have no npm
equivalent - they cannot be installed, imported, or unit tested like a
normal dependency. Everything that _can_ be tested outside that sandbox -
the five analyzers, the scorer, the verdict thresholds - lives in the
shared analysis engine at [`../src/core`](../src/core), which this add-on
imports and has no knowledge of Gmail at all.

The Gmail-specific code, all of it, lives here:

- `src/emailAdapter.ts` - maps a `GmailMessage` + Gmail API payload into the
  engine's `ParsedEmail` shape.
- `src/cardBuilder.ts` - renders an `AnalysisResult` as a `CardService` UI.
- `src/main.ts` - the `onGmailMessage` trigger that ties the two together
  and calls `analyzeEmail()` from `src/core`.

This layer is intentionally thin: it's just enough glue to get a Gmail
message into the engine and the engine's result back out as a Card. The
engine is what does the actual work, and it's also exercised directly by
a local CLI (see the root README's
[Local development](../README.md#local-development-optional) section)
for fast iteration without redeploying to Apps Script on every change.

## Deploying

The root README's [Install the Gmail add-on](../README.md#install-the-gmail-add-on)
section is the canonical step-by-step walkthrough (including the
permissions Google will ask for and the authorization warnings you'll
see). The steps below are the same commands, kept here as a quick
reference plus the "why" behind the build.

Apps Script's V8 runtime does not support ES module `import`/`export` at
the top level, and it has no package manager, so the TypeScript sources
here are bundled into a single script with [esbuild](https://esbuild.github.io/)
before being pushed with [`clasp`](https://github.com/google/clasp):

### Prerequisites

1. **Install clasp** (first time only):

   ```bash
   npm install -g @google/clasp
   ```

2. **Authenticate with Google** (first time only):

   ```bash
   clasp login
   ```

   This will open a browser window. Sign in with your Google account and grant the requested permissions.

3. **Enable the Apps Script API**:
   - Visit https://script.google.com/home/usersettings
   - Turn on "Google Apps Script API"

### Deploy to Apps Script

```bash
# Build the bundle
npm run build:gas

# Copy config file
cp apps-script/appsscript.json apps-script/dist/

# Navigate to dist folder
cd apps-script/dist

# Create a new Apps Script project (first time only)
clasp create --type gmail-addon --title "Malicious Email Scorer"

# Push your code to Apps Script
clasp push
```

### Install the Add-on in Gmail

After deployment:

1. Open the Apps Script project in the browser:

   ```bash
   clasp open
   ```

2. In the Apps Script editor:
   - Click **Deploy** > **Test deployments**
   - Click **Install** to add it to your Gmail
   - Accept the authorization prompts

3. Open Gmail, select any email, and look for the add-on icon in the right sidebar.

Because the bundle is built with `--format=iife`, the Apps Script trigger
dispatcher (which looks up `onGmailMessage` as a property on the global
object) would otherwise be unable to see it - `main.ts` re-publishes the
function on `globalThis` after declaring it to work around this.

## Why this isn't part of CI

Deploying and exercising this add-on requires a Google Workspace account,
OAuth consent, and an actual Gmail inbox, none of which are available in a
CI runner. `npm run typecheck` still type-checks this folder against
`@types/google-apps-script`, so it can't silently drift from the core
engine's API.
