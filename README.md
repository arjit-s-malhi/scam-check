# Scam Check 🛡️

A privacy-focused, client-side static web application for Indian college students to verify whether an internship, job offer, or gig message is a scam.

Built for the **"Smart Campus & Student Life"** challenge.

---

## Key Features

1. **100% In-Browser Execution**:
   - Zero backend, zero database, zero external API keys.
   - All text checks and OCR run locally in the browser; images and messages never leave the device.
2. **Three Input Modalities**:
   - **Message Text**: Analyzes English and Hinglish messages for upfront fees, task traps, fake HR Gmail senders, and sensitive credential demands.
   - **URL Analysis**: Inspects URL strings for shorteners, raw IP hosts, IDN homoglyphs/punycode, brand names in subdomains, risky TLDs, and edit-distance lookalikes of verified corporate portals.
   - **Screenshot OCR**: Extracts text locally via bundled Tesseract.js (lazy-loaded on demand), with an editable review box before scanning.
3. **Transparent Verdicts**:
   - **Likely scam** / **Suspicious** / **No red flags found** (never "safe" or "legit").
   - Inline visual highlighting of matched signals in message text.
   - Plain-language explanations citing published advisories from **I4C (MHA)**, **CERT-In**, **RBI**, and **AICTE**.
4. **Actionable Guidance**:
   - "What to do next" guidance box with emergency helplines: **Dial 1930** and reporting links to [cybercrime.gov.in](https://cybercrime.gov.in) and [sancharsaathi.gov.in](https://sancharsaathi.gov.in).
5. **Educational Extras**:
   - "Common Scams" breakdown showing anatomy of real Indian student scam patterns.

---

## How to Run Locally

### Prerequisites
- Node.js (v18+) and npm

### Steps
```bash
# 1. Install dependencies
npm install

# 2. Run unit tests
npm test

# 3. Start local development server
npm run dev
# The website will be available at: http://localhost:3000

# 4. Or build and preview production bundle
npm run build
npm run preview
```

---

## How to Deploy as a Plain Static Site

Because Scam Check is 100% front-end with zero server dependencies, it deploys directly to static hosting:

### Deploy to GitHub Pages
1. Build the production assets:
   ```bash
   npm run build
   ```
2. Commit and push the `dist/` directory to your `gh-pages` branch, or configure GitHub Pages in repository settings to build from the main branch using Vite's GitHub Action workflow.

### Deploy to Netlify
1. Drag and drop the `dist` folder into the Netlify Drop dashboard at [app.netlify.com/drop](https://app.netlify.com/drop).
2. Or connect your repository with build settings:
   - **Build command**: `npm run build`
   - **Publish directory**: `dist`

---

## How to Add a New Rule

All rules are machine-readable and defined in `rules.json` and documented in `RULES.md`.

To add a new rule:
1. Open `rules.json`.
2. Add an object to the `"rules"` array with the following schema:
   ```json
   {
     "id": "RULE_IDENTIFIER",
     "category": "payment | message | sender | link",
     "title": "Short title describing what it detects",
     "weight": 35,
     "explanation": "Plain-language explanation shown to students",
     "logic": {
       "type": "regex",
       "patterns": [
         "pattern1",
         "pattern2"
       ]
     },
     "source": {
       "name": "Published Advisory Authority",
       "url": "https://official-source-url"
     },
     "falsePositiveRisk": "Low / Medium / High note"
   }
   ```
3. Run `npm test` to verify that new rules compile and existing test cases pass without regressions.

