# Project Handoff: Scam Check

## Overview
Scam Check is a static web application built for Indian college students to verify internship, job, and gig offers against known cyber fraud patterns. It runs 100% in the browser with zero backend, database, or API keys, and is ready for static deployment on GitHub Pages or Netlify.

---

## Status & Completed Work

### 1. Research & Rules Specification (Phase 1)
- Researched published advisories: I4C / cybercrime.gov.in (Task scams, mule accounts), Sanchar Saathi (Chakshu), CERT-In (CIAD-2024-0050), RBI (BE(A)WARE booklet), AICTE (Zero-fee internship policy), FTC, CISA, UK NCSC, and OWASP.
- Created `RULES.md` and machine-readable `rules.json` with 17 rules across 4 categories (`payment`, `message`, `sender`, `link`).
- Verified official career domains for TCS, Infosys, Wipro, Cognizant, Accenture, Google, Microsoft, Amazon, AICTE, and Internshala.
- Incorporated verified reporting channels: Dial 1930, cybercrime.gov.in, and sancharsaathi.gov.in.

### 2. Pure Engine Implementation & Testing (Phase 2 - Slice 1)
- Built pure function rule engine in `src/engine/`:
  - `rulesData.js`: Data source from `rules.json`.
  - `urlAnalyzer.js`: URL heuristics (shorteners, IP hosts, punycode, brand in subdomain/path, deep nesting, risky TLDs, userinfo `@`, Levenshtein distance).
  - `textAnalyzer.js`: English & Hinglish regex matcher with Safari-safe negation pre-checking (avoids lookbehind syntax).
  - `engine.js`: Verdict calculator (`Likely scam`, `Suspicious`, `No red flags found`), highlight span merger, and result assembler.
- Tested via Node.js test runner (`node:test`) in `test/engine.test.js`: 19/19 tests passing.

### 3. User Interface & Feature Tabs (Phase 2 - Slices 2 to 5)
- **Message Text Tab**: Text input, quick sample buttons, highlight rendering, signal breakdown with source links, and "What to do next" guidance box.
- **Link Check Tab**: URL inspection with clear disclaimer that pages are not fetched over the network.
- **Screenshot Tab**: Client-side OCR via lazy-loaded Tesseract.js (image never leaves device), progress bar, and editable extracted text box.
- **Common Scams Tab**: Anatomies of real-world Indian student scams with highlighted red flags.
- **Accessibility & Design**: Mobile-first, responsive, light/dark mode toggle, high-contrast, visible focus states, respects reduced motion.
- **Build & Server**: Vite build verified (`npm run build` generates clean `dist/` bundle), local server live on `http://localhost:3000/`.

---

## Key Files & References

- Rules definition: [RULES.md](file:///c:/Users/arjit/Downloads/scam_check/RULES.md)
- Machine-readable rules: [rules.json](file:///c:/Users/arjit/Downloads/scam_check/rules.json)
- Universal agent conventions: [universal_rules.md](file:///c:/Users/arjit/Downloads/scam_check/universal_rules.md)
- Test suite: [test/engine.test.js](file:///c:/Users/arjit/Downloads/scam_check/test/engine.test.js)
- App entry & UI: [index.html](file:///c:/Users/arjit/Downloads/scam_check/index.html) and [src/main.js](file:///c:/Users/arjit/Downloads/scam_check/src/main.js)
- Styles: [src/style.css](file:///c:/Users/arjit/Downloads/scam_check/src/style.css)
- Run & deploy guide: [README.md](file:///c:/Users/arjit/Downloads/scam_check/README.md)

---

## Deployment Instructions

### GitHub Pages
```bash
npm run build
# Deploy dist/ directory to gh-pages branch
```

### Netlify
- Build Command: `npm run build`
- Publish Directory: `dist`

---

## Known Gaps & Future Considerations (Out of Scope for Static Prototype)
- OCR accuracy on low-contrast or noisy photos of physical paper letters.
- Real-time link reputation lookups (e.g. Google Safe Browsing API) require backend keys and are excluded by design.
- Multi-language Hindi script OCR (Romanized Hinglish is fully supported).
