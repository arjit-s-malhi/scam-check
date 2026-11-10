import { analyzeMessage, checkUrlOnly, VERDICTS } from './engine/engine.js';
import { fictionalTestCases, reportingChannels, verifiedOfficialDomains } from './engine/rulesData.js';
import { extractTextFromImage } from './ocr/ocrHandler.js';

// DOM Elements
const themeToggleBtn = document.getElementById('themeToggleBtn');
const themeIcon = document.getElementById('themeIcon');
const themeLabel = document.getElementById('themeLabel');

const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanels = document.querySelectorAll('.tab-panel');

const messageInput = document.getElementById('messageInput');
const checkMessageBtn = document.getElementById('checkMessageBtn');
const clearMessageBtn = document.getElementById('clearMessageBtn');

const linkInput = document.getElementById('linkInput');
const checkLinkBtn = document.getElementById('checkLinkBtn');

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const ocrProgressContainer = document.getElementById('ocrProgressContainer');
const ocrProgressBar = document.getElementById('ocrProgressBar');
const ocrStatusText = document.getElementById('ocrStatusText');
const ocrPercentText = document.getElementById('ocrPercentText');
const ocrEditArea = document.getElementById('ocrEditArea');
const ocrExtractedText = document.getElementById('ocrExtractedText');
const checkOcrBtn = document.getElementById('checkOcrBtn');

const commonScamsContainer = document.getElementById('commonScamsContainer');
const resultsSection = document.getElementById('resultsSection');

// 1. Theme Management (Light / Dark)
function initTheme() {
  const savedTheme = localStorage.getItem('scamcheck_theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const currentTheme = savedTheme || (prefersDark ? 'dark' : 'light');

  setTheme(currentTheme);

  themeToggleBtn.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    setTheme(isDark ? 'light' : 'dark');
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('scamcheck_theme', theme);
  if (theme === 'dark') {
    themeIcon.textContent = '☀️';
    themeLabel.textContent = 'Light';
  } else {
    themeIcon.textContent = '🌙';
    themeLabel.textContent = 'Dark';
  }
}

// 2. Accessible Tabs Navigation
function initTabs() {
  tabButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => switchTab(btn));

    // Keyboard arrow navigation
    btn.addEventListener('keydown', (e) => {
      let targetIndex = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        targetIndex = (index + 1) % tabButtons.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        targetIndex = (index - 1 + tabButtons.length) % tabButtons.length;
      }
      if (targetIndex !== null) {
        e.preventDefault();
        tabButtons[targetIndex].focus();
        switchTab(tabButtons[targetIndex]);
      }
    });
  });
}

function switchTab(selectedBtn) {
  tabButtons.forEach(b => {
    b.setAttribute('aria-selected', 'false');
    b.setAttribute('tabindex', '-1');
  });
  tabPanels.forEach(p => p.classList.remove('active'));

  selectedBtn.setAttribute('aria-selected', 'true');
  selectedBtn.setAttribute('tabindex', '0');

  const panelId = selectedBtn.getAttribute('aria-controls');
  const targetPanel = document.getElementById(panelId);
  if (targetPanel) {
    targetPanel.classList.add('active');
  }

  // Hide results when switching away from check tabs if desired, or keep persisted
}

// 3. Render Results UI
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderHighlightedText(rawText, spans) {
  if (!rawText) return '';
  if (!spans || spans.length === 0) return escapeHtml(rawText);

  let html = '';
  let cursor = 0;

  for (const span of spans) {
    if (span.start > cursor) {
      html += escapeHtml(rawText.slice(cursor, span.start));
    }
    const chunk = rawText.slice(span.start, span.end);
    html += `<mark class="flag-highlight" title="Triggered rule">${escapeHtml(chunk)}</mark>`;
    cursor = span.end;
  }

  if (cursor < rawText.length) {
    html += escapeHtml(rawText.slice(cursor));
  }

  return html;
}

export function displayResults(result, isUrlOnly = false) {
  resultsSection.style.display = 'block';

  let verdictClass = 'no-red-flags';
  let verdictIcon = '🔍';
  let verdictSummary = '';

  if (result.verdict === VERDICTS.LIKELY_SCAM) {
    verdictClass = 'likely-scam';
    verdictIcon = '🚨';
    verdictSummary = 'This message contains critical red flags commonly found in student-targeted scams. Real companies do not ask you for money, passwords, or personal UPI transfers.';
  } else if (result.verdict === VERDICTS.SUSPICIOUS) {
    verdictClass = 'suspicious';
    verdictIcon = '⚠️';
    verdictSummary = 'This message has multiple suspicious characteristics. Do not share sensitive documents, and verify the recruiter directly through the official company website.';
  } else {
    verdictClass = 'no-red-flags';
    verdictIcon = '🔍';
    verdictSummary = 'No known scam red flags were detected in this message. However, automated tools cannot guarantee authenticity. Always remain vigilant and never pay any registration fees.';
  }

  const triggeredHtml = (result.triggeredRules && result.triggeredRules.length > 0)
    ? `
      <div style="margin-top: 1rem;">
        <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">Detected Signals & Explanations:</h4>
        <div class="flags-list">
          ${result.triggeredRules.map(rule => `
            <div class="flag-item">
              <div class="flag-title-row">
                <span class="flag-title">
                  <span aria-hidden="true">${rule.weight >= 40 ? '🔴' : '🟡'}</span>
                  ${escapeHtml(rule.title)}
                </span>
                <span class="flag-weight-badge">Weight: ${rule.weight}</span>
              </div>
              <p class="flag-explanation">${escapeHtml(rule.explanation)}</p>
              ${rule.matches && rule.matches.length > 0 ? `
                <div style="font-size: 0.76rem; color: var(--text-subtle);">
                  <strong>Matched text:</strong> <code>${escapeHtml(rule.matches.join(', '))}</code>
                </div>
              ` : ''}
              <div class="flag-meta">
                <span>Source: <a href="${escapeHtml(rule.source.url)}" target="_blank" rel="noopener noreferrer" class="flag-source-link">${escapeHtml(rule.source.name)}</a></span>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `
    : `
      <div style="padding: 0.75rem; background: var(--bg-muted); border-radius: var(--radius-sm); font-size: 0.85rem; color: var(--text-muted); margin-top: 0.5rem;">
        No suspicious keywords, free-email impersonation, or deceptive URL patterns were triggered.
      </div>
    `;

  const highlightedHtml = (!isUrlOnly && result.rawText) ? `
    <div style="margin-top: 0.75rem;">
      <label class="input-label">Message with highlighted signals:</label>
      <div class="highlighted-box">${renderHighlightedText(result.rawText, result.highlightSpans)}</div>
    </div>
  ` : '';

  const urlBreakdownHtml = (result.urlAnalyses && result.urlAnalyses.length > 0) ? `
    <div style="margin-top: 1rem;">
      <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">Link Analysis Breakdown:</h4>
      <div class="flags-list">
        ${result.urlAnalyses.map(u => `
          <div class="flag-item">
            <div class="flag-title-row">
              <span class="flag-title">🔗 ${escapeHtml(u.url)}</span>
              <span class="flag-weight-badge">${u.triggeredRules.length} red flag(s)</span>
            </div>
            <div style="font-size: 0.82rem; color: var(--text-muted);">
              <strong>Analyzed Host:</strong> <code>${escapeHtml(u.hostname || 'Invalid URL')}</code>
            </div>
            ${u.triggeredRules.map(tr => `
              <div style="font-size: 0.8rem; margin-top: 0.25rem; color: var(--text-main);">
                ⚠️ <strong>${escapeHtml(tr.title)}:</strong> ${escapeHtml(tr.explanation)}
              </div>
            `).join('')}
          </div>
        `).join('')}
      </div>
    </div>
  ` : '';

  resultsSection.innerHTML = `
    <div class="verdict-card ${verdictClass}">
      <div class="verdict-header">
        <div class="verdict-title-wrap">
          <span class="verdict-icon" aria-hidden="true">${verdictIcon}</span>
          <h3 class="verdict-title">${escapeHtml(result.verdict)}</h3>
        </div>
        <span class="verdict-score-badge">Risk Score: ${result.score}</span>
      </div>
      <p class="verdict-summary">${verdictSummary}</p>
      
      ${highlightedHtml}
      ${triggeredHtml}
      ${urlBreakdownHtml}

      <!-- "What to do next" Guidance Box -->
      <div class="guidance-box" style="margin-top: 1rem;">
        <div class="guidance-title">
          <span aria-hidden="true">💡</span> What to do next
        </div>
        <ul class="guidance-steps">
          <li class="guidance-step">
            <span class="guidance-step-num">1</span>
            <div><strong>Never pay money:</strong> Genuine employers and AICTE-verified internships never ask candidates for application fees, security deposits, or laptop courier charges.</div>
          </li>
          <li class="guidance-step">
            <span class="guidance-step-num">2</span>
            <div><strong>Never share OTP or banking details:</strong> Legitimate onboarding never requires your OTP, UPI PIN, ATM PIN, or passwords.</div>
          </li>
          <li class="guidance-step">
            <span class="guidance-step-num">3</span>
            <div><strong>Verify directly on official portals:</strong> Always cross-check job openings on verified career websites (e.g. <a href="https://nextstep.tcs.com" target="_blank" rel="noopener noreferrer">nextstep.tcs.com</a>, <a href="https://careers.infosys.com" target="_blank" rel="noopener noreferrer">careers.infosys.com</a>, or <a href="https://internship.aicte-india.org" target="_blank" rel="noopener noreferrer">internship.aicte-india.org</a>).</div>
          </li>
          <li class="guidance-step">
            <span class="guidance-step-num">4</span>
            <div>
              <strong>Report suspicious messages:</strong>
              <div style="margin-top: 0.35rem; display: flex; flex-direction: column; gap: 0.25rem;">
                <div>• Report suspect calls/SMS on <strong><a href="https://sancharsaathi.gov.in" target="_blank" rel="noopener noreferrer">Chakshu (Sanchar Saathi)</a></strong></div>
                <div>• If you lost money, dial the National Cybercrime Helpline immediately: <span class="helpline-pill">📞 1930</span> and file a report at <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">cybercrime.gov.in</a>.</div>
              </div>
            </div>
          </li>
        </ul>
      </div>
    </div>
  `;

  // Scroll smoothly to results
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// 4. Sample Loaders
function initSamples() {
  const sampleMap = {
    'clear-scam-1': fictionalTestCases.find(tc => tc.id === 'TC_CLEAR_SCAM_1')?.input || '',
    'clear-scam-2': fictionalTestCases.find(tc => tc.id === 'TC_CLEAR_SCAM_2')?.input || '',
    'borderline-1': fictionalTestCases.find(tc => tc.id === 'TC_BORDERLINE_1')?.input || '',
    'legit-1': fictionalTestCases.find(tc => tc.id === 'TC_LEGIT_1')?.input || ''
  };

  document.querySelectorAll('.sample-chip[data-sample]').forEach(chip => {
    chip.addEventListener('click', () => {
      const key = chip.getAttribute('data-sample');
      if (sampleMap[key]) {
        messageInput.value = sampleMap[key];
        const res = analyzeMessage(sampleMap[key]);
        displayResults(res);
      }
    });
  });

  document.querySelectorAll('.sample-chip[data-link]').forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.getAttribute('data-link');
      linkInput.value = url;
      const res = checkUrlOnly(url);
      displayResults(res, true);
    });
  });
}

// 5. Text & Link Tab Handlers
function initCheckingActions() {
  checkMessageBtn.addEventListener('click', () => {
    const text = messageInput.value.trim();
    if (!text) {
      alert('Please paste or type a message to check.');
      messageInput.focus();
      return;
    }
    const res = analyzeMessage(text);
    displayResults(res);
  });

  clearMessageBtn.addEventListener('click', () => {
    messageInput.value = '';
    resultsSection.style.display = 'none';
    messageInput.focus();
  });

  checkLinkBtn.addEventListener('click', () => {
    const url = linkInput.value.trim();
    if (!url) {
      alert('Please enter a URL to check.');
      linkInput.focus();
      return;
    }
    const res = checkUrlOnly(url);
    displayResults(res, true);
  });
}

// 6. Screenshot Tab with In-Browser Local OCR (Tesseract.js)
function initScreenshotTab() {
  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  // Drag and drop
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-active');
  });

  ['dragleave', 'dragend'].forEach(ev => {
    dropzone.addEventListener(ev, () => dropzone.classList.remove('drag-active'));
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-active');
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      handleImageFile(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleImageFile(files[0]);
    }
  });

  // Clipboard paste support (Ctrl+V anywhere in app or dropzone)
  window.addEventListener('paste', (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.indexOf('image') !== -1) {
        const file = item.getAsFile();
        if (file) {
          // Switch to screenshot tab if not already active
          const screenshotTabBtn = document.getElementById('tabBtnScreenshot');
          if (screenshotTabBtn) switchTab(screenshotTabBtn);
          handleImageFile(file);
          break;
        }
      }
    }
  });

  checkOcrBtn.addEventListener('click', () => {
    const text = ocrExtractedText.value.trim();
    if (!text) {
      alert('Extracted text is empty. Please check your image or enter text manually.');
      return;
    }
    const res = analyzeMessage(text);
    displayResults(res);
  });
}

async function handleImageFile(file) {
  if (!file.type.startsWith('image/')) {
    alert('Please upload a valid image file (PNG, JPG, WebP).');
    return;
  }

  ocrProgressContainer.style.display = 'flex';
  ocrProgressBar.style.width = '10%';
  ocrStatusText.textContent = 'Preparing image...';
  ocrPercentText.textContent = '10%';
  ocrEditArea.style.display = 'none';

  const reader = new FileReader();
  reader.onload = async () => {
    const dataUrl = reader.result;

    const result = await extractTextFromImage(dataUrl, (p) => {
      const pct = Math.round((p.progress || 0) * 100);
      ocrProgressBar.style.width = `${Math.max(10, pct)}%`;
      ocrStatusText.textContent = p.status || 'Scanning locally...';
      ocrPercentText.textContent = `${pct}%`;
    });

    ocrProgressContainer.style.display = 'none';

    if (result.success && result.text) {
      ocrExtractedText.value = result.text;
      ocrEditArea.style.display = 'flex';
      ocrEditArea.scrollIntoView({ behavior: 'smooth' });
    } else {
      alert(result.error || 'Could not detect clear text from this image. Please ensure the screenshot has readable text.');
    }
  };

  reader.readAsDataURL(file);
}

// 7. Common Scams Tab
function initCommonScams() {
  const commonScams = [
    {
      title: 'Telegram Task & YouTube Like Scam',
      badge: 'High Financial Loss',
      description: 'Scammers promise ₹2,000–₹5,000 daily for liking YouTube videos or giving 5-star Google Map reviews. After paying ₹150 to build trust, they demand ₹5,000+ for "prepaid tasks" and freeze your money.',
      advisorySource: 'I4C Advisory (Ministry of Home Affairs)',
      sourceUrl: 'https://cybercrime.gov.in',
      sample: 'Ghar baithe kamai karein. Part time job: Daily 3000 rs for liking YouTube videos. Join Telegram channel: t.me/task_hiring to receive payment.'
    },
    {
      title: 'Refundable Registration Fee / Security Deposit',
      badge: 'Zero-Fee Violation',
      description: 'You receive an unsolicited job/internship selection letter. Before onboarding, they demand ₹499–₹2,000 as a "refundable gate pass" or "training fee". Real corporate recruiters never ask candidates for money.',
      advisorySource: 'CERT-In CIAD-2024-0050 & AICTE Zero-Fee Directive',
      sourceUrl: 'https://www.cert-in.org.in',
      sample: 'Congratulations! You are selected for Infosys Remote Internship. Kindly pay a refundable registration fee of Rs 499 to confirm your slot.'
    },
    {
      title: 'Fake Laptop Courier Charges & OTP Stealing',
      badge: 'Identity & Fund Theft',
      description: 'The scammer claims a company laptop, ID card, and uniform are being dispatched, but you must pay ₹1,500 for courier insurance via UPI. They then ask you for OTPs under the guise of "package tracking".',
      advisorySource: 'RBI BE(A)WARE Booklet (Employment Frauds)',
      sourceUrl: 'https://www.rbi.org.in',
      sample: 'Your company laptop and training kit have been packed. Send courier charges of ₹1,200 via UPI and share OTP received on your phone.'
    },
    {
      title: 'Lookalike Link with Brand Subdomain',
      badge: 'Credential Phishing',
      description: 'Fraudsters create fake links like `tcs.careers-portal-india.xyz` or `infosys-recruitment.top`. The brand name is in the subdomain or path, but the actual domain belongs to the scammer.',
      advisorySource: 'OWASP & Google Anti-Phishing Guidelines',
      sourceUrl: 'https://support.google.com/mail/answer/8253',
      sample: 'TCS NextStep Hiring Drive 2026: Apply online at http://tcs.campus-hiring.xyz/register'
    }
  ];

  commonScamsContainer.innerHTML = commonScams.map(cs => `
    <div class="scam-example-card">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem;">
        <h4 style="font-size: 0.95rem; font-weight: 700; color: var(--text-main);">${escapeHtml(cs.title)}</h4>
        <span class="scam-badge-tag">${escapeHtml(cs.badge)}</span>
      </div>
      <p style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.45;">${escapeHtml(cs.description)}</p>
      <div style="background: var(--bg-primary); padding: 0.6rem; border-radius: var(--radius-sm); border-left: 3px solid var(--primary); font-size: 0.82rem; font-family: var(--font-mono); color: var(--text-main);">
        "${escapeHtml(cs.sample)}"
      </div>
      <div style="font-size: 0.75rem; color: var(--text-subtle);">
        Official Advisory: <a href="${escapeHtml(cs.sourceUrl)}" target="_blank" rel="noopener noreferrer" style="color: var(--primary); text-decoration: underline;">${escapeHtml(cs.advisorySource)}</a>
      </div>
    </div>
  `).join('');
}

// Global Initialization
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initTabs();
  initSamples();
  initCheckingActions();
  initScreenshotTab();
  initCommonScams();
});

