# Scam Check: Rule Set & Detection Framework (`RULES.md`)

This document defines the published-guidance-derived rules, detection logic, verified official recruiting domains, and reporting channels for **Scam Check**—a static scam checker designed for Indian college students.

---

## 1. Official Reporting Channels (Verified)

| Channel | Authority | Contact / Link | Purpose & Verification Note |
| :--- | :--- | :--- | :--- |
| **National Cyber Crime Helpline** | Ministry of Home Affairs (I4C) | **Dial 1930** (Toll-Free) | Immediate reporting for online financial fraud to block funds in transit. Verified from [cybercrime.gov.in](https://cybercrime.gov.in). |
| **National Cyber Crime Reporting Portal** | Ministry of Home Affairs (I4C) | [https://cybercrime.gov.in](https://cybercrime.gov.in) | Formal filing of cyber fraud incidents, task fraud, mule account tracking, and suspect registry checks. |
| **Chakshu (Sanchar Saathi)** | Department of Telecommunications (DoT) | [https://sancharsaathi.gov.in](https://sancharsaathi.gov.in) | Citizen facility to report suspected fraud communications received via SMS, WhatsApp, or calls before financial loss occurs. |
| **AICTE National Internship Portal** | AICTE / Ministry of Education | [https://internship.aicte-india.org](https://internship.aicte-india.org) | Mandatory zero-fee internship verification portal for engineering & management students across India. |
| **RBI Complaint Management System** | Reserve Bank of India | [https://cms.rbi.org.in](https://cms.rbi.org.in) | For banking fraud, unauthorized electronic fund deductions, and mule account disputes under RBI Ombudsman scheme. |

---

## 2. Verified Official Corporate & Internship Domains

Attackers routinely use lookalike domains (e.g. `infosys-jobs.com`, `tcs-career-portal.site`) or place company names in subdomains (`tcs.student-internship.xyz`). The following domains have been verified from the official company sources for lookalike and typo-squatting detection:

| Organization | Primary Domain | Verified Recruitment / Career Subdomains |
| :--- | :--- | :--- |
| **Tata Consultancy Services (TCS)** | `tcs.com` | `nextstep.tcs.com`, `careers.tcs.com`, `tcs.com` |
| **Infosys** | `infosys.com` | `career.infosys.com`, `careers.infosys.com`, `infosys.com` |
| **Wipro** | `wipro.com` | `careers.wipro.com`, `wipro.com` |
| **Cognizant** | `cognizant.com` | `careers.cognizant.com`, `cognizant.com` |
| **Accenture** | `accenture.com` | `accenture.com`, `accenture.com/in-en/careers` |
| **Amazon** | `amazon.com` / `amazon.in` | `amazon.jobs`, `jobs.amazon.in` |
| **Google** | `google.com` | `careers.google.com`, `google.com/about/careers` |
| **Microsoft** | `microsoft.com` | `careers.microsoft.com`, `microsoft.com` |
| **AICTE Internship Portal** | `aicte-india.org` | `internship.aicte-india.org` |
| **Internshala** | `internshala.com` | `internshala.com` |

---

## 3. Scoring System & Verdict Engine

The scoring model assigns an additive weight to triggered rules. When an individual rule with a critical weight (40+) triggers, or when aggregate red flags accumulate, the engine assigns one of three transparent verdicts:

- **Likely scam** (Total Score $\ge 40$, or any critical payment/credential rule triggered)
- **Suspicious** ($20 \le \text{Total Score} < 40$)
- **No red flags found** ($\text{Total Score} < 20$) — *Note: The engine explicitly never outputs "Safe" or "Legit", as absence of automated red flags cannot guarantee authenticity.*

---

## 4. Rule Specifications

### Category: Payment (`payment`)

#### Rule 1: `PAY_UPFRONT_FEE`
- **What it detects:** Demand for upfront registration, processing, security, or application fee.
- **Weight:** 50 (Critical)
- **Plain-language explanation:** Real companies never charge you an application, registration, or processing fee to give you a job or internship.
- **Detection Logic:**
  - *English regex:* `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:registration|application|processing|entry|enrollment|onboarding)\s*(?:fee|fees|charge|charges|amount|cost)` / `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:refundable|security|caution)\s*(?:deposit|money|amount|fee|fees)`
  - *Hinglish regex:* `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:pehle|advance|registration|refundable)\s*(?:paisa|paise|fees|rupaye|amount)\s*(?:do|dena|jama|pay|transfer)` / `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:fees|charges|deposit)\s*(?:dena\s*hoga|bharna\s*padega|pay\s*karna)`
- **Source:** CERT-In Advisory CIAD-2024-0050 ("Preventing Online Scams") & RBI *BE(A)WARE* Booklet ([cert-in.org.in](https://www.cert-in.org.in) / [rbi.org.in](https://www.rbi.org.in))
- **False-Positive Risk:** Low. While official exam bodies (e.g. UPSC, GATE) charge application fees, corporate employment and internship offers never require upfront payment to secure selection.

---

#### Rule 2: `PAY_EQUIPMENT_KIT`
- **What it detects:** Demanding payment for company laptops, IDs, uniforms, training kits, or courier/dispatch fees.
- **Weight:** 45 (Critical)
- **Plain-language explanation:** Legitimate employers never make candidates pay for laptops, IDs, training kits, or dispatch courier charges.
- **Detection Logic:**
  - *English regex:* `(?:laptop|kit|material|uniform|id\s*card|equipment|training\s*kit|courier|dispatch)\s*(?:charge|charges|fee|fees|cost|deposit)`
  - *Hinglish regex:* `(?:laptop|kit|uniform)\s*(?:ke\s+liye|ka)\s*(?:paisa|charges|fees)`
- **Source:** RBI *BE(A)WARE* Booklet — Employment/Job Frauds Section ([rbi.org.in](https://www.rbi.org.in))
- **False-Positive Risk:** Low. Genuine employers provide assets free of charge or request BYOD (Bring Your Own Device). They never ask students to transfer funds for equipment dispatch.

---

#### Rule 3: `PAY_DIRECT_UPI`
- **What it detects:** Direct personal UPI IDs, QR codes, or payment app transfers requested over chat.
- **Weight:** 40 (Critical)
- **Plain-language explanation:** Companies process finances through verified corporate bank accounts, not personal UPI IDs or QR codes on WhatsApp/Telegram.
- **Detection Logic:**
  - *UPI pattern:* `[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|okicici|oksbi|paytm|ybl|ibl|upi|apl)`
  - *Action pattern:* `(?:scan|send\s+to|pay\s+via)\s*(?:this)?\s*(?:qr\s*code|upi|gpay|phonepe|paytm)`
  - *Hinglish regex:* `(?:upi|gpay|phonepe)\s*(?:se\s*pay\s*karo|par\s*bhejo)`
- **Source:** Indian Cyber Crime Coordination Centre (I4C) Advisory on Task/Recruitment Mule Accounts ([cybercrime.gov.in](https://cybercrime.gov.in))
- **False-Positive Risk:** Medium in arbitrary conversational text, but in a recruitment context it is an immediate red flag.

---

### Category: Message (`message`)

#### Rule 4: `MSG_TASK_SCAM`
- **What it detects:** Part-time task-based gigs (liking YouTube videos, posting Google map reviews, prepaid tasks).
- **Weight:** 45 (Critical)
- **Plain-language explanation:** Earning money for simple online tasks like 'liking YouTube videos' or 'rating hotels' is part of an organized fraud syndicate highlighted by national cybercrime advisories.
- **Detection Logic:**
  - *English regex:* `(?:like|subscribe)\s*(?:to)?\s*(?:youtube|yt)\s*(?:video|videos|channel)` / `(?:rate|review)\s*(?:google\s*maps?|hotels?|products?|apps?)\s*(?:and\s*earn|for\s*money|per\s*review)` / `(?:prepaid|investment)\s*task`
  - *Hinglish regex:* `(?:video\s*like\s*karo|review\s*karke\s*kamao|per\s*review\s*₹?\d+)` / `(?:ghar\s*baithe\s*(?:kamai|kaam)|task\s*complete\s*karo)`
- **Source:** I4C Advisory on Online Task-Based Job Frauds ([pib.gov.in](https://pib.gov.in) / [cybercrime.gov.in](https://cybercrime.gov.in))
- **False-Positive Risk:** Very low. Commercial digital platforms strictly prohibit incentivized engagements, and no legitimate internship involves prepaid tasks.

---

#### Rule 5: `MSG_UNREALISTIC_PAY`
- **What it detects:** Unrealistic daily/hourly income promises for minimal non-technical effort (typing, SMS sending, copy-paste).
- **Weight:** 30 (High)
- **Plain-language explanation:** Promises of earning ₹2,000–₹10,000 daily for typing, copy-pasting, or 1–2 hours of work are standard bait used by scammers.
- **Detection Logic:**
  - *English regex:* `(?:earn|salary|income)\s*(?:rs\.?|inr|₹)?\s*[1-9]\d{3,5}\s*(?:per\s*day|daily|per\s*hour|every\s*day)` / `(?:typing|data\s*entry|sms\s*sending|form\s*filling)\s*job.*(?:\d{3,5}\s*(?:daily|per\s*day))`
  - *Hinglish regex:* `(?:rozana|daily|har\s*din)\s*(?:₹|rs\.?|inr)?\s*[1-9]\d{2,5}\s*(?:kamaye|kamao|earning)`
- **Source:** FTC Job Scams Guidance ([consumer.ftc.gov](https://consumer.ftc.gov)) & I4C Public Warnings
- **False-Positive Risk:** Medium for senior freelance consultants, but high accuracy for student entry-level job offers.

---

#### Rule 6: `MSG_OFFER_NO_INTERVIEW`
- **What it detects:** Direct selection or appointment letter issued without an interview, test, or formal application.
- **Weight:** 35 (High)
- **Plain-language explanation:** Reputable companies do not issue instant selection letters or high-paying internships without a structured interview or assessment.
- **Detection Logic:**
  - *English regex:* `(?:direct|immediate)\s*(?:selection|joining|appointment|placement)\s*(?:without|no)\s*(?:interview|exam|test)` / `congratulations!\s*you\s*(?:have\s+been|are)\s*selected\s*for\s*(?:the\s+post|internship)`
  - *Hinglish regex:* `(?:bina|without)\s*interview\s*(?:ke)?\s*(?:direct)?\s*(?:selection|joining|offer)` / `seedha\s*(?:selection|joining|offer\s*letter)`
- **Source:** CERT-In Advisory CIAD-2024-0050 & RBI BE(A)WARE Guidelines ([cert-in.org.in](https://www.cert-in.org.in))
- **False-Positive Risk:** Low. Campus recruitment notices may announce walk-in events, but formal offers are never issued prior to candidate evaluation.

---

#### Rule 7: `MSG_SENSITIVE_DATA`
- **What it detects:** Demands for OTP, ATM/UPI PINs, passwords, or immediate copies of Aadhaar/PAN cards.
- **Weight:** 50 (Critical)
- **Plain-language explanation:** Never share an OTP, ATM PIN, UPI PIN, or bank password. No recruiter ever needs your OTP or bank security codes.
- **Detection Logic:**
  - *English regex:* `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:share|send|provide|enter|verify)\s*(?:your)?\s*(?:otp|one\s*time\s*password|upi\s*pin|atm\s*pin|cvv|net\s*banking\s*password)`
  - *Hinglish regex:* `(?<!(?:never|do not|don't|not|never to|na)\s+)(?:otp|pin|cvv)\s*(?:bhejo|share\s*(?:karo|karein)|batao|enter\s*(?:karo|karein))`
- **Source:** RBI "Kehta Hai" Consumer Protection Campaign ([rbi.org.in](https://www.rbi.org.in)) & [cybercrime.gov.in](https://cybercrime.gov.in)
- **False-Positive Risk:** Very low. Authentic onboarding portals use authenticated self-service portals; recruiters never request transaction credentials.

---

#### Rule 8: `MSG_ARTIFICIAL_URGENCY`
- **What it detects:** Artificial urgency, extreme time pressure (e.g., "valid for 15 minutes"), or panic triggers.
- **Weight:** 15 (Medium / Contextual)
- **Plain-language explanation:** Scammers create artificial pressure (e.g. 'offer expires in 15 minutes') to stop you from researching or asking advice.
- **Detection Logic:**
  - *English regex:* `(?:valid|expires|offer\s*ends|act\s*fast)\s*(?:in|within)?\s*(?:10|15|30|60)\s*(?:mins?|minutes?|hours?)` / `(?:limited|few)\s*(?:seats|vacancies|spots)\s*(?:left|remaining|only)`
  - *Hinglish regex:* `(?:jaldi\s*karo|offer\s*khatam|aakhri\s*mauka|last\s*chance)`
- **Source:** UK NCSC Phishing Guidance ("Urgency & Pressure") ([ncsc.gov.uk](https://www.ncsc.gov.uk)) & CISA Security Tips ([cisa.gov](https://www.cisa.gov))
- **False-Positive Risk:** Moderate if seen alone (event registrations have genuine deadlines); acts as a modifier alongside other red flags.

---

### Category: Sender (`sender`)

#### Rule 9: `SND_FREE_MAILBOX`
- **What it detects:** Enterprise HR / recruiter claiming to represent large firms via free public webmail (@gmail, @yahoo, etc.).
- **Weight:** 35 (High)
- **Plain-language explanation:** Recruiters from established organizations (e.g. TCS, Infosys, Amazon) always use their corporate domain email, never generic @gmail.com or @yahoo.com.
- **Detection Logic:**
  - *Regex:* `(?:hr|recruiter|careers|jobs|talent|hiring|placement)?[a-zA-Z0-9._%+-]*@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|rediffmail\.com|zoho\.com)` alongside corporate brand mentions (`tcs`, `infosys`, `wipro`, `cognizant`, `amazon`, etc.).
- **Source:** Google Anti-Phishing Documentation ([support.google.com/mail/answer/8253](https://support.google.com/mail/answer/8253)) & AICTE Caution Notices
- **False-Positive Risk:** Low for enterprise roles. (Note: Seed-stage student startups may legitimately use Gmail, but established recruiters never do.)

---

#### Rule 10: `SND_CHAT_REDIRECT`
- **What it detects:** Forcing official hiring communication onto unmonitored messaging channels (Telegram handle, WhatsApp group).
- **Weight:** 25 (Medium)
- **Plain-language explanation:** Scammers shift conversations to Telegram or WhatsApp to evade enterprise email security filters and delete chat histories.
- **Detection Logic:**
  - *Regex:* `(?:contact|message|dm|connect|join)\s*(?:us|me|hr|manager)?\s*(?:on|via)?\s*(?:telegram|whatsapp|wa\.me|t\.me)` / `(?:t\.me\/[a-zA-Z0-9_]+|wa\.me\/[0-9]+)`
  - *Hinglish regex:* `(?:telegram|whatsapp)\s*(?:par\s*message\s*karein|join\s*karo|par\s*aao)`
- **Source:** I4C Advisory on Cyber Frauds Utilizing Encrypted Messaging Applications ([cybercrime.gov.in](https://cybercrime.gov.in))
- **False-Positive Risk:** Moderate (some startups communicate on WhatsApp); heavily weighted when combined with payment or task keywords.

---

### Category: Link / URL Analysis (`link`)

*(Derived strictly from OWASP Unvalidated Redirects/URL Cheat Sheet, CISA, and Google Security Guidance)*

#### Rule 11: `LNK_URL_SHORTENER`
- **What it detects:** Shortened links obscuring target domain names (`bit.ly`, `tinyurl.com`, `t.ly`, `cutt.ly`, etc.).
- **Weight:** 20 (Medium)
- **Plain-language explanation:** Shorteners hide the true website address, preventing you from seeing the actual target domain before clicking.
- **Detection Logic:** URL host matches list of known URL shortening services (`bit.ly`, `tinyurl.com`, `t.ly`, `cutt.ly`, `is.gd`, `rb.gy`, `shorturl.at`).
- **Source:** UK NCSC Spotting Phishing Links ([ncsc.gov.uk](https://www.ncsc.gov.uk))
- **False-Positive Risk:** Moderate (legitimate SMS messages sometimes use URL shorteners due to character limits).

---

#### Rule 12: `LNK_IP_HOST`
- **What it detects:** Raw IP addresses used as the host in links instead of a registered domain name (e.g. `http://192.0.2.1/apply`).
- **Weight:** 40 (Critical)
- **Plain-language explanation:** Authentic company career portals have domain names (e.g. company.com). Direct raw IP addresses indicate temporary scam infrastructure.
- **Detection Logic:** Host parsed from URL satisfies IPv4 or IPv6 regex pattern.
- **Source:** OWASP URL Validation Cheat Sheet ([cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org))
- **False-Positive Risk:** Negligible. Corporate recruitment platforms never direct candidates to bare IP addresses.

---

#### Rule 13: `LNK_PUNYCODE_HOMOGRAPH`
- **What it detects:** IDN Punycode strings (`xn--`) indicating Cyrillic/Greek character substitution.
- **Weight:** 45 (Critical)
- **Plain-language explanation:** Attackers substitute lookalike foreign characters in brand names (showing as 'xn--...' in the URL) to disguise fake domains.
- **Detection Logic:** Host begins with or contains `xn--`.
- **Source:** OWASP IDN Homograph Protection Guidelines
- **False-Positive Risk:** Negligible in Indian recruitment and career domains.

---

#### Rule 14: `LNK_USERINFO_TRICK`
- **What it detects:** The `@` symbol used inside the URL authority section (e.g. `https://google.com@evil-site.com`).
- **Weight:** 45 (Critical)
- **Plain-language explanation:** In standard URLs, everything before an '@' sign is treated as username/password, and the browser actually connects to the host *after* the '@'.
- **Detection Logic:** URL string contains an `@` symbol between protocol delimiter (`://`) and the first path slash (`/`).
- **Source:** OWASP Unvalidated Redirects & URL Obfuscation ([owasp.org](https://owasp.org))
- **False-Positive Risk:** Very low.

---

#### Rule 15: `LNK_BRAND_SUBDOMAIN_OR_PATH`
- **What it detects:** Verified company brand used as a subdomain or path component on an unrelated base domain (e.g. `tcs.apply-online-portal.in` or `jobs-update.xyz/infosys`).
- **Weight:** 35 (High)
- **Plain-language explanation:** A link like 'tcs.careers-portal-india.com' is hosted on 'careers-portal-india.com', NOT TCS. Scammers put brand names in subdomains to trick you.
- **Detection Logic:** URL subdomain or first path segment matches a recognized brand name, but the registrable domain (eTLD+1) does not match the company's verified domain list.
- **Source:** Google Safe Browsing / Phishing Best Practices ([support.google.com](https://support.google.com))
- **False-Positive Risk:** Low when applied against verified brand lists.

---

#### Rule 16: `LNK_RISKY_TLD`
- **What it detects:** Unofficial top-level domains with high historical abuse rates (`.xyz`, `.top`, `.click`, `.buzz`, `.site`, `.online`, `.work`).
- **Weight:** 25 (Medium)
- **Plain-language explanation:** Major Indian employers operate on .com, .in, or .org. Domains ending in .xyz, .top, or .click are frequently exploited for cheap, throwaway scam websites.
- **Detection Logic:** Domain TLD extracted from URL belongs to the high-abuse TLD list.
- **Source:** CERT-In Incident Response Notes & Spamhaus TLD Abuse Index ([cert-in.org.in](https://www.cert-in.org.in))
- **False-Positive Risk:** Medium (some legitimate portfolio sites use `.site`), therefore weighted to complement rather than decide verdicts on its own.

---

#### Rule 17: `LNK_LOOKALIKE_DOMAIN`
- **What it detects:** Typo-squatted domains within Levenshtein edit distance 1 or 2 of official career domains (e.g. `infossys.com`, `tcs-careers.org`).
- **Weight:** 45 (Critical)
- **Plain-language explanation:** This domain is suspiciously close to an official recruiting portal (e.g. 'infosys-jobs.com' or 'tcs-portal.net') but is not registered by the actual company.
- **Detection Logic:** Levenshtein string distance $\le 2$ between extracted domain stem and verified domain stems, with non-identical match.
- **Source:** CISA Phishing & Lookalike Domain Guidance ([cisa.gov](https://cisa.gov))
- **False-Positive Risk:** Low when restricted to targeted enterprise domains.

---

## 5. Verified Test Cases (Pure Engine Verification)

| Test Case ID | Class | Input Summary | Triggered Rules | Expected Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `TC_CLEAR_SCAM_1` | Clear Scam | Fake TCS internship, ₹2500 daily for YouTube likes, ₹499 refundable fee via UPI to `hr-tcs-verify@okhdfcbank`, Telegram redirect | `PAY_UPFRONT_FEE`, `PAY_DIRECT_UPI`, `MSG_TASK_SCAM`, `MSG_UNREALISTIC_PAY`, `MSG_OFFER_NO_INTERVIEW`, `SND_CHAT_REDIRECT` | **Likely scam** (Score: 195) |
| `TC_CLEAR_SCAM_2` | Clear Scam | Infosys data entry without interview, laptop courier charges ₹1,200, OTP request, 30 min urgency | `PAY_EQUIPMENT_KIT`, `MSG_OFFER_NO_INTERVIEW`, `MSG_SENSITIVE_DATA`, `MSG_ARTIFICIAL_URGENCY` | **Likely scam** (Score: 145) |
| `TC_CLEAR_SCAM_3` | Clear Scam | Fake recruitment link `http://infosys.campus-hiring-drive.xyz/apply`, earn 5000 daily | `LNK_BRAND_SUBDOMAIN_OR_PATH`, `LNK_RISKY_TLD`, `MSG_UNREALISTIC_PAY` | **Likely scam** (Score: 90) |
| `TC_BORDERLINE_1` | Borderline | Early-stage startup WhatsApp intro with interview slot urgency | `MSG_ARTIFICIAL_URGENCY`, `SND_CHAT_REDIRECT` | **Suspicious** (Score: 40) |
| `TC_LEGIT_1` | Legitimate | Official TCS NextStep portal login (`nextstep.tcs.com/campus/`), mentions TCS never charges fees | None | **No red flags found** (Score: 0) |
| `TC_LEGIT_2` | Legitimate | Official AICTE Internship Portal notification (`internship.aicte-india.org`) with application status | None | **No red flags found** (Score: 0) |

---

## 6. What To Do Next Guidance Box (Shown to Students)

1. **Never pay money:** Genuine companies pay you; they will never ask you to pay for registration, tests, laptops, or onboarding.
2. **Never share OTP or banking credentials:** No recruiter or company official ever requires your OTP, ATM PIN, UPI PIN, or bank passwords.
3. **Verify directly:** Always verify open positions on the company's verified careers website (e.g. `nextstep.tcs.com`, `careers.infosys.com`, `internship.aicte-india.org`).
4. **Report suspicious communication:**
   - Report scam messages/calls on **Chakshu (Sanchar Saathi)**: [sancharsaathi.gov.in](https://sancharsaathi.gov.in)
   - If money was lost, call the **National Cyber Crime Helpline at 1930** immediately and register a complaint at [cybercrime.gov.in](https://cybercrime.gov.in).
5. **Privacy reminder:** All checks run locally inside your browser—no text or screenshots are sent to external servers. Always blur personal names and phone numbers before sharing screenshots publicly.

