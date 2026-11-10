import { verifiedOfficialDomains, rules } from './rulesData.js';

export function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,     // deletion
          dp[i][j - 1] + 1,     // insertion
          dp[i - 1][j - 1] + 1  // substitution
        );
      }
    }
  }
  return dp[m][n];
}

const SHORTENER_HOSTS = new Set([
  'bit.ly', 'tinyurl.com', 't.ly', 'cutt.ly', 'is.gd', 'rb.gy',
  'shorturl.at', 'ow.ly', 'buff.ly', 'soo.gd', 'qr.ae', 'v.gd'
]);

const RISKY_TLDS = new Set([
  'xyz', 'top', 'click', 'buzz', 'site', 'online', 'club', 'work',
  'loan', 'rest', 'cam', 'quest', 'win', 'vip', 'gq', 'cf', 'ml', 'tk'
]);

// Extract brand keywords and their official domains
const BRAND_MAP = [
  { brand: 'tcs', primary: 'tcs.com', allowed: ['tcs.com', 'careers.tcs.com', 'nextstep.tcs.com'] },
  { brand: 'infosys', primary: 'infosys.com', allowed: ['infosys.com', 'career.infosys.com', 'careers.infosys.com'] },
  { brand: 'wipro', primary: 'wipro.com', allowed: ['wipro.com', 'careers.wipro.com'] },
  { brand: 'cognizant', primary: 'cognizant.com', allowed: ['cognizant.com', 'careers.cognizant.com'] },
  { brand: 'accenture', primary: 'accenture.com', allowed: ['accenture.com'] },
  { brand: 'google', primary: 'google.com', allowed: ['google.com', 'careers.google.com'] },
  { brand: 'microsoft', primary: 'microsoft.com', allowed: ['microsoft.com', 'careers.microsoft.com'] },
  { brand: 'amazon', primary: 'amazon.com', allowed: ['amazon.jobs', 'jobs.amazon.in', 'amazon.com', 'amazon.in'] },
  { brand: 'aicte', primary: 'aicte-india.org', allowed: ['internship.aicte-india.org', 'aicte-india.org'] },
  { brand: 'internshala', primary: 'internshala.com', allowed: ['internshala.com'] }
];

export function extractUrlsFromText(text) {
  if (!text || typeof text !== 'string') return [];
  // Comprehensive regex matching http/https URLs and bare domains like t.me/..., wa.me/...
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:(?:t\.me|wa\.me|bit\.ly|tinyurl\.com)\/[^\s<>"'{}|\\^`]+)/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches.map(u => {
    let cleaned = u.replace(/[.,;:)\]]+$/, ''); // strip trailing punctuation
    if (!/^https?:\/\//i.test(cleaned)) {
      cleaned = 'https://' + cleaned;
    }
    return cleaned;
  })));
}

export function parseUrlSafely(urlStr) {
  try {
    let raw = urlStr.trim();
    if (!/^https?:\/\//i.test(raw)) {
      raw = 'https://' + raw;
    }
    const parsed = new URL(raw);
    return {
      success: true,
      rawUrl: urlStr,
      normalizedUrl: parsed.href,
      protocol: parsed.protocol,
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port,
      pathname: parsed.pathname,
      search: parsed.search,
      username: parsed.username,
      password: parsed.password
    };
  } catch (err) {
    return {
      success: false,
      rawUrl: urlStr,
      error: 'Invalid URL format'
    };
  }
}

export function getDomainStem(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    // Basic eTLD handling for .co.in, .gov.in, .org.in, .com
    if (['co.in', 'gov.in', 'org.in', 'ac.in', 'net.in'].some(t => hostname.endsWith('.' + t)) && parts.length >= 3) {
      return parts[parts.length - 3];
    }
    return parts[parts.length - 2];
  }
  return parts[0];
}

export function getTLD(hostname) {
  const parts = hostname.split('.');
  if (parts.length < 2) return '';
  return parts[parts.length - 1].toLowerCase();
}

export function analyzeUrl(urlStr) {
  const parsed = parseUrlSafely(urlStr);
  if (!parsed.success) {
    return {
      url: urlStr,
      valid: false,
      error: parsed.error,
      score: 10,
      triggeredRules: []
    };
  }

  const { hostname, pathname, username, rawUrl } = parsed;
  const triggered = [];
  const ruleMap = new Map(rules.map(r => [r.id, r]));

  // 1. @ symbol authority trick (LNK_USERINFO_TRICK)
  if (username || rawUrl.includes('@')) {
    const rule = ruleMap.get('LNK_USERINFO_TRICK');
    if (rule) {
      triggered.push({
        ...rule,
        matches: ['@ in URL authority']
      });
    }
  }

  // 2. IP Address host (LNK_IP_HOST)
  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIPv6 = /^\[?[a-fA-F0-9:]+\]?$/.test(hostname) && hostname.includes(':');
  if (isIPv4 || isIPv6) {
    const rule = ruleMap.get('LNK_IP_HOST');
    if (rule) {
      triggered.push({
        ...rule,
        matches: [hostname]
      });
    }
  }

  // 3. Punycode / IDN Homograph (LNK_PUNYCODE_HOMOGRAPH)
  if (hostname.includes('xn--') || /[^\u0000-\u007F]/.test(hostname)) {
    const rule = ruleMap.get('LNK_PUNYCODE_HOMOGRAPH');
    if (rule) {
      triggered.push({
        ...rule,
        matches: [hostname]
      });
    }
  }

  // 4. URL Shortener (LNK_URL_SHORTENER)
  if (SHORTENER_HOSTS.has(hostname) || hostname.endsWith('.short.gy')) {
    const rule = ruleMap.get('LNK_URL_SHORTENER');
    if (rule) {
      triggered.push({
        ...rule,
        matches: [hostname]
      });
    }
  }

  // 5. Risky TLD (LNK_RISKY_TLD)
  const tld = getTLD(hostname);
  if (RISKY_TLDS.has(tld)) {
    const rule = ruleMap.get('LNK_RISKY_TLD');
    if (rule) {
      triggered.push({
        ...rule,
        matches: [`.${tld}`]
      });
    }
  }

  // 6. Deep Subdomains / Obfuscation (classic phishing pattern)
  const hostParts = hostname.split('.');
  if (hostParts.length > 4) {
    triggered.push({
      id: 'LNK_DEEP_SUBDOMAINS',
      category: 'link',
      title: 'Excessive subdomain nesting',
      weight: 20,
      explanation: 'Unusually long subdomain structure often used in phishing kits to mimic deep internal corporate domains.',
      source: {
        name: 'OWASP Phishing & URL Structure Best Practices',
        url: 'https://cheatsheetseries.owasp.org'
      },
      falsePositiveRisk: 'Low',
      matches: [hostname]
    });
  }

  // 7. Brand in subdomain or path on untrusted domain (LNK_BRAND_SUBDOMAIN_OR_PATH)
  for (const entry of BRAND_MAP) {
    const brand = entry.brand;
    const isAllowedHost = entry.allowed.some(allowed => hostname === allowed || hostname.endsWith('.' + allowed));
    
    if (!isAllowedHost) {
      // Check if brand is in subdomains or path
      const subdomains = hostParts.slice(0, -2);
      const inSubdomain = subdomains.some(part => part.includes(brand));
      const inPath = pathname.toLowerCase().split('/').some(segment => segment.includes(brand));

      if (inSubdomain || inPath) {
        const rule = ruleMap.get('LNK_BRAND_SUBDOMAIN_OR_PATH');
        if (rule) {
          triggered.push({
            ...rule,
            matches: [inSubdomain ? `subdomain containing "${brand}"` : `path containing "${brand}"`]
          });
        }
        break;
      }
    }
  }

  // 8. Levenshtein Lookalike against verified official domains (LNK_LOOKALIKE_DOMAIN)
  const domainStem = getDomainStem(hostname);
  for (const official of verifiedOfficialDomains) {
    const officialStem = getDomainStem(official.primaryDomain);
    const isOfficial = official.careerDomains.some(cd => hostname === cd || hostname.endsWith('.' + cd));

    if (!isOfficial && domainStem !== officialStem) {
      // Compare domain stem
      const dist = levenshteinDistance(domainStem, officialStem);
      if (dist > 0 && dist <= 2 && domainStem.length >= 4) {
        const rule = ruleMap.get('LNK_LOOKALIKE_DOMAIN');
        if (rule) {
          triggered.push({
            ...rule,
            matches: [`"${domainStem}" is lookalike of "${officialStem}" (distance: ${dist})`]
          });
        }
        break;
      }
    }
  }

  const score = triggered.reduce((acc, r) => acc + r.weight, 0);

  return {
    url: urlStr,
    normalizedUrl: parsed.normalizedUrl,
    hostname,
    valid: true,
    score,
    triggeredRules: triggered
  };
}

