import { metadata, reportingChannels, verifiedOfficialDomains, rules } from './rulesData.js';
import { analyzeText } from './textAnalyzer.js';
import { extractUrlsFromText, analyzeUrl } from './urlAnalyzer.js';

export const VERDICTS = {
  LIKELY_SCAM: 'Likely scam',
  SUSPICIOUS: 'Suspicious',
  NO_RED_FLAGS: 'No red flags found'
};

export function determineVerdict(score, triggeredRules) {
  const likelyScamThreshold = metadata.thresholds?.likely_scam ?? 40;
  const suspiciousThreshold = metadata.thresholds?.suspicious ?? 20;

  const hasCriticalRule = triggeredRules.some(r => r.weight >= 40);

  if (hasCriticalRule || score >= likelyScamThreshold) {
    return VERDICTS.LIKELY_SCAM;
  }
  if (score >= suspiciousThreshold) {
    return VERDICTS.SUSPICIOUS;
  }
  return VERDICTS.NO_RED_FLAGS;
}

export function mergeHighlightSpans(highlights, textLength) {
  if (!highlights || highlights.length === 0) return [];

  // Sort by start position, then by length descending
  const sorted = [...highlights].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const merged = [];

  for (const span of sorted) {
    if (span.start >= textLength) continue;
    const end = Math.min(span.end, textLength);

    if (merged.length === 0) {
      merged.push({ start: span.start, end, ruleIds: [span.ruleId] });
      continue;
    }

    const last = merged[merged.length - 1];
    if (span.start < last.end) {
      // Overlapping span
      if (end > last.end) {
        last.end = end;
      }
      if (!last.ruleIds.includes(span.ruleId)) {
        last.ruleIds.push(span.ruleId);
      }
    } else {
      merged.push({ start: span.start, end, ruleIds: [span.ruleId] });
    }
  }

  return merged;
}

export function analyzeMessage(text) {
  const cleanText = (text || '').trim();
  if (!cleanText) {
    return {
      score: 0,
      verdict: VERDICTS.NO_RED_FLAGS,
      triggeredRules: [],
      urlAnalyses: [],
      highlightSpans: [],
      meta: { checkedAt: new Date().toISOString() }
    };
  }

  // 1. Text Analysis
  const { triggeredRules: textTriggered, matchHighlights } = analyzeText(cleanText);

  // 2. Link Analysis from extracted URLs
  const urls = extractUrlsFromText(cleanText);
  const urlAnalyses = urls.map(u => analyzeUrl(u));
  const urlTriggered = [];

  for (const analysis of urlAnalyses) {
    for (const rule of analysis.triggeredRules) {
      urlTriggered.push(rule);
    }
  }

  // 3. Deduplicate triggered rules by id
  const ruleMap = new Map();
  for (const r of [...textTriggered, ...urlTriggered]) {
    if (!ruleMap.has(r.id)) {
      ruleMap.set(r.id, { ...r, occurrences: 1 });
    } else {
      const existing = ruleMap.get(r.id);
      existing.occurrences += 1;
      if (Array.isArray(r.matches)) {
        existing.matches = Array.from(new Set([...(existing.matches || []), ...r.matches]));
      }
    }
  }

  const triggeredRules = Array.from(ruleMap.values());

  // 4. Calculate total score
  const score = triggeredRules.reduce((sum, r) => sum + (r.weight || 0), 0);

  // 5. Determine verdict
  const verdict = determineVerdict(score, triggeredRules);

  // 6. Highlight spans for UI rendering
  const highlightSpans = mergeHighlightSpans(matchHighlights, cleanText.length);

  return {
    rawText: cleanText,
    score,
    verdict,
    triggeredRules,
    urlAnalyses,
    highlightSpans,
    reportingChannels,
    verifiedOfficialDomains,
    meta: { checkedAt: new Date().toISOString() }
  };
}

export function checkUrlOnly(urlStr) {
  const analysis = analyzeUrl(urlStr);
  const verdict = determineVerdict(analysis.score, analysis.triggeredRules);
  return {
    ...analysis,
    verdict,
    reportingChannels,
    meta: { checkedAt: new Date().toISOString() }
  };
}

