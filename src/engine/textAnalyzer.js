import { rules } from './rulesData.js';

// Checks if a match is immediately preceded by a cautionary negation phrase
// Avoids regex lookbehind syntax for 100% compatibility with older Safari / WebKit engines.
function isPrecededByNegation(text, matchIndex) {
  if (matchIndex <= 0) return false;
  const windowStart = Math.max(0, matchIndex - 35);
  const preceding = text.slice(windowStart, matchIndex);
  // Match English and Hinglish negation phrases directly before the action
  return /(?:never|do not|don't|not|never to|kisi se|kabhi|na)\s+$/i.test(preceding);
}

export function analyzeText(text) {
  if (!text || typeof text !== 'string') {
    return {
      triggeredRules: [],
      matchHighlights: []
    };
  }

  const triggeredRules = [];
  const matchHighlights = [];

  // Filter text-based rules (payment, message, sender categories with regex patterns)
  const textRules = rules.filter(r => r.logic && r.logic.type === 'regex' && Array.isArray(r.logic.patterns));

  for (const rule of textRules) {
    let ruleMatched = false;
    const ruleMatches = [];

    for (const patternStr of rule.logic.patterns) {
      try {
        const regex = new RegExp(patternStr, 'gi');
        let match;
        while ((match = regex.exec(text)) !== null) {
          const matchedText = match[0];
          if (!matchedText || matchedText.length === 0) continue;

          // For payment and credential rules, check if this is cautionary advice ("Never share OTP", "Never pay fees")
          if ((rule.category === 'payment' || rule.id === 'MSG_SENSITIVE_DATA') && isPrecededByNegation(text, match.index)) {
            continue;
          }

          ruleMatched = true;
          ruleMatches.push(matchedText);
          matchHighlights.push({
            ruleId: rule.id,
            category: rule.category,
            title: rule.title,
            start: match.index,
            end: match.index + matchedText.length,
            text: matchedText
          });
        }
      } catch (err) {
        console.error(`Error executing regex for rule ${rule.id}:`, err);
      }
    }

    if (ruleMatched) {
      triggeredRules.push({
        id: rule.id,
        category: rule.category,
        title: rule.title,
        weight: rule.weight,
        explanation: rule.explanation,
        source: rule.source,
        falsePositiveRisk: rule.falsePositiveRisk,
        matches: Array.from(new Set(ruleMatches))
      });
    }
  }

  return {
    triggeredRules,
    matchHighlights
  };
}
