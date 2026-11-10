import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage, checkUrlOnly, VERDICTS } from '../src/engine/engine.js';
import { fictionalTestCases } from '../src/engine/rulesData.js';

describe('Scam Check Pure Engine Test Suite', () => {

  describe('Fictional Test Cases from rules.json', () => {
    for (const tc of fictionalTestCases) {
      test(`Sample [${tc.type}] ${tc.id}: ${tc.description}`, () => {
        const result = analyzeMessage(tc.input);

        // Verify verdict matches expectation
        assert.equal(
          result.verdict,
          tc.expectedVerdict,
          `Verdict mismatch for ${tc.id}: expected "${tc.expectedVerdict}", got "${result.verdict}" (score: ${result.score})`
        );

        // For clear scams, ensure score >= 40
        if (tc.type === 'clear_scam') {
          assert.ok(result.score >= 40, `Score should be >= 40 for clear scam, got ${result.score}`);
        }

        // For legitimate messages, ensure score < 20 and no red flags found
        if (tc.type === 'legitimate') {
          assert.equal(result.verdict, VERDICTS.NO_RED_FLAGS);
          assert.equal(result.triggeredRules.length, 0);
        }
      });
    }
  });

  describe('Indian Scam Patterns (English + Hinglish)', () => {
    test('Hinglish registration fees demand', () => {
      const msg = "Aapko pehle registration fees dena hoga 500 rupaye to start the work from home job.";
      const res = analyzeMessage(msg);
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
      assert.ok(res.triggeredRules.some(r => r.id === 'PAY_UPFRONT_FEE'));
    });

    test('Hinglish YouTube like task scam', () => {
      const msg = "Ghar baithe kamai karein. Bas YouTube video like karke kamao per day 3000 rs.";
      const res = analyzeMessage(msg);
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
      assert.ok(res.triggeredRules.some(r => r.id === 'MSG_TASK_SCAM'));
    });

    test('Hinglish OTP request', () => {
      const msg = "Selected for Amazon internship. Jaldi OTP share karein to confirm your slot.";
      const res = analyzeMessage(msg);
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
      assert.ok(res.triggeredRules.some(r => r.id === 'MSG_SENSITIVE_DATA'));
    });

    test('Corporate impersonator with Gmail address produces Suspicious or Likely Scam', () => {
      const msg = "Official TCS Hiring Manager: Send your CV to tcs.careers.placement@gmail.com for placement opportunities.";
      const res = analyzeMessage(msg);
      assert.equal(res.verdict, VERDICTS.SUSPICIOUS);
      assert.ok(res.triggeredRules.some(r => r.id === 'SND_FREE_MAILBOX'));

      // When combined with direct joining without interview, escalates to Likely scam
      const scamMsg = "Official TCS Recruiter: Selected directly without interview! Send details to tcs.careers.dept@gmail.com";
      const scamRes = analyzeMessage(scamMsg);
      assert.equal(scamRes.verdict, VERDICTS.LIKELY_SCAM);
      assert.ok(scamRes.score >= 40);
    });
  });

  describe('Link-Specific URL Heuristics', () => {
    test('Detects URL shorteners (bit.ly, tinyurl)', () => {
      const res = checkUrlOnly('https://bit.ly/tcs-internship-2026');
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_URL_SHORTENER'));
    });

    test('Detects raw IP hosts', () => {
      const res = checkUrlOnly('http://192.168.1.100/apply');
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_IP_HOST'));
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
    });

    test('Detects @ authority spoofing tricks', () => {
      const res = checkUrlOnly('https://google.com@phishing-career-site.com/verify');
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_USERINFO_TRICK'));
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
    });

    test('Detects brand in subdomain on untrusted domain', () => {
      const res = checkUrlOnly('https://tcs.fake-campus-portal.xyz/register');
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_BRAND_SUBDOMAIN_OR_PATH'));
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_RISKY_TLD'));
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
    });

    test('Detects lookalike domain (Levenshtein distance <= 2)', () => {
      const res = checkUrlOnly('https://infossys.com/careers');
      assert.ok(res.triggeredRules.some(r => r.id === 'LNK_LOOKALIKE_DOMAIN'));
      assert.equal(res.verdict, VERDICTS.LIKELY_SCAM);
    });

    test('Verified official domains trigger no red flags', () => {
      const officialLinks = [
        'https://nextstep.tcs.com/campus/',
        'https://careers.infosys.com/',
        'https://amazon.jobs/en/',
        'https://internship.aicte-india.org/'
      ];

      for (const link of officialLinks) {
        const res = checkUrlOnly(link);
        assert.equal(res.verdict, VERDICTS.NO_RED_FLAGS, `Failed for official link: ${link}`);
        assert.equal(res.triggeredRules.length, 0);
      }
    });
  });

  describe('Edge Cases & UI Safety', () => {
    test('Empty text input returns No Red Flags with 0 score', () => {
      const res = analyzeMessage('');
      assert.equal(res.verdict, VERDICTS.NO_RED_FLAGS);
      assert.equal(res.score, 0);
      assert.equal(res.triggeredRules.length, 0);
    });

    test('Never returns "Safe" or "Legit"', () => {
      const legitText = "Hi team, let's meet tomorrow at 10 AM to discuss the syllabus.";
      const res = analyzeMessage(legitText);
      assert.notEqual(res.verdict.toLowerCase(), 'safe');
      assert.notEqual(res.verdict.toLowerCase(), 'legit');
      assert.equal(res.verdict, VERDICTS.NO_RED_FLAGS);
    });

    test('Highlights spans correctly overlap without breaking string indices', () => {
      const sample = "Pay refundable security deposit of Rs 500 now.";
      const res = analyzeMessage(sample);
      assert.ok(res.highlightSpans.length > 0);
      for (const span of res.highlightSpans) {
        assert.ok(span.start >= 0);
        assert.ok(span.end <= sample.length);
        assert.ok(span.start < span.end);
      }
    });
  });

});

