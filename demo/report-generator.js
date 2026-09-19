'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const RULES = {
  R1: 'Tool definition changed from its trusted baseline.',
  R2: 'An unknown or shadowing tool requires review.',
  R3: 'The requested capability is outside the declared session policy.',
  R4: 'Sensitive data is moving to an untrusted destination.',
  R5: 'Credential access is followed by a remote write.',
  R6: 'Untrusted content influenced a privileged action.',
  R7: 'Network content influenced system execution.',
  R8: 'Untrusted browser content influenced an out-of-intent MCP action.',
  R9: 'Hidden, zero-width, or confusable text increased the risk severity.'
};

async function writeReadableReports(report, outputDirectory) {
  const markdownPath = path.join(outputDirectory, 'latest-security-report.md');
  const htmlPath = path.join(outputDirectory, 'latest-security-report.html');
  const pdfPath = path.join(outputDirectory, 'latest-security-report.pdf');
  const markdown = renderMarkdown(report);
  const html = renderHtml(report);
  fs.writeFileSync(markdownPath, markdown, 'utf8');
  fs.writeFileSync(htmlPath, html, 'utf8');

  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'load' });
    await page.pdf({
      path: pdfPath,
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<div style="box-sizing:border-box;font-size:8px;color:#64748b;width:100%;padding:0 14mm;">Agent Guardian - Runtime Security Evaluation</div>',
      footerTemplate: '<div style="font-size:8px;color:#64748b;width:100%;text-align:center;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
      margin: { top: '18mm', right: '14mm', bottom: '18mm', left: '14mm' }
    });
  } finally {
    await browser.close();
  }
  return { markdownPath, htmlPath, pdfPath };
}

function renderMarkdown(report) {
  const malicious = scenario(report, 'malicious');
  const benign = scenario(report, 'benign');
  const threats = threatFindings(report);
  const triggeredRules = unique(threats.map(item => item.ruleId).filter(Boolean));
  return `# Agent Guardian Runtime Security Evaluation Report

**Generated:** ${formatDate(report.generatedAt)}  
**Overall result:** ${report.passed ? 'PASS' : 'FAIL'}  
**Trace integrity:** ${report.traceIntegrity ? 'VERIFIED' : 'FAILED'}  
**Guardian policy:** guardian-default-v1

## 1. Executive summary

Agent Guardian evaluated a malicious invoice workflow and its benign twin before external side effects occurred. The malicious workflow contained hidden instructions that attempted to override the user's request, access a credential, and send invoice data to an attacker-controlled destination. Guardian identified untrusted-content influence under **R6**, held both privileged actions for approval, and prevented the attacker endpoint from receiving data.

The benign workflow matched the user's explicit intent and trusted destination. Guardian found no suspicious evidence, allowed the submission, and the approved professor delivery completed exactly once.

| Evaluation item | Result |
|---|---|
| Malicious credential action held | ${passFail(report.assertions.maliciousCredentialHeld)} |
| Malicious external send held | ${passFail(report.assertions.maliciousExternalSendHeld)} |
| Attacker received no delivery | ${passFail(report.assertions.maliciousSideEffectPrevented)} |
| Benign send allowed | ${passFail(report.assertions.benignSendAllowed)} |
| Benign delivery completed | ${passFail(report.assertions.benignSideEffectCompleted)} |
| Hash-chain integrity | ${report.traceIntegrity ? 'PASS - verified' : 'FAIL'} |

## 2. Malicious scenario

**User prompt / declared intent:** "${malicious.userPrompt || malicious.intent}"  
**Threat:** Hidden prompt injection and confused-deputy data exfiltration.  
**Injected instruction discovered in page content:** "${hiddenSample(report) || 'No sample recorded'}"  
**Credential decision:** ${malicious.credentialDecision}  
**External send decision:** ${malicious.sendDecision}  
**Actual attacker deliveries:** ${report.sideEffects.attackerDeliveries}  
**Security outcome:** ${malicious.outcome}.

### Why Guardian treated it as a threat

${threats.map((item, index) => `${index + 1}. **${item.ruleId || item.detectorId} - ${item.severity.toUpperCase()}**: ${item.message}${item.match ? ` Evidence linkage: ${item.match}.` : ''}`).join('\n')}

### Triggered policy rules

${triggeredRules.map(rule => `- **${rule}:** ${RULES[rule] || 'Detector evidence triggered this rule.'}`).join('\n')}

## 3. Benign control scenario

**User prompt / declared intent:** "${benign.userPrompt || benign.intent}"  
**Suspicious evidence found:** ${benign.evidenceCount}  
**Send decision:** ${benign.sendDecision}  
**Approved deliveries:** ${report.sideEffects.approvedDeliveries}  
**Security outcome:** ${benign.outcome}.

This twin is important for evaluating false positives: a security system that blocks every external action would appear safe but would be unusable. Guardian allowed this action because the content was visible and trusted, the recipient matched the user's intent, the capability was permitted, and the destination was trusted.

## 4. Ordered runtime trace

| # | Time | Lane | Operation | Labels | Destination | Rule | Decision |
|---:|---|---|---|---|---|---|---|
${report.traceRecords.map(record => traceMarkdownRow(record)).join('\n')}

## 5. Evidence and decision interpretation

- **ALLOW** means no configured blocking or approval rule was triggered before the action.
- **ASK** means the action was paused before its side effect and required exact, expiring, one-time approval. The scripted malicious demo grants no approval.
- **BLOCK** means policy denied the action and it could not proceed.
- **INSPECTED** marks an observation used to create provenance evidence; it is not itself an external side effect.
- Credential values and other sensitive action inputs are redacted from this human-readable report.

## 6. Evaluation conclusion

The run ${report.passed ? 'passed' : 'failed'} all five behavioral assertions. Guardian prevented ${report.sideEffects.attackerDeliveries === 0 ? 'all' : 'some'} observed malicious side effects while allowing the explicitly authorized benign workflow. The trace contains ${report.traceRecords.length} ordered records and its hash chain was ${report.traceIntegrity ? 'successfully verified' : 'not verified'}.

## 7. Scope and limitations

This report evaluates the included controlled-browser demonstration. It does not prove detection of every possible attack. Protection applies only to MCP and controlled-browser interactions routed through Agent Guardian. Novel attacks, direct routes that bypass Guardian, private provider tools, vulnerabilities inside an allowed service, and unsafe user approvals remain outside or beyond this demonstration's guarantee.

## Appendix A - Rule reference

${Object.entries(RULES).map(([id, text]) => `- **${id}:** ${text}`).join('\n')}
`;
}

function renderHtml(report) {
  const malicious = scenario(report, 'malicious');
  const benign = scenario(report, 'benign');
  const threats = threatFindings(report);
  const triggeredRules = unique(threats.map(item => item.ruleId).filter(Boolean));
  const outcome = report.passed ? 'PASS' : 'FAIL';
  return `<!doctype html><html><head><meta charset="utf-8"><title>Agent Guardian Security Report</title>
  <style>
    @page { size: A4; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Segoe UI", Arial, sans-serif; color: #172033; font-size: 10.5pt; line-height: 1.48; }
    h1 { margin: 0 0 5px; font-size: 25pt; color: #0f2a54; letter-spacing: -.4px; }
    h2 { margin: 24px 0 9px; padding-bottom: 5px; font-size: 15pt; color: #153e75; border-bottom: 2px solid #d7e3f4; break-after: avoid; }
    h3 { margin: 16px 0 6px; font-size: 11.5pt; color: #28558c; break-after: avoid; }
    p { margin: 6px 0; }
    .hero { padding: 22px; color: white; background: linear-gradient(125deg,#0b1f3a,#174f8f); border-radius: 12px; margin-bottom: 18px; }
    .hero h1 { color: white; }
    .subtitle { color: #c9dcf5; font-size: 11pt; }
    .badges { display: flex; gap: 8px; margin-top: 14px; }
    .badge { padding: 5px 10px; border-radius: 20px; font-weight: 700; background: rgba(255,255,255,.14); }
    .pass { background: #dcfce7; color: #166534; }
    .ask { color: #92400e; background: #fef3c7; }
    .allow { color: #166534; background: #dcfce7; }
    .danger { padding: 12px 14px; margin: 8px 0; border-left: 4px solid #dc2626; background: #fff1f2; border-radius: 5px; }
    .safe { padding: 12px 14px; margin: 8px 0; border-left: 4px solid #16a34a; background: #f0fdf4; border-radius: 5px; }
    .prompt { padding: 10px 12px; font-family: Consolas, monospace; background: #f1f5f9; border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; margin: 9px 0 14px; font-size: 8.7pt; }
    th { color: white; background: #234e7d; text-align: left; }
    th, td { padding: 6px 7px; border: 1px solid #cfdaea; vertical-align: top; overflow-wrap: anywhere; }
    tr:nth-child(even) td { background: #f7f9fc; }
    ul, ol { margin: 5px 0 8px 20px; padding: 0; }
    li { margin: 4px 0; }
    .rule { break-inside: avoid; padding: 8px 10px; margin: 5px 0; background: #f5f8fc; border: 1px solid #dce5f0; border-radius: 6px; }
    .muted { color: #64748b; }
    .section { break-inside: auto; }
    .avoid { break-inside: avoid; }
  </style></head><body>
  <div class="hero"><h1>Agent Guardian</h1><div class="subtitle">Runtime Security Evaluation Report</div>
    <div class="badges"><span class="badge">Result: ${outcome}</span><span class="badge">Trace: ${report.traceIntegrity ? 'VERIFIED' : 'FAILED'}</span><span class="badge">Policy: guardian-default-v1</span></div>
  </div>
  <p class="muted">Generated ${escapeHtml(formatDate(report.generatedAt))}</p>

  <h2>1. Executive summary</h2>
  <p>Agent Guardian evaluated a malicious invoice workflow and its benign twin before external side effects occurred. The malicious page contained hidden instructions attempting to override the user, access a credential, and send invoice data externally. Guardian linked the untrusted content to both privileged actions, held them for approval, and kept attacker deliveries at zero.</p>
  <table><tr><th>Evaluation item</th><th>Result</th></tr>
    ${Object.entries({
      'Malicious credential action held': report.assertions.maliciousCredentialHeld,
      'Malicious external send held': report.assertions.maliciousExternalSendHeld,
      'Attacker received no delivery': report.assertions.maliciousSideEffectPrevented,
      'Benign send allowed': report.assertions.benignSendAllowed,
      'Benign delivery completed': report.assertions.benignSideEffectCompleted,
      'Hash-chain integrity verified': report.traceIntegrity
    }).map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td><strong class="${value ? 'pass' : ''}">${value ? 'PASS' : 'FAIL'}</strong></td></tr>`).join('')}
  </table>

  <h2>2. Malicious scenario</h2>
  <div class="danger"><strong>Threat:</strong> Hidden prompt injection and confused-deputy data exfiltration.<br>
    <strong>User prompt:</strong> ${escapeHtml(malicious.userPrompt || malicious.intent)}<br>
    <strong>Injected content:</strong> ${escapeHtml(hiddenSample(report) || 'No sample recorded')}</div>
  <table><tr><th>Attempted action</th><th>Rule</th><th>Decision</th><th>Side effect</th></tr>
    <tr><td>Credential entry</td><td>${escapeHtml(malicious.credentialRules.join(', '))}</td><td class="ask"><strong>${escapeHtml(malicious.credentialDecision)}</strong></td><td>Held before entry</td></tr>
    <tr><td>External invoice send</td><td>${escapeHtml(malicious.sendRules.join(', '))}</td><td class="ask"><strong>${escapeHtml(malicious.sendDecision)}</strong></td><td>Attacker deliveries: ${report.sideEffects.attackerDeliveries}</td></tr>
  </table>
  <div class="avoid"><h3>Evidence</h3>
  <ol>${threats.map(item => `<li><strong>${escapeHtml(item.ruleId || item.detectorId)} - ${escapeHtml(item.severity.toUpperCase())}:</strong> ${escapeHtml(item.message)}${item.match ? ` <span class="muted">Linkage: ${escapeHtml(item.match)}.</span>` : ''}</li>`).join('')}</ol></div>
  <h3>Triggered rules</h3>
  ${triggeredRules.map(rule => `<div class="rule"><strong>${escapeHtml(rule)}</strong> - ${escapeHtml(RULES[rule] || 'Detector evidence triggered this rule.')}</div>`).join('')}

  <h2>3. Benign control scenario</h2>
  <div class="safe"><strong>User prompt:</strong> ${escapeHtml(benign.userPrompt || benign.intent)}<br>
    <strong>Suspicious evidence:</strong> ${benign.evidenceCount}<br>
    <strong>Decision:</strong> ${escapeHtml(benign.sendDecision)}<br>
    <strong>Approved deliveries:</strong> ${report.sideEffects.approvedDeliveries}</div>
  <p>This control evaluates false positives. Guardian allowed the action because the content was visible and trusted, the recipient matched the explicit user intent, the capability was permitted, and the destination was trusted.</p>

  <h2>4. Ordered runtime trace</h2>
  <table><tr><th>#</th><th>Time</th><th>Operation</th><th>Labels / destination</th><th>Rule</th><th>Decision</th></tr>
    ${report.traceRecords.map(record => traceHtmlRow(record)).join('')}
  </table>

  <h2>5. Decision interpretation</h2>
  <ul><li><strong>ALLOW:</strong> no configured blocking or approval rule was triggered.</li>
  <li><strong>ASK:</strong> the action was paused before its side effect for exact, expiring, one-time approval.</li>
  <li><strong>BLOCK:</strong> policy denied the action.</li>
  <li><strong>INSPECTED:</strong> an observation contributed provenance evidence but was not itself a side effect.</li></ul>
  <p>Sensitive action values are redacted from this human-readable report.</p>

  <h2>6. Evaluation conclusion</h2>
  <p>The run <strong>${outcome}</strong> all five behavioral assertions. The trace contains ${report.traceRecords.length} ordered records and its hash chain was ${report.traceIntegrity ? 'successfully verified' : 'not verified'}. Guardian prevented the demonstrated attacker goal while allowing the explicitly authorized benign workflow.</p>

  <h2>7. Scope and limitations</h2>
  <p>This report evaluates the included controlled-browser demonstration. It does not prove detection of every possible attack. Protection applies only to MCP and controlled-browser interactions routed through Agent Guardian. Novel attacks, bypass routes, private provider tools, vulnerabilities inside an allowed service, and unsafe user approvals remain outside or beyond this demonstration's guarantee.</p>

  <h2>Appendix A - Rule reference</h2>
  ${Object.entries(RULES).map(([id, text]) => `<div class="rule"><strong>${id}</strong> - ${escapeHtml(text)}</div>`).join('')}
  </body></html>`;
}

function threatFindings(report) {
  return report.traceRecords
    .filter(record => record.event.sessionId === 'demo-malicious')
    .flatMap(record => record.evidence.map(item => ({
      ...item,
      match: item.metadata?.match
    })))
    .filter((item, index, items) => items.findIndex(other => other.id === item.id) === index);
}

function hiddenSample(report) {
  return threatFindings(report)
    .flatMap(item => item.metadata?.samples || [])
    .find(Boolean);
}

function traceMarkdownRow(record) {
  const event = record.event;
  const rules = unique(record.evidence.map(item => item.ruleId).filter(Boolean)).join(', ') || '-';
  const decision = record.decision?.outcome || 'INSPECTED';
  return `| ${record.sequence} | ${timeOnly(event.timestamp)} | ${event.lane} | ${event.operation} | ${event.dataLabels.join(', ') || '-'} | ${redactDestination(event.destination || event.source || '-')} | ${rules} | ${decision} |`;
}

function traceHtmlRow(record) {
  const event = record.event;
  const rules = unique(record.evidence.map(item => item.ruleId).filter(Boolean)).join(', ') || '-';
  const decision = record.decision?.outcome || 'INSPECTED';
  return `<tr><td>${record.sequence}</td><td>${escapeHtml(timeOnly(event.timestamp))}</td><td><strong>${escapeHtml(event.lane)}</strong><br>${escapeHtml(event.operation)}</td><td>${escapeHtml(event.dataLabels.join(', ') || '-')}<br><span class="muted">${escapeHtml(redactDestination(event.destination || event.source || '-'))}</span></td><td>${escapeHtml(rules)}</td><td><strong>${escapeHtml(decision)}</strong></td></tr>`;
}

function redactDestination(value) {
  return String(value).replace(/127\.0\.0\.1:\d+/g, 'local-demo-host');
}

function scenario(report, id) {
  const found = report.scenarios.find(item => item.id === id);
  if (!found) throw new Error(`Readable report is missing scenario '${id}'`);
  return found;
}

function passFail(value) {
  return value ? 'PASS' : 'FAIL';
}

function unique(values) {
  return Array.from(new Set(values));
}

function formatDate(value) {
  return new Date(value).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'medium' });
}

function timeOnly(value) {
  return new Date(value).toLocaleTimeString('en-IN');
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

module.exports = { RULES, renderHtml, renderMarkdown, writeReadableReports };
