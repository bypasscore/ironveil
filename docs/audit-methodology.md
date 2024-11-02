# IronVeil Audit Methodology

## Purpose

This document describes the systematic methodology IronVeil follows when conducting security audits of casino and iGaming platforms. The methodology is designed to be thorough, repeatable, and aligned with responsible disclosure practices.

## Prerequisites

Before starting an audit:

1. **Written authorization** — Obtain explicit written permission from the platform operator
2. **Scope definition** — Define which domains, APIs, and game types are in scope
3. **Test accounts** — Provision dedicated test accounts (never use real player accounts)
4. **Environment** — Confirm whether testing targets production or staging
5. **Communication channel** — Establish a secure channel for reporting critical findings

## Phase 1: Reconnaissance

### Objectives
- Map the platform's technology stack
- Identify all client-facing endpoints
- Catalog third-party integrations

### Activities
- Load the target in a clean browser session
- Record all network requests (XHR, WebSocket, script loads)
- Extract API endpoints from JavaScript bundles
- Identify CDN, WAF, and bot protection providers
- Note CAPTCHA providers and trigger conditions
- Document cookie structure and session management

### Output
- Technology inventory
- Endpoint catalog
- Initial risk surface assessment

## Phase 2: Detection Analysis

### Bot Detection Testing
1. Navigate the platform with a default automated browser
2. Execute detection vector probes (WebDriver, chrome.runtime, plugins, etc.)
3. Record which vectors the platform actively checks
4. Score detection coverage (0-10)

### Behavioral Analysis Testing
1. Inject event collectors into the page
2. Generate synthetic mouse movements, clicks, and keystrokes
3. Observe if the platform triggers challenges or blocks
4. Test with varying levels of human simulation quality

### Fingerprint Analysis
1. Collect full browser fingerprint from the platform
2. Identify which components the platform collects
3. Measure fingerprint entropy and uniqueness
4. Test fingerprint consistency across sessions

### CAPTCHA Classification
1. Identify CAPTCHA provider and version
2. Determine trigger conditions
3. Assess visual/interactive difficulty
4. Rate bypass difficulty on 1-10 scale

## Phase 3: Evasion Testing

### Fingerprint Spoofing
1. Generate a realistic spoof profile
2. Apply navigator, Canvas, WebGL, and AudioContext overrides
3. Verify overrides are effective
4. Test if the platform detects the spoofing

### Human Simulation
1. Generate Bezier curve mouse movements
2. Apply natural typing cadence with errors
3. Simulate realistic scrolling and page reading
4. Test if simulated behavior passes behavioral checks

### Timing Evasion
1. Apply session timing profiles (casual, focused, etc.)
2. Implement request rate management
3. Simulate break patterns and session length variation
4. Monitor for rate limiting or blocking

## Phase 4: Platform Security

### API Probing
1. Enumerate API endpoints (common paths + JS extraction)
2. Test rate limiting on each discovered endpoint
3. Probe for authentication bypass (header injection, method override)
4. Test for parameter tampering vulnerabilities
5. Check CORS configuration

### Game Integrity
1. Collect RNG output samples from game sessions
2. Run statistical tests (frequency, runs, serial correlation, gap)
3. Verify provably fair hash chains if implemented
4. Compare observed RTP against declared values

## Phase 5: Reporting

### Report Contents
1. **Executive summary** — High-level overview for stakeholders
2. **Risk score** — Aggregate risk rating (0-10)
3. **Findings table** — All findings with severity, description, evidence
4. **Phase details** — Detailed results from each audit phase
5. **Remediation recommendations** — Prioritized fix suggestions

### Output Formats
- **HTML** — Self-contained visual report for stakeholders
- **JSON** — Machine-readable for integration with security tools
- **SARIF** — GitHub/Azure compatible for CI/CD integration

### Severity Classification
| Level | Description |
|-------|-------------|
| Critical | Immediate exploitation possible, significant financial impact |
| High | Exploitable vulnerability with moderate effort |
| Medium | Weakness that could be exploited in combination with others |
| Low | Minor issue, best practice deviation |
| Info | Informational observation, no direct security impact |

## Responsible Disclosure

- Critical findings are reported immediately via the established communication channel
- Full reports are delivered within the agreed timeline
- Re-testing is available after remediation
- All test data and credentials are securely deleted after the engagement

## Frequency

For optimal security posture, we recommend:
- **Quarterly** full audits for high-traffic platforms
- **After major releases** targeting security-relevant features
- **Annual** comprehensive assessments including penetration testing
