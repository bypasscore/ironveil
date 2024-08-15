# Casino Platform Security Model

## Overview

Modern online casino and iGaming platforms implement multi-layered security models to protect against fraud, bonus abuse, collusion, and automated gameplay. This document outlines the common security architecture that IronVeil is designed to audit.

## Layer 1: Network and Infrastructure

### DDoS Protection
- Cloudflare, Akamai, or AWS Shield
- Rate limiting at CDN edge
- Geographic IP filtering for licensed jurisdictions

### TLS and Certificate Pinning
- Minimum TLS 1.2, most platforms enforce TLS 1.3
- Certificate pinning in mobile applications
- HSTS with long max-age values

### API Gateway
- Authentication token validation
- Request signing (HMAC-based)
- Rate limiting per user/IP/session
- Input validation and sanitization

## Layer 2: Bot Detection and Automation Prevention

### Browser Fingerprinting
Platforms collect and analyze:
- **Canvas fingerprint** — Rendering differences across GPU/driver combinations
- **WebGL fingerprint** — GPU vendor, renderer, supported extensions
- **AudioContext fingerprint** — Audio processing stack characteristics
- **Navigator properties** — User agent, platform, language, hardware concurrency
- **Font enumeration** — Installed font list via CSS measurement
- **Screen properties** — Resolution, color depth, device pixel ratio

### Automation Detection
- `navigator.webdriver` flag checking
- Chrome DevTools Protocol detection
- Selenium/Playwright artifact detection
- Stack trace analysis for automation frameworks
- Missing browser APIs (chrome.runtime, plugins)

### Behavioral Analysis
- Mouse movement trajectory analysis (Bezier vs. linear)
- Click timing distribution (coefficient of variation)
- Keystroke dynamics (dwell time, flight time)
- Scroll behavior patterns
- Session activity patterns (idle time, session duration)
- Page interaction sequences

## Layer 3: CAPTCHA and Challenge Systems

### Common Implementations
- **reCAPTCHA v2** — Image classification challenges
- **reCAPTCHA v3** — Invisible score-based assessment
- **reCAPTCHA Enterprise** — Advanced risk analysis with session tracking
- **hCaptcha** — Privacy-focused alternative with bot scoring
- **Cloudflare Turnstile** — Invisible challenge with managed rules
- **FunCaptcha/Arkose** — 3D puzzle-based challenges
- **GeeTest** — Slider and interaction-based challenges

### Trigger Conditions
- Account registration
- Login (especially after failed attempts)
- Financial transactions (deposit/withdrawal)
- Suspicious activity detection
- Rate limit threshold breach

## Layer 4: Game Integrity

### Random Number Generation
- Hardware RNG or certified PRNG algorithms
- Server-side seed generation with hash commitments
- Provably fair implementations (hash chain verification)
- Regular third-party RNG audits (eCOGRA, iTech Labs, GLI)

### Payout Monitoring
- Real-time RTP (Return To Player) tracking
- Statistical deviation alerts
- Per-game and per-player payout analysis
- Regulatory reporting compliance

### Anti-Collusion
- Multi-account detection (device fingerprint, payment method, IP)
- Poker hand history analysis for collusion patterns
- Chip dumping detection
- Shared device/network detection

## Layer 5: Account Security

### Authentication
- Multi-factor authentication (SMS, TOTP, email)
- Device registration and trust scoring
- Geo-velocity checks
- Session management with rolling tokens

### Fraud Prevention
- KYC (Know Your Customer) verification
- AML (Anti-Money Laundering) transaction monitoring
- Self-exclusion system integration
- Responsible gambling limits enforcement

## IronVeil Audit Scope

IronVeil tests layers 2-4 by:
1. Probing bot detection capabilities and identifying weaknesses
2. Testing behavioral analysis sensitivity with simulated patterns
3. Classifying CAPTCHA implementations and assessing bypass difficulty
4. Verifying RNG fairness through statistical testing
5. Validating payout rate accuracy
6. Testing API endpoint security (rate limiting, auth bypass)

All testing is performed under authorized security assessment agreements.
