# IronVeil

**Casino and iGaming Security Audit Framework**

IronVeil is a comprehensive security auditing framework for casino and iGaming platforms. It tests platform integrity against bot detection bypass, behavioral analysis evasion, CAPTCHA circumvention, and automated gameplay detection.

Built for authorized security assessments of iGaming platforms.

## Features

- **Bot Detection Analysis** — Probes platform bot detection capabilities including WebDriver flags, navigator properties, Chrome runtime checks, and headless indicators
- **Behavioral Analysis** — Tests mouse movement patterns, click timing distributions, keystroke dynamics, and ML-based pattern classification
- **Browser Fingerprinting** — Collects and analyzes Canvas, WebGL, WebGL2, AudioContext, navigator, font, and screen fingerprints
- **CAPTCHA Classification** — Detects and classifies reCAPTCHA (v2/v3/Enterprise), hCaptcha, Turnstile, FunCaptcha, GeeTest, and custom implementations
- **Human Simulation** — Generates Bezier curve mouse movements, natural typing cadence, and realistic scroll patterns
- **Fingerprint Spoofing** — Canvas noise injection, WebGL parameter randomization, navigator property overrides
- **Timing Evasion** — Randomized delays, session length variation, break patterns, rate-limit-aware scheduling
- **API Security Probing** — Endpoint discovery, rate limit testing, authentication bypass testing
- **Platform Integrity** — RNG fairness testing, payout rate verification, provably fair validation
- **Reporting** — HTML, JSON, and SARIF output formats

## Installation

```bash
pip install -e .
```

For browser automation:
```bash
# Playwright (recommended)
pip install playwright
playwright install chromium

# Or Selenium
pip install selenium
```

## Quick Start

```bash
# Run a full audit
ironveil audit https://target-platform.com

# Use specific timing profile
ironveil audit https://target-platform.com --profile focused

# Skip certain phases
ironveil audit https://target-platform.com --skip-evasion

# JSON output only
ironveil audit https://target-platform.com -f json

# Show configuration
ironveil config show

# Validate configuration
ironveil config validate
```

## Configuration

IronVeil uses YAML configuration files. Generate a default config:

```bash
ironveil config init
```

Configuration is loaded from (in order of priority):
1. CLI `--config` flag
2. `./ironveil.yaml`
3. `~/.ironveil/config.yaml`
4. Built-in defaults

Environment variables with `IRONVEIL_` prefix override config values:
```bash
export IRONVEIL_BROWSER__HEADLESS=false
export IRONVEIL_SESSION__MAX_CONCURRENT_SESSIONS=10
```

## Project Structure

```
ironveil/
├── core/
│   ├── engine.py          # Audit orchestration
│   ├── session.py         # Session & fingerprint rotation
│   └── config.py          # YAML configuration system
├── detection/
│   ├── bot_detector.py    # Bot detection analysis
│   ├── behavioral.py      # Behavioral analysis + ML
│   ├── fingerprint.py     # Browser fingerprint collection
│   └── captcha.py         # CAPTCHA detection & classification
├── evasion/
│   ├── human_sim.py       # Human behavior simulation
│   ├── fingerprint_spoof.py  # Fingerprint spoofing
│   └── timing.py          # Timing evasion
├── platform/
│   ├── api_probe.py       # API endpoint security testing
│   └── integrity.py       # RNG & payout verification
├── reporting/
│   ├── html_report.py     # HTML report generation
│   └── json_export.py     # JSON & SARIF export
└── utils/
    ├── browser.py         # Playwright/Selenium wrapper
    ├── proxy.py           # Proxy rotation & health checks
    └── crypto.py          # Token analysis & hash utilities
```

## Audit Phases

1. **Initialization** — Browser setup, session pool creation, config validation
2. **Reconnaissance** — Target loading, technology stack identification
3. **Detection Analysis** — Bot detection, behavioral analysis, fingerprinting, CAPTCHA
4. **Evasion Testing** — Fingerprint spoofing, human simulation verification
5. **Platform Analysis** — API probing, rate limit testing, auth bypass testing
6. **Integrity Checks** — RNG fairness, payout verification
7. **Reporting** — HTML, JSON, SARIF report generation

## Legal Disclaimer

IronVeil is designed for **authorized security assessments only**. Always obtain written permission before testing any platform. Unauthorized use against platforms you do not own or have permission to test may violate applicable laws.

## Contact

- **Email:** [contact@bypasscore.com](mailto:contact@bypasscore.com)
- **Telegram:** [@bypasscore](https://t.me/bypasscore)
- **Web:** [bypasscore.com](https://bypasscore.com)

## Support

Help keep BypassCore open-source and independent.

| Network | Address |
|---------|---------|
| **Polygon** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Ethereum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **BSC** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Arbitrum** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Optimism** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |
| **Avalanche** | `0xd0f38b51496bee61ea5e9e56e2c414b607ab011a` |

USDT / USDC / ETH / BNB accepted on all networks.

## License

MIT License — see [LICENSE](LICENSE) for details.
