# Contributing

We welcome contributions to the NeoXFortress Agent Risk Lab.

## What We're Looking For

- **New attack scenarios** — Additional MITRE ATLAS techniques (e.g., model poisoning, training data extraction, membership inference)
- **Policy engine rules** — New detection patterns for prompt injection, data classification, or tool abuse
- **Report improvements** — Better visualizations, additional compliance framework mappings (SOC 2, ISO 27001, FedRAMP)
- **Bug fixes** — Anything that breaks `python run_all.py` or produces invalid receipts

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scenario`)
3. Make your changes
4. Test: `python run_all.py` must complete without errors
5. Ensure any new receipts pass schema validation against [schema.json v0.1.1](https://github.com/NeoXFortress/agent-accountability-receipt)
6. Submit a pull request with a clear description

## Guidelines

- Keep scenarios **deterministic** — no LLM API calls in the base simulation
- Every scenario must produce a **structured log entry** and a **signed receipt**
- Follow existing code style (minimal dependencies, readable, well-commented)
- Update the README if adding new scenarios or features

## Code of Conduct

Be professional. This is a security-focused project used in regulated environments. Contributions should reflect that standard.

---

*Questions? Open an issue or email julio@neoxfortress.com*
