# Contributing to Sentinel Mesh

Thank you for contributing to **Sentinel Mesh — Autonomous 8-Agent SOC Intelligence Platform**.

To ensure clear, traceable development, please follow our commit conventions and development standards.

---

## 📌 Commit Message Conventions

All commits must follow standard conventional commit prefixes:

- `feat:` — New feature or major enhancement (e.g. `feat: integrate AbuseIPDB threat intelligence with caching and fallback`)
- `fix:` — Bug fix or error resolution (e.g. `fix: show visible demo mode banner instead of silent fallback`)
- `test:` — Adding or updating unit/integration tests (e.g. `test: add coverage for approval gate, containment, commander, and threat intel`)
- `docs:` — Documentation or roadmap updates (e.g. `docs: add V2 roadmap and commit conventions`)
- `refactor:` — Code changes that neither fix a bug nor add a feature

> **Rule**: Do not rewrite, amend, or fake git commit history. Maintain a clean, forward-only commit log.

---

## 🛠️ Development Guidelines

1. **Structured Outputs**: All LLM agent communications must use schema validation via Pydantic models.
2. **Fallback Safety**: External API integrations (such as AbuseIPDB) must include in-memory TTL caching and graceful fallback paths with explicit logging.
3. **Sandboxed Containment**: Any destructive containment action must execute against isolated sandbox targets with post-execution verification round-trips.
4. **Test-Driven Security**: High-stakes code paths (human approval gates, containment execution, commander verdict deltas) must maintain unit test coverage with stubbed/mocked LLM clients.
