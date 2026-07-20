# Ghostline — Prioritized Roadmap

*Living doc. Updated as milestones land. Goal: move from "early-alpha with strong bones" to "credible, installable, trustworthy privacy-first security CLI."*

## Tier 1 — Polish & trust signals (do first; low risk, high signal)
- [x] **Fix `shadowaudit` probe/error handling** — probe failure no longer fabricates TLS/redirect fails; single `error` state. (2026-07-19)
- [x] **Add root CI** — `.github/workflows/ci.yml` runs `pytest` per module on push/PR. (2026-07-19)
- [ ] **Close stale issues #1–#5** — implemented in the July "Complete Ghostline" commit; close with a note linking the PR.
- [ ] **Add GitHub topics** — `security`, `cli`, `python`, `privacy`, `osint`, `pentest`, `infosec`.
- [ ] **Fix `shadowaudit` score display** — ensure `error` state renders distinctly in the CLI (not as 0/score confusion).

## Tier 2 — Packaging & friction (unlock adoption)
- [ ] **Publish `ghostline-cli` to PyPI** — the dispatcher + `ghostline modules` status command.
- [ ] **Publish one flagship module to PyPI** — `bookmark-audit` or `vaultcheck` (best-tested, most shippable).
- [ ] **One-command install doc** — `pip install ghostline-cli bookmark-audit vaultcheck` should just work.
- [ ] **Slim `ghost-scan` data bundle** — generate `service_map.json` at build, or ship a 50KB default + fetch-full flag.

## Tier 3 — Capability & coherence (the actual product)
- [ ] **Flagship narrative** — lead with `bookmark-audit` (offline, polished) + `vaultcheck` (strong core) as the demo pair.
- [ ] **`accountwatch` Phase 1** — verify Meta + GitHub token UX and baseline security before advertising.
- [ ] **`phantomtrace` legal/disclosure guard** — explicit per-run consent + scope banner; user carries the burden, make it unmissable.
- [ ] **Unified report format** — one JSON/Markdown schema across all 7 modules so the dispatcher can compose a single audit.

## Tier 4 — Deferred (until OSS earns trust)
- [ ] **Paid Next.js dashboard ($9–29/mo)** — only after CI + releases + 10+ external users. The `web/` folder is roadmap, not MVP.
- [ ] **PyPI for all 7 modules** — after the flagship proves the install path.

## Principles (non-negotiable)
- **No telemetry. Ever.** (contributing guideline)
- **Authorized use only** warnings stay on every entry point.
- **Composition + privacy + unified CLI** is the differentiator — not raw capability vs nmap/ZAP.

## Grade trajectory
- Today: **C+ / early alpha, strong bones**
- After Tier 1: **B-** (CI + clean issues + fixed bugs)
- After Tier 2: **B** (installable, discoverable)
- After Tier 3: **B+** (coherent product, real demos)
