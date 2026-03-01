# Contributing to Ghostline

Ghostline is built in the open. If you're here, you already pass the vibe check.

**Beginners are up front.** No gatekeeping. If you're learning, this is a good place to learn.

---

## 🏁 Step-by-Step Workflow

### 1. Fork & Clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/YOUR_USERNAME/ghostline.git
cd ghostline
```

### 2. Find Something to Work On

- Browse [`good first issue`](https://github.com/Mellowambience/ghostline/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) — bite-sized tasks for newcomers
- Browse [`help wanted`](https://github.com/Mellowambience/ghostline/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) — open tasks that need hands
- Or suggest something new — open an issue first before writing code

### 3. Claim the Issue

Leave a comment on the issue: `"I'd like to work on this"`. This avoids duplicate effort.

### 4. Create a Branch

```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/what-youre-fixing
```

Branch naming convention:
- `feat/` — new feature or module functionality
- `fix/` — bug fix
- `docs/` — documentation only
- `chore/` — tooling, configs, cleanup

### 5. Make Your Changes

Write your code. Keep it focused — one issue per PR.

### 6. Test Your Work

```bash
# Run the module you worked on, manually verify output
# All CLI modules must support --json flag:
python your_module.py --check test --json
```

### 7. Commit

```bash
git add .
git commit -m "feat(vaultcheck): add entropy scoring for passwords"
```

Commit message format: `type(module): short description`

### 8. Push & Open a PR

```bash
git push origin feat/your-feature-name
```

Then open a Pull Request on GitHub. In the PR description:
- Reference the issue (`Closes #42`)
- Briefly describe what you did and how to test it

---

## Module Standards

- CLI modules: **Python 3.11+** or **TypeScript (Node 20+)**
- All modules must have a `--json` output flag for pipeline composability
- No telemetry. Ever.
- No third-party analytics. Ever.
- Keep dependencies minimal — justify every import

---

## Merch Store

Design contributions welcome — ghost skull variants, terminal humor, dark aesthetic.  
Open an issue tagged `merch-design` with your concept before starting.

---

## Code of Conduct

Be technically rigorous. Be kind to humans. Don't be a threat actor.

---

*Questions? Open an issue or tag [@1Aether1Rose1](https://twitter.com/1Aether1Rose1) on X.*
