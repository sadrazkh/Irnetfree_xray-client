# PROJECT DOCUMENTATION RULES

Documentation is part of engineering, not cleanup. Project knowledge (decisions, status, constraints, open problems) must live in the repo, not only in chat history.

These rules work in two modes. Use the mode that matches the project's current state.

- **Mode A: Baseline.** One-time, full documentation pass. Used when the docs do not exist yet or no longer match the code.
- **Mode B: Maintenance.** Lightweight, change-driven updates. This is the default once a baseline exists.

---

## 1. Truth and Verification (applies in both modes)

- The codebase is the authority on what currently exists. Docs describe it; they never override it.
- Never invent technical details. Mark each claim as one of: **Verified** (checked against code, with file/function reference), **Assumption**, or **Recommendation**.
- Reference real files, modules, functions, and APIs wherever possible.
- Never mark an incomplete feature as done. Record unknowns explicitly instead of guessing.
- Never leave a doc describing an outdated implementation. If you spot a mismatch, fix it or log it in `KNOWN_ISSUES_AND_TECH_DEBT.md`.

## 2. What to Preserve (applies in both modes)

For any decision worth recording, capture the WHY, not only the WHAT:

- Why this approach, which alternatives were considered, why they were rejected.
- Constraints and assumptions behind it.
- Known limitations.
- What should not be changed without reconsideration.

Keep context that originated in informal discussion if it affects the project.

---

## 3. Mode A: Baseline (full set)

Create all of these once, verified against the actual code:

| File | Purpose |
|---|---|
| `MASTER_CONTEXT.md` | Project overview, current state, entry point to all other docs |
| `PRODUCT_SPEC.md` | Vision, requirements, features, business logic |
| `ARCHITECTURE.md` | Components and their relationships (Mermaid diagrams) |
| `TECHNICAL_SPEC.md` | Implementation details, APIs, data models |
| `IMPLEMENTATION_STATUS.md` | Feature-by-feature status (Done / Partial / Not started) |
| `DECISIONS_AND_RATIONALE.md` | Decision log (see format below) |
| `KNOWN_ISSUES_AND_TECH_DEBT.md` | Bugs, limitations, debt |
| `ROADMAP.md` | Priorities and planned work |
| `AI_WORKING_GUIDELINES.md` | Project-specific conventions and rules |
| `ENVIRONMENT_AND_SETUP.md` | Setup, config, how to run |
| `GLOSSARY.md` | Domain terms |
| `CHANGELOG.md` | Notable changes over time |
| `OPEN_QUESTIONS.md` | Unresolved questions and pending decisions |

Baseline requirements:

- Specific to this project, not generic templates. No filler sections.
- Every doc starts with `Last verified: YYYY-MM-DD` and the scope it was checked against.
- Finish with a consistency review across all documents (see section 5).
- Where history is unknown (months of past work), mark it `Unknown / reconstructed from code` rather than inventing a rationale.

## 4. Mode B: Maintenance (change-driven)

After the baseline, do not touch every file on every change. Update only what the change affects:

| If the change... | Update |
|---|---|
| Adds, removes, or changes a feature | `IMPLEMENTATION_STATUS.md` (+ `PRODUCT_SPEC.md` if behavior changed) |
| Changes structure, components, or data flow | `ARCHITECTURE.md` (+ `TECHNICAL_SPEC.md` if details changed) |
| Involves a real choice between options | `DECISIONS_AND_RATIONALE.md` |
| Finds or fixes a bug, limitation, or shortcut | `KNOWN_ISSUES_AND_TECH_DEBT.md` |
| Changes setup, config, or run steps | `ENVIRONMENT_AND_SETUP.md` |
| Introduces a new domain term | `GLOSSARY.md` |
| Raises or answers an open question | `OPEN_QUESTIONS.md` |
| Changes priorities or scope | `ROADMAP.md` |
| Is a bug fix, typo, refactor with no behavior change, or style tweak | Nothing (git history is enough) |

Other maintenance rules:

- **Significant** means: changes behavior, structure, a public interface, a dependency, or reflects a decision with trade-offs. Everything else is not significant.
- `CHANGELOG.md` gets one line per release or milestone, not per commit. Summarize from git; do not hand-write every change.
- `MASTER_CONTEXT.md` is updated only when the overall state or direction changes.
- A doc update is part of the same change that caused it, not postponed.

### Decision entry format

```markdown
## D-NNN: <short title>  (YYYY-MM-DD)
- **Context:** what problem or constraint triggered this
- **Decision:** what was chosen
- **Alternatives considered:** option A (rejected because ...), option B (...)
- **Consequences / limitations:** ...
- **Do not change without reconsidering:** ...
- **Status:** Verified in code | Assumption
```

## 5. Milestone Consistency Review

At the end of every substantial milestone (and at the end of Mode A):

1. Check that `IMPLEMENTATION_STATUS.md` matches the code.
2. Check that `ARCHITECTURE.md` and `TECHNICAL_SPEC.md` match the code.
3. Check that no decision in `DECISIONS_AND_RATIONALE.md` contradicts current implementation.
4. Check that `KNOWN_ISSUES_AND_TECH_DEBT.md` and `ROADMAP.md` do not list the same item inconsistently.
5. Resolve or log every mismatch found. Update `Last verified` dates on files you checked.
6. Add a short `CHANGELOG.md` entry for the milestone.

## 6. Quality Standard

Documentation must be accurate, structured, consistent across files, and useful to both human developers and AI assistants. Use Markdown, tables, code examples, and Mermaid diagrams where they help. Prefer short and correct over long and generic.
