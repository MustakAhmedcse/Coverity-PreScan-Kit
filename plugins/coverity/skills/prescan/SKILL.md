---
name: prescan
description: Coverity pre-scan for .NET (C#), Next.js (TS/TSX), Python and Dockerfiles. Finds — and in fix mode fixes — the issues the client's Coverity security scan reports (null dereference, resource leak, dead code, hard-coded secrets, weak crypto, XSS, SQL injection, container running as root, etc.) before code is handed over. Use when the user asks to pre-scan, prepare for a Coverity / client security scan, or fix Coverity findings.
argument-hint: "[api|web|python|docker|all] [scan|fix]   e.g. /coverity:prescan web scan"
disable-model-invocation: true
---

You are preparing this repository for the client's **Coverity security scan** (policy AL1, "Carrier grade" severity mapping — a single Very-High or High finding fails it, so the target is ZERO findings).

Arguments: `$ARGUMENTS`
- Scope (first word): `api` = .NET/C# projects, `web` = Next.js app, `python` = Python code, `docker` = Dockerfiles/compose/k8s, `all` (default) = everything found in the repo.
- Mode (second word): `scan` (default) = find and report only, change no code. `fix` = fix items listed in `COVERITY_FINDINGS.md`.

## Before anything
1. Read [COVERITY_PRESCAN_GUIDE.md](COVERITY_PRESCAN_GUIDE.md) (in this skill's folder) fully. It is the rulebook:
   - Part A (A1–A14) = issues the client already found on our previous projects (SalesCom Modernization + Biometric). Highest priority.
   - Part B = other Coverity checks: B-1 .NET, B-2 Next.js, **B-3 Python** (Python maps Part A to Python syntax).
   - Part C = workflow, Part D = prevention config.
2. Read [Previous_Scan_Summary.md](Previous_Scan_Summary.md) for context on what failed before, why fixes were rejected, and which fixes created new issues.

## Mode: scan
1. Follow Guide Part C-1 (inventory) and C-2 (tool pass — run what is installed, note what is missing; never install tools without asking).
2. Run the C-3 ripgrep sweep for the chosen scope.
3. Do the C-4 manual review **file by file** — the important part. Coverity does inter-procedural data-flow, so read whole functions, not just grep hits. Prioritise:
   - Web: every `.tsx` under `components/`, `app/`, plus `lib/`, `components/ui/` (vendored shadcn code counts), `middleware.ts`, `app/api/**/route.ts`, server actions.
   - API: DAL / repository classes (Oracle access), BLL/services, controllers, `Program.cs`/service registration, auth/JWT/crypto helpers, file upload/download, external API clients (JObject parsing), `appsettings*.json`.
   - Python: DB access modules, API routes/views, background jobs/scripts, settings/config, file handling, subprocess/HTTP calls, data processing (division by zero in commission %).
   - Docker: every `Dockerfile*`, `docker-compose*.yml`, k8s manifests, `.dockerignore`.
4. For big scopes, split by top-level folder and use parallel sub-agents; each returns rows in the C-5 table format.
5. Write/overwrite `COVERITY_FINDINGS.md` at the repo root in the C-5 format, sorted by severity. Use Coverity's wording for the issue type (e.g. "Property access or function call before check for null or undefined", "Resource leak", "Container running as root").
6. Stop. Reply with: counts per severity, the top 10 riskiest items, and any questions that need a human decision. Do not edit source code in scan mode.

## Mode: fix
1. Load `COVERITY_FINDINGS.md`; work only on items with Status `Open` within the chosen scope. If the file doesn't exist, run scan mode first and stop for review.
2. Follow Guide Part C-6: batches by severity (Very High → High → Medium → Quality), ≤ ~20 files per batch, fix the pattern across the whole file, no behaviour change, no suppressions, no `!` non-null assertions, never add a null check *after* a use.
3. After each batch run the relevant checks (`npx tsc --noEmit`, `npx eslint .`, `dotnet build`, `ruff check .`, `mypy`, existing tests). If something breaks, fix it before the next batch.
4. Update each item's Status to `Fixed` with a one-line note of what changed.
5. When all batches are done, re-run Guide C-2 + C-3 for the scope; mark confirmed items `Verified` and add any new findings as `Open`.
6. Reply with a short summary: fixed counts, anything left open and why, and decisions needed from the user.

## Optional: prevention setup
If the user asks to "set up prevention" for this repo: propose (don't silently apply) the Part D config for the stacks present, and offer to append [CLAUDE.md.snippet.md](CLAUDE.md.snippet.md) to the repo's `CLAUDE.md` so new code stays Coverity-clean.
