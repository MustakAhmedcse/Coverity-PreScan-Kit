# Coverity Pre-Scan — Claude Code plugin for the team

Find and fix the issues the client's **Coverity** security scan reports — **before** we hand code over — in .NET, Next.js, Python and Docker repos.
Built from real client scan results: SalesCom Modernization (13 rounds, 212 issues) + Biometric (11 issues).

```
/coverity:prescan all scan      → writes COVERITY_FINDINGS.md, changes no code
/coverity:prescan web fix       → fixes Open items for the Next.js part, in batches
scopes: api | web | python | docker | all      modes: scan | fix
```

## Repo layout

```
.claude-plugin/marketplace.json          ← marketplace "team-coverity"
plugins/coverity/
  .claude-plugin/plugin.json             ← plugin "coverity"
  skills/prescan/
    SKILL.md                             ← the /coverity:prescan workflow
    COVERITY_PRESCAN_GUIDE.md            ← rulebook (Part A past issues, B per language, C workflow, D prevention config)
    Previous_Scan_Summary.md             ← what failed before and why
    CLAUDE.md.snippet.md                 ← always-on coding rules for a repo's CLAUDE.md
data/Previous_Scan_All_Issues.csv        ← raw data from the 20 SalesCom PDF reports (not loaded by Claude)
```

## 1. Install (each team member, once)

**Option A — from the team Git repo (recommended)**
```bash
claude plugin marketplace add https://<git-server>/<org>/coverity-claude-kit.git
claude plugin install coverity@team-coverity
```
(GitHub repos can use the short form `claude plugin marketplace add <org>/coverity-claude-kit`. Inside a Claude Code terminal session you can do the same with `/plugin`.)

**Option B — from the shared OneDrive / network folder (no Git)**
```bash
claude plugin marketplace add "E:/Softwere Installation/OneDrive/New Salescom CR24/Code Scaning/Coverity-PreScan-Kit"
claude plugin install coverity@team-coverity
```
Use the path where the folder is synced on *your* machine.

Restart Claude Code, open any project and type `/coverity:prescan`.

## 2. Auto-enable it in a project repo (optional)

Commit this into the project's `.claude/settings.json`. Anyone who opens the repo in Claude Code and trusts it gets asked to install the plugin:
```json
{
  "extraKnownMarketplaces": {
    "team-coverity": {
      "source": { "source": "git", "url": "https://<git-server>/<org>/coverity-claude-kit.git" }
    }
  },
  "enabledPlugins": { "coverity@team-coverity": true }
}
```

## 3. Daily use in a repo

1. `/coverity:prescan all scan` → review `COVERITY_FINDINGS.md` (answer any questions Claude lists).
2. `/coverity:prescan <scope> fix` per scope → Claude fixes in batches and runs build/lint/tests after each batch.
3. `/coverity:prescan all scan` again → aim for zero open items, then send to the client.
4. Optional: ask Claude to "set up prevention" — it proposes tsconfig/ESLint/.NET analyzer/ruff+mypy config and appends `CLAUDE.md.snippet.md` to the repo's `CLAUDE.md`.

Large repos: run one scope at a time (`web`, then `api`, then `python`) — faster and cheaper.

## 4. Updating the plugin (maintainer)

1. Edit files under `plugins/coverity/skills/prescan/` (e.g. add new findings after each client scan).
2. Bump `version` in **both** `plugins/coverity/.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`.
3. Validate: `claude plugin validate . --strict`
4. Commit + push. Team members run:
```bash
claude plugin marketplace update team-coverity
claude plugin update coverity@team-coverity
```

## Notes

- This is a **pre-scan**, not Coverity itself — it greatly reduces findings but can't guarantee zero. If the client report still has items, give Claude the PDF/CID list and fix by data-flow, not by line.
- Keep this repo **private** — it contains client scan data and file paths.
- Ask the client for: their enabled Coverity checker list, a CSV export with event traces, and the "Non-Security Issues" list.
