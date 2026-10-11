# Previous Coverity Scan Summary — SalesCom Modernization + Biometric

Sources:
- **SalesCom Modernization** (.NET API + Next.js Web): 20 Coverity Security Report PDFs under `Code Scaning/SalesCom Mordanization/` (Phase 1: 8 scan rounds, Sep 2024 · Phase 2: 5 scan rounds, Nov 2024). Full row-level data: `data/Previous_Scan_All_Issues.csv` in the kit repo (436 rows = 212 unique CIDs). Sections 1–4.
- **Biometric / RetailerSelfCareApp** (.NET API): `Coverity Scan distinct Issues for Biometric.xlsx` (11 distinct issues with solved code). Section 5.

## 1. How the client grades the scan

| Policy element | Target | Notes |
|---|---|---|
| Security Score | **≥ 90** (Assurance Level AL1) | Severity mapping = **"Carrier grade" (very stringent)** |
| OWASP Top 10 (2017) count | **0** | |
| CWE/SANS Top 25 (2019) count | **0** | CWE-476 is #14 → every null-deref counts here too |
| Analysis date | < 30 days old | |

**Observed score vs. remaining issues (from the reports):**

| Remaining issues | Score | Pass? |
|---|---|---|
| 0 | 100 | ✅ |
| 1 × High (Unused value) | 80 | ❌ |
| 1 × Very High (one null-deref, or Dockerfile root) | 70 | ❌ |
| 2 × Very High | 66 | ❌ |
| 5–22 × Very High | 55–61 | ❌ |
| 142–150 issues | 48–49 | ❌ |

> **Conclusion: in practice the project passes only with ZERO security issues.** One single Very-High or High finding fails the policy.

Carrier-grade severity mapping seen in the reports:

| Technical impact | Severity | CWEs that landed here |
|---|---|---|
| Execute unauthorized code | **Very High** | CWE-476 (null deref), CWE-79 (XSS), CWE-798 (hard-coded secret) |
| Gain privileges | **Very High** | CWE-269 (container running as root) |
| Denial of service, unreliable execution | **High** | CWE-561 (dead code), CWE-563 (unused value), CWE-688 (typo in identifier) |
| Denial of service, resource consumption | Medium | CWE-404 (resource leak) |

"Non-Security Issues" (not in score, but visible to client in Coverity Connect): **14** in API, **204 → 238** in Web. They are not itemised in the PDFs.

## 2. Distinct issue types found (deduplicated by CID)

| # | Coverity issue type (as printed) | Likely checker | CWE | Severity | Stack | Unique CIDs |
|---|---|---|---|---|---|---|
| 1 | Property access or function call before check for null or undefined | `REVERSE_NULL` (JS) | 476 | Very High | Next.js | **160** |
| 2 | Bad use of null-like value | `FORWARD_NULL` (JS) | 476 | Very High | Next.js | 10 |
| 3 | Resource leak | `RESOURCE_LEAK` | 404 | Medium | .NET | 21 |
| 4 | Resource leak on an exceptional path | `RESOURCE_LEAK` | 404 | Medium | .NET | 3 |
| 5 | Logically dead code | `DEADCODE` | 561 | High | .NET (5) + Next.js (2) | 7 |
| 6 | Unused value | `UNUSED_VALUE` | 563 | High | .NET | 3 |
| 7 | Dereference after null check | `FORWARD_NULL` | 476 | Very High | .NET | 2 |
| 8 | Dereference before null check | `REVERSE_INULL` | 476 | Very High | .NET | 1 |
| 9 | Null value leads to thrown exception | `FORWARD_NULL`/`NULL_RETURNS` family | 476 | Very High | .NET | 1 |
| 10 | Typo in identifier | `IDENTIFIER_TYPO` | 688 | High | Next.js | 1 |
| 11 | Hard-coded secret | `HARDCODED_CREDENTIALS` | 798 | Very High | Next.js | 1 |
| 12 | Unsafe output of data into innerHtml | XSS (React `dangerouslySetInnerHTML`) | 79 | Very High | Next.js | 1 |
| 13 | Container running as root | Dockerfile / IaC | 269 | Very High | Docker (API) | 1 |

**~80 % of all findings were CWE-476 in the Next.js front-end.**

## 3. Where they were

### Next.js (Web)
- 137 different `.tsx` files had REVERSE_NULL hits: `components/feature/setup/*` (105), `approval-process/*` (39), `claim-disburse/*` (12), plus `lib/utils.ts`, `components/ui/chart.tsx`, `app/login/page.tsx`.
- XSS: `components/ui/chart.tsx:82` (shadcn/ui `ChartStyle` uses `dangerouslySetInnerHTML`).
- Hard-coded secret: `lib/localstorage.ts:3` (encryption key in client code).
- Typo in identifier: `esi-kpi-configure/EsiKpiConfigure.tsx:274`.
- Dead code: `RegularAdhocReportSearch.tsx:137`, `DenoDriveTargetUpload.tsx:250`.

### .NET (API)
- Resource leaks concentrated in the Oracle DAL layer: `dllOracle.cs`, `ESI_dllOracle.cs`, `POS.DAL/dllOracle.cs`, `ImportExcelToDataBaseDAL.cs` (5 hits), `ESI_KPIConfigurationDAL*.cs`, `ESI_ReportApprovalDAL.cs`, `DenoDriveTargetUploadDAL.cs`, `DailyDenoDriveTargetUploadDAL.cs`, `InitiateClaimDAL.cs`, `InitiateDisburseDAL.cs`, `ReportWiseRedisburseInitiationDAL.cs`, `POS.DAL/ImportFromExcel.cs`, `Account/Implement/Authentication.cs:141`.
- Null deref: `DownloadFilesfromByteArrayBLL.cs:70`, `CampaignDenoDriveBLL.cs:93`, `DigitalDistributionCommission.cs:51`, `WebAPI/ServiceRegister/ServiceRegister.cs:93`.
- Dead code in BLLs: `ClaimInitiationBLL.cs:59`, `ReDisburseInitiationBLL.cs:60`, `CampaignDenoDriveBLL.cs:97`, `DisburseInitiationBLL.cs:49`, `ESI_ReportApprovalDAL.cs:28`.
- Unused value: `ESI_KPIConfigurationDAL2.cs:249, 354`, `ESI_KPIConfigurationBLL.cs:109`.
- Dockerfile: `/Dockerfile:1` — no `USER` instruction (Phase 2 only; it alone held the API at score 70 for 2 rounds).

## 4. Lessons learned (why it took 13 scan rounds)

1. **Fixes were often cosmetic — the same CID came back.** CID 11493 (`ReportConfig.tsx`, Bad use of null-like value) survived **8 scans**, just moving lines (295→300→322→323→334→336→339). 50+ other CIDs survived 3–6 scans. Coverity tracks the *data-flow*, not the line; adding `?.` in one place while still using `.` elsewhere on the same variable keeps (or creates) the finding.
2. **Defensive checks *after* use create new issues.** REVERSE_NULL fires when code does `x.foo` and *later* does `x?.bar` / `if (x)`. The later check tells Coverity "x can be null", so the earlier access is flagged. Consistency per variable is the fix.
3. **New code re-introduced the same patterns.** Phase 2 added new modules (`supporting-upload`, `digital-distribution-commission`, `esi-manualdata-approval`) and immediately produced 22 new CWE-476 hits. Prevention rules must be applied while writing code, not only before the scan.
4. **Infrastructure files are scanned too.** The Dockerfile was flagged Very High (root user) even when all C# code was clean.
5. **Template/library code counts.** shadcn/ui `chart.tsx` and shared `lib/utils.ts` produced XSS + null findings — vendored UI code must be reviewed like our own.

---

## 5. Second source — Biometric project (RetailerSelfCareApp, .NET API)

Source: `Code Scaning/Coverity Scan distinct Issues for Biometric.xlsx` (11 distinct issue rows, all **Solved**, each with problem + solved code).
This scan used a newer Coverity with the **SIGMA** engine (checker names `SIGMA.*`), which adds crypto/secret/config rules on top of the classic data-flow checkers.

| CID | Coverity issue (checker) | CWE | Impact | New vs SalesCom? |
|---|---|---|---|---|
| 464198 | Weak hash algorithm (`SIGMA.weak_hash`) — `MD5CryptoServiceProvider` | 327 | Low | 🆕 new |
| 464225 | Insecure block cipher algorithm (`SIGMA.insecure_block_cipher_algorithm`) — `TripleDESCryptoServiceProvider` | 327 | Medium | 🆕 new |
| 464191 | Insecure block cipher mode (`SIGMA.insecure_block_cipher_mode`) — `CipherMode.ECB` | 310 | Medium | 🆕 new |
| 464279 | Insecure random (`SIGMA.insecure_random`) — `new Random()` for OTP/password | 338 | Low | 🆕 new |
| 464234 | Hard-coded secret (`SIGMA.hardcoded_secret`, type "Password (generic)") — triggered by a **user message literal** `"Password has been sent to …"` | 798 | Low | 🔁 same type, **new trigger** |
| 464197 | Identical code for different branches (`IDENTICAL_BRANCHES`) — `if/else` same body, `cond ? "iTopUp" : "iTopUp"` | 398 | Medium | 🆕 new |
| 464249 | Exception not thrown (`MISSING_THROW`) — `new Exception(...)` without `throw` | 390 | Medium | 🆕 new |
| 464267 | Structurally dead code (`UNREACHABLE`) — `for` loop with unconditional `break` (`i++` unreachable) | 561 | Medium | 🆕 new subtype |
| 464253 | Explicit null dereferenced (`FORWARD_NULL`) — `(int)dbssRespObj["data"]?["id"]` | 476 | Medium | 🆕 new subtype |
| 464238 | Dereference after null check (`FORWARD_NULL`) — passing possibly-null model to a method that dereferences it; `else` branch using a null object; use before `model ??= new()` | 476 | Medium | 🔁 same type, **new patterns** |
| 464194 | Logically dead code (`DEADCODE`) — `x.Equals(null) ? null : x`, `?.` after a null check, `x != null ? x.m : ""` inside `if (x != null)` | 561 | Medium | 🔁 same type, **new patterns** |
| 464189 | Resource leak (`RESOURCE_LEAK`) — `new ConfigurationBuilder()...Build()` inside methods, `new HttpClient()` without `using`, unmanaged `new Thread(...)` | 404 | High | 🔁 same type, **new sources** |

### Lessons from the Biometric fixes
1. **The fix for one issue caused another.** The hard-coded-secret fix built `new ConfigurationBuilder().AddJsonFile(...).Build()` inside the method, and Coverity then reported a **Resource leak** for that. The right fix is to inject `IConfiguration`/`IOptions<T>` through DI.
2. **The crypto changes affect existing data.** Moving from TripleDES/ECB to AES/CBC with a random IV means tokens or values encrypted earlier can't be decrypted any more. A migration plan is needed. The key was also derived from a hard-coded string (`SHA256("bl_smart_pos")`), which is still a hard-coded key.
3. **Redundant null checks count as dead code.** If a value is already known to be non-null, a later `?.` or `!= null` on it is reported as DEADCODE. If it is not checked before use, it is reported as FORWARD_NULL. Check once, before the first use.
4. **Code smells that were not flagged but should be avoided:** `throw ex;` (loses the stack trace, use `throw;`), empty `catch { }`, and returning `Password = login.Password` in the login response (sensitive data exposure).
