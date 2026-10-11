# Coverity Pre-Scan Guide — .NET API + Next.js Web + Python

> **Audience: Claude (and developers).** Use this file to find and fix everything the client's Coverity scan would report **before** the code is handed over.
> Stack: ASP.NET Core Web API (C#, Oracle DAL) · Next.js (TypeScript/TSX, shadcn/ui) · Python (services/scripts/APIs — FastAPI/Flask/Django/pandas) · Dockerfile.
> Python has no past client findings yet: apply the Part A principles (they are language-independent) plus Part B-3.
> Evidence base: 13 Coverity rounds on the SalesCom Modernization project (Sep–Nov 2024) + the Biometric/RetailerSelfCareApp scan (newer Coverity with `SIGMA.*` crypto/secret rules), see `Previous_Scan_Summary.md`.

---

## 0. The bar we must clear

The client runs **Coverity Connect (2024.x), policy AL1, "Carrier grade" severity mapping**:

- Security Score ≥ 90, **0** OWASP Top 10 issues, **0** CWE/SANS Top 25 issues.
- Observed: **1 Very-High issue ⇒ score 70 (fail). 1 High issue ⇒ score 80 (fail).**
- ⇒ **Target = ZERO security findings.** Treat every item in Part A and Part B as blocking.

| Technical impact (Carrier grade) | Severity | Typical CWEs |
|---|---|---|
| Execute unauthorized code | Very High | 476 null deref, 79 XSS, 89 SQLi, 78 cmd inj, 94, 502, 798 hard-coded creds |
| Gain privileges / Bypass protection | Very High / High | 269 run as root, 287, 352 CSRF, 639 IDOR, 862 |
| DoS – unreliable execution | High | 561 dead code, 563 unused value, 688 typo, 369 divide by zero |
| Modify / Read data | High / Medium | 22 path traversal, 200/209/532 info exposure, 601 open redirect, 918 SSRF |
| DoS – resource consumption | Medium | 404/772 resource leak, 400, 1333 ReDoS |

Coverity also scans **non-code files** (Dockerfile, config) and **vendored UI code** (`components/ui/*`, `lib/utils.ts`). Exclude only: `node_modules/`, `.next/`, `bin/`, `obj/`, `dist/`, `venv/`, `.venv/`, `__pycache__/`, `site-packages/`, generated files.

---

## Part A — Issues the client ALREADY found on our previous projects (highest priority)

A1–A10: SalesCom Modernization (.NET + Next.js). A11–A14: Biometric/RetailerSelfCareApp (.NET). A3, A4, A5 and A8 also include new patterns from Biometric.

### A1. Next.js — "Property access or function call before check for null or undefined" (REVERSE_NULL, CWE-476, Very High) — *160 hits last time*

**Why it fires:** a variable is used with `.` / `()` / `[]` **and somewhere later in the same function it is checked** for null/undefined (`?.`, `&&`, `if (x)`, `x ?? y`, `x == null`). The later check proves to Coverity that *you* believe it can be null, so the earlier unguarded use is a defect.

```tsx
// ❌ flagged at line 1 (because of the ?. on line 3)
const total = data.items.length;
...
if (data?.items?.length) { ... }

// ❌ classic React handler
const onSubmit = (values) => {
  const id = selectedRow.id;          // used
  ...
  if (!selectedRow) return;            // checked later → flagged
};

// ✅ normalise ONCE at the top, then use one style consistently
const items = data?.items ?? [];
const total = items.length;
if (items.length) { ... }

// ✅ guard first, then use without ?.
const onSubmit = (values) => {
  if (!selectedRow) return;
  const id = selectedRow.id;
};
```

**Fix rules**
1. For every variable in a function: **either** it is nullable → guard/normalise *before first use* (early return, `?? []`, `?? ''`, `?? 0`), **or** it is never null → remove all later `?.`/null checks on it. **Never mix `x.a` and `x?.b` on the same variable.**
2. Do NOT "fix" by sprinkling `?.` on the flagged line only — last time CIDs survived up to 6 rounds that way.
3. The TypeScript `!` operator is not a fix (Coverity ignores TS types; it follows data-flow).
4. Hot spots: API response objects (`res.data.data`, `response?.data`), `selectedRow`/`editData`/`rowData` props, `session.user`, `form.getValues()`, `searchParams.get()`, `useRef().current`, `event.target.files[0]`, `JSON.parse(localStorage.getItem(...))`, results of `.find()`, table `row.original`, `useQuery` `data`, array index `arr[0]`.

### A2. Next.js — "Bad use of null-like value" (FORWARD_NULL, CWE-476, Very High) — *survived 8 rounds in `ReportConfig.tsx`*

**Why it fires:** a value is known to be `null`/`undefined` on some path (initialised to null, returned from `.find()`, checked and fell through) and is then dereferenced on that path.

```tsx
// ❌
let selected = null;
if (mode === 'edit') selected = rows.find(r => r.id === id);
setForm(selected.name);               // null on the non-edit path / not-found path

const [config, setConfig] = useState<Config | null>(null);
const cols = config.columns.map(...); // first render: null

// ✅
const selected = mode === 'edit' ? rows.find(r => r.id === id) : undefined;
if (!selected) return;                 // or show "not found"
setForm(selected.name);

if (!config) return <Skeleton />;
const cols = config.columns.map(...);
```
Fix rule: walk **every path** to the dereference (if/else, ternary, switch default, early `catch`). Assign the narrowed value to a new `const` after the guard and use only that const afterwards.

### A3. C# — "Dereference after null check" / "Dereference before null check" / "Null value leads to thrown exception" (FORWARD_NULL / REVERSE_INULL / NULL_RETURNS family, CWE-476, Very High)

```csharp
// ❌ after-check: checked for null, then used on the null path
if (dt != null && dt.Rows.Count > 0) { ... }
var first = dt.Rows[0];                        // dt may be null here

// ❌ before-check: used, then checked
var name = request.Name.Trim();
if (request == null) return BadRequest();

// ❌ null return used directly
var user = _ctx.Users.FirstOrDefault(u => u.Id == id);
return user.Email;

// ❌ "Null value leads to thrown exception" (ServiceRegister.cs last time)
services.AddScoped(_ => new Repo(config.GetConnectionString("Oracle")));   // may be null → throws later

// ✅
if (request is null) return BadRequest();
var name = request.Name?.Trim() ?? string.Empty;

var user = _ctx.Users.FirstOrDefault(u => u.Id == id);
if (user is null) return NotFound();
return user.Email;

var cs = config.GetConnectionString("Oracle")
         ?? throw new InvalidOperationException("Connection string 'Oracle' is missing.");
```
Null-returning APIs to always check: `FirstOrDefault`, `SingleOrDefault`, `LastOrDefault`, `Find`, `as` casts, `GetConnectionString`, `GetValue<T>`, `GetSection(...).Value`, `JsonConvert.DeserializeObject<T>` / `JsonSerializer.Deserialize<T>`, `HttpContext.User.FindFirst(...)`, `Request.Headers[...]`, `Path.GetDirectoryName`, `DataRow["col"]` (DBNull), `ExecuteScalar()`, `Dictionary.TryGetValue` out value, `IFormFile` parameters.

**More patterns from the Biometric scan (same checker family):**
```csharp
// ❌ "Explicit null dereferenced": casting a null-conditional result
raResp.id = (int)dbssRespObj["data"]?["id"];
if ((bool)obj["included"][0]["attributes"]?["is-company"]) { ... }
// ✅
var idToken = dbssRespObj["data"]?["id"];
raResp.id = idToken != null && int.TryParse(idToken.ToString(), out var id) ? id : 0;
// ✅ better: deserialize external API JSON into typed DTOs instead of long JObject ?[..] chains

// ❌ passing a possibly-null object into a method that dereferences it
if (resp != null && resp.data == null) return Invalid();
return _parser.Parse(resp);                          // resp may still be null
// ✅
if (resp?.data is null) return Invalid();
return _parser.Parse(resp);

// ❌ else-branch uses the object that may be null
if (api != null && !api.isError) { ... } else { return Fail(api.message); }
// ✅ handle api == null as its own branch

// ❌ mixed style on one variable (same as A1 in C#)
Token = Make(user != null ? user.user_id : "");    // treats user as nullable
Role  = user.role_access;                          // ...then dereferences it
// ✅ if (user is null) return Unauthorized(); then use user.x everywhere

// ❌ null-coalescing assignment AFTER the object was already used
int.TryParse(model.versionName, out var v);
model ??= new AppSettingsRequest();
// ✅ move `model ??= …` (or the null guard) to the top of the method
```

### A4. C# — "Resource leak" / "Resource leak on an exceptional path" (RESOURCE_LEAK, CWE-404, Medium) — *24 hits, all in Oracle DAL / Excel import*

```csharp
// ❌ Close() is skipped if anything throws; reader/command never disposed
OracleConnection con = new OracleConnection(_cs);
con.Open();
OracleCommand cmd = new OracleCommand("PKG.PROC", con);
cmd.CommandType = CommandType.StoredProcedure;
OracleDataReader dr = cmd.ExecuteReader();
dt.Load(dr);
con.Close();

// ✅ every IDisposable in a using declaration
using var con = new OracleConnection(_cs);
con.Open();
using var cmd = new OracleCommand("PKG.PROC", con) { CommandType = CommandType.StoredProcedure };
using var dr  = cmd.ExecuteReader();
dt.Load(dr);
```
- Applies to: `OracleConnection`, `OracleCommand`, `OracleDataReader`, `OracleDataAdapter`, `OracleTransaction`, `OracleParameter`/`OracleRefCursor`/`OracleClob`/`OracleBlob` (ODP.NET types are IDisposable), `SqlConnection`/`SqlCommand`, `ExcelPackage` (EPPlus), `XLWorkbook` (ClosedXML), `IExcelDataReader`, `Stream`/`MemoryStream`/`FileStream`/`StreamReader`/`StreamWriter`, `HttpResponseMessage`, `CryptoStream`, `Aes`/`HMACSHA*`/`SHA*`/`RandomNumberGenerator` instances, `Process`, `Image`/`Bitmap`, `X509Certificate2`.
- If a method must **return** a disposable (reader/stream), the caller owns it and must `using` it; for readers use `CommandBehavior.CloseConnection`.
- Never `new HttpClient()` per call → use `IHttpClientFactory` (Biometric: `HttpClient client = new HttpClient();` without `using` was flagged).
- **Never build configuration inside a method**: `new ConfigurationBuilder().AddJsonFile("appsettings.json").Build()` returns a disposable `ConfigurationRoot` → flagged as leak (Biometric). Inject `IConfiguration` / `IOptions<T>` via constructor; in a static helper use one `static readonly` instance.
- Don't start raw `new Thread(...)` for fire-and-forget work (flagged as leak in Biometric) → use a hosted `BackgroundService`/queue (or at minimum `Task.Run` with exception handling).
- "on an exceptional path" = disposal code exists but sits after code that can throw → move to `using` / `try…finally`.

### A5. Both — "Logically dead code" (DEADCODE, CWE-561, High)

Typical triggers: `if (obj == null)` right after `obj = new X()`; checking a condition already guaranteed by an earlier `return`; `bool flag = false; if (flag) {...}`; `catch` after code that can't throw; `x !== undefined && x === undefined`; `switch` branches that can't be reached; `if (list.Count > 0) ... else if (list.Count > 0)`.
Fix: delete the unreachable branch or fix the condition that is wrong (it is often a real bug — confirm intent before deleting).

More DEADCODE triggers seen in the Biometric scan:
```csharp
// ❌ Equals(null) on a value: the "null" branch can never run
order.division_id = model.division_id.Equals(null) ? null : model.division_id;
if (request.is_Success.Equals(null)) { ... }
// ✅
order.division_id = model.division_id;
if (request.is_Success is null) { ... }

// ❌ re-checking null inside a block that already guarantees non-null
if (apiResponse != null && apiResponse.isError)
    return Fail(apiResponse != null ? apiResponse.message : " ");   // else-part is dead
// ✅
    return Fail(apiResponse.message);

// ❌ ?. after an explicit null check of the same value
if (obj["included"] == null || obj?["included"]?.Count() != 3) ...
// ✅
if (obj["included"] == null || obj["included"].Count() != 3) ...

// ❌ null check on something that cannot be null (non-nullable type, just assigned, .ToString() result)
is_success = user != null ? 1 : 0;              // user is non-nullable here
var msg = resp.ToString() != null ? resp.ToString() : ex.Message;
```

**"Structurally dead code" (UNREACHABLE, CWE-561)** — code that can never run because of control flow:
```csharp
// ❌ loop body always breaks on the first pass, so i++ is unreachable
for (int i = 0; i < dt.Rows.Count; i++) { amount = dt.Rows[0]["AMOUNT"]...; break; }
// ✅
if (dt.Rows.Count > 0) { amount = dt.Rows[0]["AMOUNT"]...; }
```
Also: statements after `return`/`throw`/`continue`, code after an infinite loop, `catch` blocks for exceptions that cannot be thrown.

### A6. C# — "Unused value" (UNUSED_VALUE, CWE-563, High)

```csharp
// ❌ initial value is overwritten before being read
DataTable dt = new DataTable();
dt = _dal.GetData(id);
string msg = "";
msg = result > 0 ? "Saved" : "Failed";

// ✅ declare at first real assignment
var dt  = _dal.GetData(id);
var msg = result > 0 ? "Saved" : "Failed";
```
Also: return values assigned and never read, `i++` results ignored in last iteration, parameters overwritten before use.

### A7. Next.js — "Typo in identifier" (IDENTIFIER_TYPO, CWE-688, High)

Coverity flags an identifier/property used once that is one edit away from a frequently used one (e.g. `kpiValu` vs `kpiValue`, `reportID` vs `reportId`, `staus` vs `status`). Fix the spelling; give objects a TS `type`/`interface` so typos fail compilation.

### A8. Next.js — "Hard-coded secret" (HARDCODED_CREDENTIALS, CWE-798, Very High) — `lib/localstorage.ts:3`

```ts
// ❌ any literal assigned to something named key/secret/password/token
const SECRET_KEY = "SalesCom@2024#Key";
CryptoJS.AES.encrypt(JSON.stringify(user), SECRET_KEY);
// ❌ also: NEXT_PUBLIC_*_SECRET / *_KEY with real values — they are shipped to the browser
```
**Newer Coverity (`SIGMA.hardcoded_secret`) is very aggressive.** In the Biometric scan it flagged a **user-facing message** as "Secret type: Password (generic)":
```csharp
return "Password has been sent to Retailer's transaction mobile number.";   // ❌ flagged as hard-coded password
```
→ Keep user messages that contain words like *password / PIN / OTP / secret / token / key* in a messages source (`.resx`, an `IOptions<Messages>` section in appsettings, or i18n JSON in Next.js), injected via DI — **not** with `new ConfigurationBuilder()` inside the method (that caused a new Resource leak in Biometric, see A4).

✅ Do not encrypt in the browser with a shipped key (it is not secret). Keep tokens in **httpOnly, Secure, SameSite cookies** set by the API/Route Handler, or in server session. If client-side obfuscation is truly required, derive the key at runtime from the server per session. In .NET: secrets only from environment variables / user-secrets / vault; `appsettings*.json` committed with placeholders only (no Oracle passwords, JWT signing keys, SMTP passwords, API keys).

### A9. Next.js — "Unsafe output of data into innerHtml" (XSS, CWE-79, Very High) — shadcn `components/ui/chart.tsx`

shadcn/ui `ChartStyle` writes CSS with `dangerouslySetInnerHTML`. Same for any `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`.
```tsx
// ✅ replace ChartStyle: pass colours as CSS variables via the style prop
const style = Object.fromEntries(
  Object.entries(config).map(([k, v]) => [`--color-${k}`, v.color])
) as React.CSSProperties;
<div data-chart={id} style={style}> ... </div>
```
If HTML from the API must be rendered, sanitise with DOMPurify **and** still expect Coverity to flag `dangerouslySetInnerHTML` — prefer rendering as text/React elements.

### A10. Docker — "Container running as root" (CWE-269, Very High) — API `Dockerfile:1`

```dockerfile
# ✅ ASP.NET Core (.NET 8+ images ship a non-root 'app' user)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .
# non-root cannot bind port 80; .NET 8+ default port is 8080 (update compose/k8s/ingress accordingly)
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "SalesCom.WebAPI.dll"]
```
```dockerfile
# ✅ Next.js (standalone output)
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
```
Also: pin base image tags (no `latest`), no secrets in `ENV`/`ARG`, no `chmod 777`, prefer `COPY` over `ADD`, add `.dockerignore` (`.env*`, `node_modules`, `bin`, `obj`, `.git`). Check every Dockerfile in the repo (API, Web, any `docker/` folder) and compose/k8s files (`runAsNonRoot: true`).

### A11. C# — Weak crypto (Biometric: `SIGMA.weak_hash` CWE-327, `SIGMA.insecure_block_cipher_algorithm` CWE-327, `SIGMA.insecure_block_cipher_mode` CWE-310)

```csharp
// ❌ all three were flagged in one helper
using var md5 = new MD5CryptoServiceProvider();
var key = md5.ComputeHash(Encoding.UTF8.GetBytes("bl_smart_pos"));   // weak hash + hard-coded key material
using var tdes = new TripleDESCryptoServiceProvider { Key = key, Mode = CipherMode.ECB };   // weak cipher + ECB

// ✅ AES (or AesGcm) with a key from configuration/secret store and a random IV per message
using var aes = Aes.Create();                       // AES-256, default mode CBC
aes.Key = Convert.FromBase64String(_options.Value.EncryptionKey);   // 32 bytes, from env var / vault
aes.GenerateIV();                                   // new IV each time; store IV + ciphertext together
using var enc = aes.CreateEncryptor();
var cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
var payload = aes.IV.Concat(cipher).ToArray();      // decrypt: first 16 bytes = IV
```
- Forbidden for security use: `MD5`, `SHA1`, `DES`, `TripleDES`, `RC2`, `CipherMode.ECB` (also avoid `CFB`/`OFB`), a fixed/zero IV, a key derived from a string literal.
- Hashing data integrity → `SHA256`/`SHA512`. **Passwords** → `PasswordHasher<T>` / PBKDF2 (`Rfc2898DeriveBytes.Pbkdf2`, SHA256, ≥100k iterations) — never a plain hash.
- Tokens/sessions: prefer standard signed JWT (`HS256`/`RS256`) or ASP.NET Data Protection API over home-made AES tokens.
- ⚠ Changing the algorithm breaks decryption of data/tokens encrypted the old way — plan a migration (re-encrypt or force re-login).

### A12. C# / TS — Insecure random (`SIGMA.insecure_random`, CWE-338)

```csharp
// ❌ OTP / temporary password from System.Random
var random = new Random();
randomPWD = random.Next(111111, 999999);
// ✅
randomPWD = RandomNumberGenerator.GetInt32(111111, 999999);    // System.Security.Cryptography
```
TS/Next.js: no `Math.random()` for ids, OTP, tokens or file names → `crypto.randomUUID()` / `crypto.getRandomValues()`. Using `Random` for non-security things (UI shuffles, test data) can still be flagged, so prefer the crypto RNG everywhere.

### A13. C# / TS — "Identical code for different branches" (IDENTICAL_BRANCHES, CWE-398)

```csharp
// ❌ both branches do the same thing
if (string.Equals(ex.Message, "Padding is invalid and cannot be removed.")) decrypted = "InvalidSessionToken";
else                                                                           decrypted = "InvalidSessionToken";
string iTopUpStr = model.lan == "bn" ? "iTopUp" : "iTopUp";
// ✅ remove the condition (or fix the branch that was meant to be different — check with the team: it is often a missing translation / copy-paste bug)
decrypted = "InvalidSessionToken";
string iTopUpStr = "iTopUp";
```
Watch for this especially in **bn/en language switches** and in `catch` handling.

### A14. C# — "Exception not thrown" (MISSING_THROW, CWE-390)

```csharp
// ❌ exception object created and dropped — the error is silently ignored
if (data == null) new Exception("No data found. API url: " + url);
// ✅
if (data == null) throw new InvalidOperationException("No data found.");   // also: don't put internal URLs in messages returned to clients
```
Related things to avoid while you are there: `throw ex;` (loses the stack trace → use `throw;`), empty `catch { }`, `catch (Exception ex) { throw ex; }` wrappers that add nothing.

---

## Part B — Other Coverity checks we have NOT hit yet but must pre-empt

Checker names below are indicative; ask the client for the enabled-checker list (Coverity Connect → `/doc/en/cov_checker_ref.html`) to confirm.

### B-1. .NET API (C#)

| # | Check (typical checker) | CWE | What to look for | Fix |
|---|---|---|---|---|
| 1 | SQL injection (`SQLI`) | 89 | String concat / interpolation / `string.Format` into `OracleCommand.CommandText`, `FromSqlRaw`, `ExecuteSqlRaw`, dynamic `ORDER BY`/`WHERE` built from request | `OracleParameter` / `:p_name` bind vars, `FromSqlInterpolated`; whitelist column/sort names |
| 2 | Path traversal (`PATH_MANIPULATION`) | 22 | `Path.Combine(root, userInput)`, `IFormFile.FileName`, download endpoints taking file name/path | Use `Path.GetFileName`, generated names (GUID), verify `Path.GetFullPath(p).StartsWith(root)` |
| 3 | Unrestricted upload | 434 | Excel/CSV upload without extension + content-type + size check | Whitelist `.xlsx/.csv`, max size, store outside wwwroot, random name |
| 4 | OS command injection (`OS_CMD_INJECTION`) | 78 | `Process.Start` with user data | Avoid; fixed exe + argument list, whitelist |
| 5 | XXE (`XML_EXTERNAL_ENTITY`) | 611 | `XmlDocument`, `XmlTextReader`, `DtdProcessing.Parse`, custom `XmlResolver` | `DtdProcessing.Prohibit`, `XmlResolver = null` |
| 6 | Unsafe deserialization (`UNSAFE_DESERIALIZATION`) | 502 | `BinaryFormatter`, `NetDataContractSerializer`, `TypeNameHandling.All/Auto/Objects` | System.Text.Json / `TypeNameHandling.None` |
| 7 | Weak crypto / hashing — **confirmed by client in Biometric, see A11** (`SIGMA.weak_hash`, `SIGMA.insecure_block_cipher_*`, `WEAK_PASSWORD_HASH`) | 327/328/916 | `MD5`, `SHA1`, `DES`, `TripleDES`, `RC2`, `CipherMode.ECB`, static/zero IV, plain SHA256 for passwords | AES-GCM / AES-CBC + random IV; passwords → `PasswordHasher<T>`/PBKDF2 (≥100k iter)/BCrypt |
| 8 | Insecure randomness — **confirmed by client in Biometric, see A12** (`SIGMA.insecure_random`) | 330/338 | `new Random()` for OTP, tokens, file names, reset links | `RandomNumberGenerator.GetInt32/GetBytes` |
| 9 | Hard-coded credentials (`HARDCODED_CREDENTIALS`) | 798/259/321 | literal password/key/token/conn-string in `.cs` **or `appsettings*.json`**, JWT `SymmetricSecurityKey(Encoding.UTF8.GetBytes("..."))` | env vars / user-secrets / vault; placeholders in repo |
| 10 | Information exposure (`SENSITIVE_DATA_LEAK`, error leaks) | 200/209/532 | `return BadRequest(ex.Message)`, `ex.ToString()`/stack trace in responses, `UseDeveloperExceptionPage` outside Development, logging passwords/tokens/OTP/NID | Generic error + correlation id; `UseExceptionHandler`; mask sensitive fields in logs |
| 11 | JWT / auth misconfig | 287/345/347 | `ValidateIssuer/Audience/Lifetime/IssuerSigningKey = false`, `RequireHttpsMetadata = false` (prod), `RequireSignedTokens=false`, very long expiry | All validations true, short expiry + refresh, key from config |
| 12 | Missing authorization / IDOR | 862/639 | Controllers without `[Authorize]`, stray `[AllowAnonymous]`, endpoints that take `userId`/`id` and don't check ownership/role | Global `[Authorize]` (fallback policy), role/policy checks, filter by current user |
| 13 | CSRF / cookies (`CSRF`, `INSECURE_COOKIE`) | 352/614/1004 | Cookie auth without antiforgery; cookies without `Secure`, `HttpOnly`, `SameSite` | `CookieOptions { HttpOnly=true, Secure=true, SameSite=Strict }`; antiforgery for cookie-auth POSTs |
| 14 | CORS misconfiguration | 942/346 | `AllowAnyOrigin()` with credentials, `SetIsOriginAllowed(_ => true)` | Explicit origin list from config |
| 15 | Open redirect (`OPEN_REDIRECT`) | 601 | `Redirect(returnUrl)` with request data | `Url.IsLocalUrl` / `LocalRedirect` / whitelist |
| 16 | SSRF | 918 | `HttpClient.GetAsync(userSuppliedUrl)` | Whitelist hosts, no raw URL from client |
| 17 | TLS / certificate validation | 295 | `ServerCertificateCustomValidationCallback = (...) => true`, `ServicePointManager.ServerCertificateValidationCallback` | Never disable in shipped code |
| 18 | Regex injection / ReDoS (`REGEX_INJECTION`) | 1333/400 | `new Regex(userInput)`, nested quantifiers, no timeout | `Regex.Escape`, `RegexOptions.NonBacktracking` / timeout |
| 19 | Log injection | 117 | Logging raw user input with newlines | Structured logging (`_log.LogInformation("{Id}", id)`) |
| 20 | Divide by zero (`DIVIDE_BY_ZERO`) | 369 | **Commission %, achievement/target, averages** with possible 0 denominator | Guard `target == 0` explicitly |
| 21 | Quality checkers that become "Non-Security Issues" | — | `CHECKED_RETURN` (ignored `TryParse`/`int.Parse` return), `COPY_PASTE_ERROR`, `CONSTANT_EXPRESSION_RESULT`, `SWAPPED_ARGUMENTS`, `MISSING_BREAK`, `async void`, un-awaited `Task`, `.Result`/`.Wait()`, empty `catch {}`, `== ` on floating values, `INFINITE_LOOP` | Fix while touching the file |

### B-2. Next.js Web (TS/TSX)

| # | Check | CWE | What to look for | Fix |
|---|---|---|---|---|
| 1 | DOM XSS (`DOM_XSS`, `XSS`) | 79 | `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function`, `setTimeout("string")`, `href={userValue}` (→ `javascript:` URLs), `window.location = param` | Render as text; validate URLs start with `/` or `https://`; DOMPurify only if unavoidable |
| 2 | Open redirect | 601 | `router.push(searchParams.get('redirect'))`, `redirect(param)` in login flow, `window.location.href = ...` | Allow only relative paths starting with `/` (not `//`) |
| 3 | Hard-coded secrets | 798 | API keys/encryption keys in `.ts`, `NEXT_PUBLIC_*KEY/SECRET/TOKEN`, committed `.env*` | Server-only env vars (no `NEXT_PUBLIC_`), `.env*` in `.gitignore` |
| 4 | Sensitive data in browser storage | 312/922 | JWT / password / user PII in `localStorage`/`sessionStorage` | httpOnly cookie set by server |
| 5 | IDOR / missing auth in Route Handlers & Server Actions (Coverity 2026 added an IDOR checker for JS/TS) | 639/862 | `app/api/**/route.ts` and `"use server"` actions without session/role check; using `id` from the client without ownership check | Check session + ownership at the top of every handler/action; `middleware.ts` matcher for protected routes |
| 6 | SSRF in server code | 918 | `fetch(userSuppliedUrl)` in Route Handlers/Server Components/actions | Fixed base URL + path whitelist |
| 7 | Insecure randomness | 330 | `Math.random()` for ids/tokens/OTP | `crypto.randomUUID()` / `crypto.getRandomValues` |
| 8 | Prototype pollution | 1321 | Merging `JSON.parse` / request bodies into objects (`Object.assign({}, body)`, deep-merge, `obj[key] = value` with user keys) | Validate with zod; block `__proto__`/`constructor` keys; `Object.create(null)` maps |
| 9 | ReDoS / regex injection | 1333 | `new RegExp(userInput)` | escape input |
| 10 | Info exposure | 209/532 | `console.log` of tokens/responses in prod, showing raw `error.message`/stack from API to user | Remove logs; generic messages |
| 11 | Insecure cookies (if set from Next) | 614/1004 | `cookies().set(name, v)` without `httpOnly`, `secure`, `sameSite` | Set all three |
| 12 | Security headers / config | 16/1021 | `next.config` without CSP / `X-Frame-Options` / `poweredByHeader: true` | `headers()` with CSP, frame-ancestors, `poweredByHeader: false` |
| 13 | `target="_blank"` without `rel="noopener noreferrer"` | 1022 | external links | add rel |
| 14 | Quality: unused vars/imports, unreachable code, self-assignment, `==` vs `===`, duplicate keys in object/JSX props, missing `key`, `useEffect` missing deps leading to stale null | — | lint | fix |

### B-3. Python (services, scripts, FastAPI / Flask / Django, pandas jobs)

**Part A mapped to Python** (same Coverity checker families, Python syntax):

| Part A item | Python form | Fix |
|---|---|---|
| A1–A3 null deref (CWE-476) | Using a value that can be `None`: `dict.get()`, `re.match()`/`re.search()`, `os.getenv()`, `next(iter, None)`, ORM `.first()`/`.get_or_none()`, `cursor.fetchone()`, `request.json`/`request.args.get()`, function that `return None` on some path; checking `if x is None` *after* `x.attr` | Guard before first use: `if x is None: raise/return`; `os.environ["KEY"]` for required config; type hints `Optional[...]` + `mypy --strict` |
| A4 resource leak (CWE-404) | `open()`, DB connections/cursors (`cx_Oracle`/`oracledb`, `psycopg2`, `pyodbc`), `requests.Session`, `zipfile`, `tempfile`, `subprocess.Popen`, `socket` without `with` / `close()` in `finally` | `with open(...) as f:`, `with conn.cursor() as cur:`, `contextlib.closing(...)` |
| A5 dead code / UNREACHABLE (CWE-561) | code after `return`/`raise`, `if x is None` right after `x = Foo()`, loop that always `break`s, `except` order where a broad `except Exception` precedes a specific one | Remove / fix the condition |
| A6 unused value (CWE-563) | variable assigned then overwritten before read; unused imports/locals | `ruff` F841, F401 |
| A7 typo in identifier | misspelled attribute/key used once (`row["staus"]`) | dataclasses/pydantic models instead of raw dicts |
| A8 hard-coded secret (CWE-798) | passwords/keys/tokens/DSNs with passwords in `.py`, `settings.py` (`SECRET_KEY = "..."`), `config.ini`, `.env` committed; message literals containing "password" | env vars / vault; `.env` in `.gitignore` |
| A11 weak crypto (CWE-327/328) | `hashlib.md5`/`sha1` for security, `Crypto.Cipher.DES`/`DES3`, `AES.MODE_ECB`, static IV | `cryptography` (AES-GCM/Fernet); passwords → `argon2`/`bcrypt`/`hashlib.pbkdf2_hmac` |
| A12 insecure random (CWE-338) | `random.randint/choice/random()` for OTP, tokens, passwords, file names | `secrets.randbelow`, `secrets.token_urlsafe` |
| A13 identical branches | `x = "a" if lang == "bn" else "a"`, identical `if/else` bodies | remove condition / fix branch |
| A14 exception not thrown (CWE-390) | `ValueError("bad input")` on its own line (created, not raised); `except: pass` | `raise ValueError(...)`; log + re-raise; never bare `except:` |
| A10 container root | Python Dockerfile without `USER` | see Dockerfile below |

**Python-specific security checks:**

| # | Check | CWE | What to look for | Fix |
|---|---|---|---|---|
| 1 | SQL injection | 89 | f-strings / `%` / `.format()` / `+` into `cursor.execute()`, `pd.read_sql()`, SQLAlchemy `text()`, Django `.raw()`/`.extra()` | bind parameters: `cur.execute("... WHERE id = :id", {"id": id})` / `%s` params |
| 2 | OS command injection | 78 | `os.system`, `os.popen`, `subprocess.*(..., shell=True)`, string commands with user input | `subprocess.run([...], shell=False, check=True)` with an argument list |
| 3 | Code injection | 94/95 | `eval`, `exec`, `compile`, `__import__` on input | `ast.literal_eval` / explicit parsing |
| 4 | Unsafe deserialization | 502 | `pickle.load(s)`, `joblib.load`/`dill` on untrusted data, `yaml.load` without `SafeLoader`, `marshal`, `shelve` | `json`, `yaml.safe_load`; only load pickles you produced and signed |
| 5 | XXE | 611 | `xml.etree`/`lxml`/`xml.dom.minidom` parsing untrusted XML | `defusedxml` |
| 6 | Path traversal | 22 | `open(os.path.join(base, user_input))`, `send_file(user_path)`, `zipfile.extractall` / `tarfile.extractall` (zip-slip) | `pathlib.Path(base, name).resolve()` must stay under `base`; `werkzeug.utils.secure_filename`; tarfile `filter="data"` |
| 7 | SSRF | 918 | `requests.get(user_url)`, `urllib.request.urlopen(user_url)` | host whitelist |
| 8 | TLS / cert validation | 295 | `requests(..., verify=False)`, `ssl._create_unverified_context`, `urllib3.disable_warnings` | never disable in shipped code |
| 9 | Missing timeouts | 400 | `requests.get(url)` without `timeout=` | always pass `timeout` |
| 10 | Debug / misconfig | 489/215 | Flask `app.run(debug=True)`, Django `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, `CORS(app)` allowing all with credentials, FastAPI `allow_origins=["*"]` + `allow_credentials=True` | settings from env; explicit origins |
| 11 | XSS / template injection | 79/1336 | `Markup(user)`, `|safe` filter, `render_template_string(user_input)`, Jinja2 `Environment(autoescape=False)` | autoescape on, no user-controlled templates |
| 12 | Info exposure / logging | 209/532 | returning `str(e)`/traceback to API clients, logging passwords/tokens, `print()` of secrets | generic error responses; mask secrets |
| 13 | Insecure temp files | 377 | `tempfile.mktemp()`, fixed paths in `/tmp` | `tempfile.NamedTemporaryFile` / `mkstemp` |
| 14 | Weak permissions | 732 | `os.chmod(path, 0o777)`, `os.umask(0)` | least privilege (`0o600`/`0o640`) |
| 15 | Assert for security | 703 | `assert user.is_admin` (removed with `python -O`) | explicit `if not ...: raise` |
| 16 | Divide by zero | 369 | commission %, achievement/target, `df["a"] / df["b"]` with 0 | guard / `np.where(b == 0, 0, a / b)` |
| 17 | Quality | — | mutable default args (`def f(x=[])`), `is` vs `==` on literals, shadowed builtins, unused loop vars, `except Exception: pass` | `ruff` rules B, F, E, SIM, RET |

**Python Dockerfile (non-root):**
```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .
USER appuser
CMD ["python", "-m", "app"]
```

---

## Part C — Pre-scan workflow for Claude

Run per scope (`api`, `web`, `docker`, or `all`). **Phase 1 (SCAN) changes no code.** Phase 2 (FIX) runs only after the human approves the findings list.

### C-1. Inventory
1. Detect projects: `*.sln`, `*.csproj`, `package.json`, `next.config.*`, `tsconfig.json`, `pyproject.toml`, `requirements*.txt`, `setup.py`, `manage.py`, `Dockerfile*`, `docker-compose*.yml`, `appsettings*.json`, `settings.py`, `.env*`.
2. Exclude `node_modules/`, `.next/`, `bin/`, `obj/`, `dist/`, `out/`, `coverage/`, `*.min.js`, `venv/`, `.venv/`, `__pycache__/`, `migrations/` (review but don't refactor generated code).
3. For large repos split by folder and review folders in parallel (sub-agents), each returning findings in the C-4 format.

### C-2. Tool pass (run what is available; skip and note what is not)
```bash
# Web
npx tsc --noEmit -p .                       # with strict settings from Part D
npx eslint . --max-warnings=0
npm audit --omit=dev
# API
dotnet build                                # Directory.Build.props from Part D turns the key analyzers into errors
dotnet list package --vulnerable --include-transitive
# Python
ruff check .                                # with the rule set from Part D (includes bandit "S" rules)
mypy --strict <package>                     # catches None-dereference (CWE-476) statically
bandit -r . -x ./venv,./.venv,./tests
pip-audit -r requirements.txt
# Optional, free tools that approximate Coverity
semgrep scan --config p/csharp --config p/typescript --config p/react --config p/nextjs --config p/python --config p/secrets --config p/dockerfile
gitleaks dir .
hadolint Dockerfile
```

### C-3. Pattern sweep (ripgrep) — every hit must be reviewed by reading the surrounding function
```bash
# --- Next.js ---
rg -n --glob '!node_modules' --glob '!.next' "dangerouslySetInnerHTML|\.innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(" 
rg -n -i --glob '!node_modules' "(secret|passw(or)?d|pwd|api[_-]?key|token|private[_-]?key|encrypt\w*key)\s*[:=]\s*['\"\`][^'\"\`]{3,}"
rg -n --glob '!node_modules' "NEXT_PUBLIC_\w*(SECRET|KEY|TOKEN|PASS)"
rg -n --glob '!node_modules' "localStorage|sessionStorage"
rg -n --glob '!node_modules' "Math\.random\(|new RegExp\("
rg -n --glob '!node_modules' "router\.(push|replace)\(|redirect\(|window\.location(\.href)?\s*="
rg -n --glob '!node_modules' "\.find\(|\[0\]\.|JSON\.parse\(|useSearchParams|\.current\." 
rg -c --glob '*.tsx' --glob '!node_modules' "\?\." | sort -t: -k2 -nr   # files with most ?. → review each for mixed x.a / x?.b on the same variable
rg -n -g 'route.ts' -g 'route.js' "export async function (GET|POST|PUT|PATCH|DELETE)"
rg -n "\"use server\"|'use server'"
# --- .NET ---
rg -n -g '*.cs' "CommandText\s*=|new (Oracle|Sql)Command\(|FromSqlRaw|ExecuteSqlRaw|string\.Format\(.*(SELECT|INSERT|UPDATE|DELETE|WHERE)" -i
rg -n -g '*.cs' -i '(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)[^;]*("\s*\+|\{\w)'   # SQL text built by + or $"{...}"
rg -n -g '*.cs' "new (Oracle\w+|Sql\w+|MemoryStream|FileStream|StreamReader|StreamWriter|ExcelPackage|XLWorkbook|HttpClient|Process|CryptoStream|Bitmap)\(" # check each has using
rg -n -g '*.cs' "FirstOrDefault\(|SingleOrDefault\(|LastOrDefault\(|\.Find\(| as [A-Z]\w+|GetConnectionString\(|ExecuteScalar\("
rg -n -g '*.cs' "MD5|SHA1\b|SHA1Managed|\bDES\b|TripleDES|RC2|CipherMode\.ECB|new Random\("
rg -n -g '*.cs' "BinaryFormatter|TypeNameHandling\.(All|Auto|Objects)|XmlDocument|XmlTextReader|DtdProcessing\.Parse|Process\.Start"
rg -n -g '*.cs' "Path\.Combine|File\.(ReadAll|WriteAll|Open|Delete|Exists)|\.FileName\b"
rg -n -g '*.cs' "Validate(Issuer|Audience|Lifetime|IssuerSigningKey)\s*=\s*false|RequireHttpsMetadata\s*=\s*false|ServerCertificate(Custom)?ValidationCallback"
rg -n -g '*.cs' "AllowAnyOrigin|SetIsOriginAllowed|AllowAnonymous|UseDeveloperExceptionPage|ex\.Message|ex\.ToString\(\)|StackTrace"
rg -n -g '*.cs' "catch\s*(\(\s*Exception\s*\w*\s*\))?\s*\{\s*\}|async void|\.Result\b|\.Wait\(\)"
rg -n -g 'appsettings*.json' -i "password|pwd=|secret|apikey|key\"\s*:"
# --- .NET patterns from the Biometric scan ---
rg -n -g '*.cs' "\.Equals\(null\)"                                   # DEADCODE
rg -n -g '*.cs' "^\s*new \w*Exception\("                             # MISSING_THROW (created, not thrown)
rg -n -g '*.cs' "throw ex;"                                          # loses stack trace
rg -n -g '*.cs' "new ConfigurationBuilder\(\)|new Thread\(|new HttpClient\(\)"   # RESOURCE_LEAK sources
rg -n -g '*.cs' "\((int|long|bool|decimal|double|string)\)\s*\w+(\[[^]]+\])*\?\["   # cast of ?[..] → Explicit null dereferenced
rg -n -g '*.cs' "MD5CryptoServiceProvider|TripleDESCryptoServiceProvider|CipherMode\.(ECB|CFB|OFB)|new Random\(\)"
rg -n -g '*.cs' -i "\"[^\"]*(password|pin|otp|secret|token)[^\"]*\""   # literals SIGMA may read as secrets
rg -n -g '*.cs' -U "for\s*\([^)]*\)\s*\{[^{}]*break;\s*\}"            # loop that always breaks (UNREACHABLE)
rg -n -P -g '*.cs' -g '*.ts' -g '*.tsx' "\?\s*(\"[^\"]*\"|'[^']*')\s*:\s*\1"   # cond ? "x" : "x" (IDENTICAL_BRANCHES)
rg -n -g '*.cs' "\?\?=\s*new"                                         # check it is at the top, before first use
# --- Python ---
rg -n -g '*.py' "execute\(\s*f[\"']|execute\([^)]*(%|\.format\(|\+)|read_sql\(\s*f[\"']|text\(\s*f[\"']|\.raw\(\s*f[\"']"   # SQL injection
rg -n -g '*.py' "shell\s*=\s*True|os\.system\(|os\.popen\(|\beval\(|\bexec\("
rg -n -g '*.py' "pickle\.loads?\(|yaml\.load\((?!.*SafeLoader)|marshal\.loads?\(|joblib\.load\(" -P
rg -n -g '*.py' "verify\s*=\s*False|_create_unverified_context|disable_warnings"
rg -n -g '*.py' "requests\.(get|post|put|delete|patch)\((?![^)]*timeout)" -P
rg -n -g '*.py' "hashlib\.(md5|sha1)\(|DES3?\b|MODE_ECB|\brandom\.(randint|choice|random|randrange)\("
rg -n -g '*.py' -i "(password|passwd|secret|api_?key|token|secret_key)\s*=\s*[\"'][^\"']{3,}[\"']"
rg -n -g '*.py' "debug\s*=\s*True|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*|allow_origins\s*=\s*\[\s*[\"']\*"
rg -n -g '*.py' "^\s*except\s*:|except\s+Exception\s*:\s*pass|^\s*(\w+Error|Exception)\(" # bare except / exception created not raised
rg -n -g '*.py' "=\s*open\(|\.connect\(|Popen\(|tempfile\.mktemp|chmod\(.*0o?777|extractall\(|^\s*assert\s"
rg -n -g '*.py' "\.get\([^)]*\)\.|\.first\(\)\.|fetchone\(\)\[|re\.(match|search)\([^)]*\)\.group"   # None deref candidates
rg -n -g 'Dockerfile*' "^(FROM|USER|ENV|ARG|ADD|RUN chmod)"
```

### C-4. Manual review checklist (per file — this is what Coverity really does)
For every function/component:
- [ ] Each variable: nullable? → guarded **before first use**, one access style (A1/A2/A3)
- [ ] Every IDisposable inside `using` (A4)
- [ ] No branch that can never execute; no condition always true/false (A5)
- [ ] No assignment overwritten before read (A6)
- [ ] Identifiers spelled consistently (A7)
- [ ] No literal secret, no secret in client bundle (A8)
- [ ] No raw HTML output (A9)
- [ ] Every input from request/query/body/file/localStorage treated as tainted → B-tables
- [ ] Division denominators can't be 0
- [ ] No redundant null checks on values already known non-null (DEADCODE), no `Equals(null)` (A5)
- [ ] No loop that always `break`s on the first pass, no code after `return`/`throw` (A5 UNREACHABLE)
- [ ] No MD5/SHA1/DES/TripleDES/ECB/`Random`; keys not derived from literals (A11, A12)
- [ ] `if`/`else` and `?:` branches are not identical (A13)
- [ ] Every created exception is thrown; no `throw ex;` (A14)
- [ ] No `new ConfigurationBuilder()` / `new HttpClient()` / `new Thread()` inside methods (A4)
- [ ] User-facing texts containing password/PIN/OTP/token come from a messages source, not inline literals (A8)
- [ ] API responses never echo passwords or secrets back to the client

### C-5. Findings file format — write `COVERITY_FINDINGS.md` at repo root
```markdown
# Coverity Pre-Scan Findings — <date> — scope: <api|web|docker|all>
Summary: Very High: n · High: n · Medium: n · Quality: n

| ID | Sev | CWE | Issue type (Coverity wording) | File:Line | Evidence (1 line) | Fix plan | Status |
|----|-----|-----|-------------------------------|-----------|-------------------|----------|--------|
| W-001 | Very High | 476 | Property access … before check for null or undefined | components/x/List.tsx:120 | `row.id` used, `row?.name` at :140 | guard `if (!row) return` at top | Open |
```
IDs: `A-` API (.NET), `W-` Web (Next.js), `P-` Python, `D-` Docker. Order by severity, then file. Status: Open → Fixed → Verified.

### C-6. Fix phase rules
1. Fix in batches by severity (Very High → High → Medium → Quality), max ~20 files per batch; after each batch run `tsc` / `eslint` / `dotnet build` and existing tests.
2. **Behaviour must not change.** If a fix needs a behaviour decision (e.g. what to show when data is null, deleting dead code that looks like a bug), list it as a question instead of guessing.
3. Fix the **pattern, not the line**: after fixing one instance, search the same file/module for the same pattern.
4. No suppressions (`// coverity[...]`, `#pragma warning disable`, `eslint-disable`) unless the human explicitly approves and the client accepts "Intentional/False positive".
5. Don't introduce new nullable checks *after* a use (creates REVERSE_NULL). Don't add `!`.
6. Update `COVERITY_FINDINGS.md` status per item; finish with a re-run of C-2 and C-3 to confirm zero open items.

---

## Part D — Prevention config (add to the new solution so issues can't come back)

**`tsconfig.json`**
```jsonc
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "allowUnreachableCode": false,
    "noImplicitReturns": true
  }
}
```

**ESLint (flat config, type-aware)** — key rules
```js
// eslint.config.mjs (add to the Next.js config)
{
  languageOptions: { parserOptions: { projectService: true } },
  rules: {
    "@typescript-eslint/no-unnecessary-condition": "error", // flags ?. on non-null values → keeps null-style consistent
    "@typescript-eslint/no-non-null-assertion": "error",
    "@typescript-eslint/no-unused-vars": "error",
    "@typescript-eslint/prefer-optional-chain": "error",
    "no-unreachable": "error", "no-constant-condition": "error", "no-self-assign": "error",
    "no-useless-assignment": "error",
    "eqeqeq": ["error", "always"],
    "react/no-danger": "error", "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error", "no-script-url": "error"
  }
}
// optional plugins: eslint-plugin-security, eslint-plugin-no-secrets
```

**`Directory.Build.props`** (solution root)
```xml
<Project>
  <PropertyGroup>
    <Nullable>enable</Nullable>
    <AnalysisLevel>latest-recommended</AnalysisLevel>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
    <WarningsAsErrors>$(WarningsAsErrors);nullable;CA2000;CA2213;CA1508;IDE0059;CS0162;CA2100;CA3001;CA3003;CA3006;CA3007;CA3075;CA5350;CA5351;CA5358;CA5394;CA2300;CA2326;CA5359;CA5390;CA1806;CA2200</WarningsAsErrors>
  </PropertyGroup>
</Project>
```
**`.editorconfig`** — enable the opt-in analyzers referenced above
```ini
[*.cs]
dotnet_diagnostic.CA2000.severity = warning   # dispose objects (RESOURCE_LEAK)
dotnet_diagnostic.CA2213.severity = warning   # disposable fields
dotnet_diagnostic.CA1508.severity = warning   # dead conditional code (DEADCODE)
dotnet_diagnostic.IDE0059.severity = warning  # unnecessary assignment (UNUSED_VALUE)
dotnet_diagnostic.CA2100.severity = warning   # SQL text from variables
dotnet_diagnostic.CA3001.severity = warning   # SQL injection (taint)
dotnet_diagnostic.CA3003.severity = warning   # file path injection
dotnet_diagnostic.CA3006.severity = warning   # process command injection
dotnet_diagnostic.CA3007.severity = warning   # open redirect
dotnet_diagnostic.CA3075.severity = warning   # insecure DTD / XXE
dotnet_diagnostic.CA5350.severity = warning   # weak crypto
dotnet_diagnostic.CA5351.severity = warning   # broken crypto
dotnet_diagnostic.CA5394.severity = warning   # insecure randomness
dotnet_diagnostic.CA5390.severity = warning   # hard-coded encryption key
dotnet_diagnostic.CA5358.severity = warning   # unsafe cipher modes (ECB/OFB/CFB)
dotnet_diagnostic.CA1806.severity = warning   # ignored results, incl. `new Exception()` not thrown (MISSING_THROW)
dotnet_diagnostic.CA2200.severity = warning   # `throw ex;` loses stack trace
```
Optional but recommended: add the free **SonarAnalyzer.CSharp** NuGet package — it catches identical branches (S1871, S3923), always-true/false conditions and more Coverity-like quality issues during build.
Note: on a legacy codebase enable these gradually (warnings first), on a new codebase use them as errors from day one.

**Python — `pyproject.toml`**
```toml
[tool.ruff]
target-version = "py311"
exclude = ["venv", ".venv", "migrations"]

[tool.ruff.lint]
# S = bandit security rules, B = bugbear, F = pyflakes (unused/undefined), E = errors,
# SIM/RET = dead & redundant code, BLE = blind except, PL = pylint subset
select = ["S", "B", "F", "E", "SIM", "RET", "BLE", "PL", "ARG", "TRY"]

[tool.mypy]
strict = true            # Optional[...] must be checked before use → prevents CWE-476
warn_unreachable = true  # dead code
```
CI / pre-commit: `ruff check .`, `mypy --strict`, `bandit -r .`, `pip-audit`.

**Repo hygiene**: `.gitignore` covers `.env*`, `appsettings.*.local.json`, `*.pfx`; `.dockerignore` present; every Dockerfile has a non-root `USER`.
