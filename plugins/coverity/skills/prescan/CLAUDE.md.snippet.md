<!-- Append this block to the CLAUDE.md at the root of the new solution. It keeps NEW code Coverity-clean while Claude writes it. -->

## Coverity-clean coding rules (client runs Coverity, AL1 — zero findings allowed)

Full rulebook: the `coverity` plugin's `prescan` skill (`COVERITY_PRESCAN_GUIDE.md`). Pre-scan command: `/coverity:prescan [api|web|python|docker|all] [scan|fix]`.

**Null safety (≈80 % of past findings, CWE-476, Very High)**
- Per variable, pick ONE style: nullable → guard/normalise *before first use* (`if (!x) return`, `x ?? []`), or non-null → no `?.`/null checks on it anywhere. Never `x.a` in one place and `x?.b` in another in the same function.
- Never add a null check *after* the variable was already dereferenced.
- Always handle the null/undefined result of: `.find()`, `arr[0]`, `searchParams.get()`, `localStorage.getItem()`, `JSON.parse`, `useRef().current`, `useState<T|null>`, API responses; C#: `FirstOrDefault/SingleOrDefault/Find`, `as` casts, `GetConnectionString`, `Deserialize<T>`, `ExecuteScalar`, `DBNull`.
- No `!` non-null assertions as a shortcut.

- Never cast a null-conditional result: `(int)obj?["id"]`, `(bool)x?["flag"]` → use `TryParse` / typed DTOs. Prefer typed DTOs over long `JObject` `?[..]` chains for external API JSON.
- Put `model ??= new()` / null guards at the **top** of the method, before the first use.

**C# resources**: every `IDisposable` (Oracle connection/command/reader/adapter/parameter, streams, Excel packages, crypto objects, `HttpResponseMessage`) in a `using` declaration. `HttpClient` only via `IHttpClientFactory`. Never `new ConfigurationBuilder()...Build()` inside a method → inject `IConfiguration`/`IOptions<T>`. No raw `new Thread(...)` → use a hosted `BackgroundService`/queue.

**No dead/unused code**: don't initialise a variable with a value that is overwritten before being read; don't write conditions that are always true/false (e.g. `if (obj == null)` right after `new`, `x.Equals(null)`, a second null check or `?.` on a value already checked); remove unreachable branches and loops that always `break` on the first pass.
- `if`/`else` or `cond ? a : b` must not have identical branches (watch bn/en switches).
- Every created exception is thrown (`throw new …`); use `throw;` not `throw ex;`; no empty `catch { }`.

**Security**
- No secrets in code, `appsettings*.json`, `NEXT_PUBLIC_*`, or Dockerfiles. Tokens in httpOnly/Secure/SameSite cookies, never `localStorage`.
- SQL only with bind parameters (`OracleParameter`); never string-concatenate or interpolate SQL. Whitelist dynamic column/sort names.
- No `dangerouslySetInnerHTML`/`innerHTML`/`eval` (shadcn `chart.tsx` → pass colours via `style` CSS variables).
- File upload/download: whitelist extension + size, `Path.GetFileName`, generated names, verify full path stays under the root.
- Every controller/Route Handler/Server Action checks auth + ownership (no IDOR). Redirect targets must be local paths.
- Crypto: AES only (random IV per message, key from config/vault, never derived from a string literal); no MD5/SHA1/DES/TripleDES/RC2/ECB; passwords via `PasswordHasher`/PBKDF2. OTP/temporary passwords/tokens via `RandomNumberGenerator` / `crypto.randomUUID()`, never `Random`/`Math.random`.
- User-facing texts containing password/PIN/OTP/token/secret go in a messages source (`.resx`, `IOptions<Messages>`, i18n JSON) — Coverity SIGMA flags such inline literals as hard-coded secrets.
- API responses never echo passwords or secrets (e.g. no `Password = login.Password` in a login response).
- Errors to clients are generic; never return `ex.Message`/stack traces; don't log tokens/passwords.
- Guard every division (commission %, achievement/target) against zero.
- Every Dockerfile ends with a non-root `USER` (`USER $APP_UID` for .NET 8+, `USER nextjs` for Next.js, a created `appuser` for Python).

**Python**
- Values that can be `None` (`dict.get`, `os.getenv`, `.first()`, `fetchone()`, `re.match`) are checked before first use; type hints + `mypy --strict`.
- Files, DB connections/cursors, sessions, `Popen` always in `with` blocks.
- SQL only with bind parameters — never f-strings / `%` / `.format()` / `+` into `execute`, `read_sql`, `text()`.
- No `shell=True`, `os.system`, `eval`/`exec`, `pickle`/`yaml.load` on untrusted data (`yaml.safe_load`), no `verify=False`; every `requests` call has `timeout=`.
- `secrets` module (not `random`) for OTP/tokens; no `hashlib.md5/sha1`, DES, ECB for security.
- `raise` every exception you create; no bare `except:` / `except Exception: pass`; no `assert` for security checks.
- No `DEBUG=True` / `debug=True` / wildcard CORS / hard-coded `SECRET_KEY` in committed code.
