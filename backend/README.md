# SecureHub Backend

## Authentication rate limits

- `POST /api/auth/login`: 10 requests per client IP per 15 minutes.
- `POST /api/auth/register`: 5 requests per client IP per hour.

The limits are configured in `src/config/rateLimit.js`. The app does not enable Express proxy trust by default, so clients cannot choose their rate-limit identity by sending an arbitrary `X-Forwarded-For` header. If the service is deployed behind a reverse proxy, configure Express `trust proxy` only for the known proxy addresses or hop count used by that deployment.

The default `express-rate-limit` memory store keeps counters in one Node.js process. Counters are not shared across multiple server instances and are cleared when a process restarts. A multi-instance or frequently restarted deployment should use a shared store, such as Redis, to enforce a consistent limit across instances.

## HTTP security headers

Helmet runs before body parsing and all routes, so successful responses, API errors, and 404 responses receive its security headers. Global CSP remains disabled for the JSON API; unmatched non-API HTML 404 responses use a focused Helmet CSP of `default-src 'none'; frame-ancestors 'none'; form-action 'none'` so they do not rely on Express's partial fallback policy. This does not set the frontend's CSP; configure that on the frontend origin when the application is deployed. `X-Frame-Options: DENY` prevents the API from being framed, and Helmet's default `X-Content-Type-Options: nosniff` prevents MIME sniffing. Other Helmet defaults remain enabled, including removal of `X-Powered-By`.

HSTS is disabled unless `NODE_ENV=production`. In production it is sent with a six-month max age and without `includeSubDomains`. Deploy production behind HTTPS before enabling this setting; browsers only honor HSTS received over secure transport. The app does not configure TLS termination or proxy trust.

## CORS

Set `CORS_ALLOWED_ORIGINS` to a comma-separated list of exact browser origins, including scheme and port when present. For local Vite development, set `CORS_ALLOWED_ORIGINS=http://localhost:5173`. Production must use explicit origins; wildcard origins are rejected. Requests from unlisted origins receive no CORS permission headers, while requests without an `Origin` header continue normally.

The API permits `GET`, `POST`, and `OPTIONS`, and the `Authorization` and `Content-Type` request headers needed by the Bearer-token API. Credentialed CORS is disabled because authentication uses JWT Bearer headers rather than cookies. Preflight responses are cached for 10 minutes in production. CORS only controls whether browsers expose cross-origin responses; it does not authenticate callers or replace route authorization.

## Local OWASP ZAP baseline assessment

Run the baseline scan only against your local SecureHub backend. This workflow targets the API health URL at port `5000`; do not replace it with a public host or a broader network target. The ZAP baseline scan spiders the target for one minute by default and uses passive rules; it does not run active attack scans. See the [official ZAP baseline scan documentation](https://www.zaproxy.org/docs/docker/baseline-scan/).

1. Start the local MongoDB service used by `MONGODB_URI`. In a PowerShell terminal, from `backend`, start the API with your local `.env` configured:

   ```powershell
   npm run dev
   ```

2. In another PowerShell terminal, verify the expected SecureHub health response:

   ```powershell
   Invoke-RestMethod -Uri 'http://127.0.0.1:5000/api/health'
   ```

   Confirm it reports `status: ok` and `service: securehub-api` before scanning. If another service is listening on port 5000, stop and resolve the conflict rather than scanning it.

3. With Docker Desktop running, execute this from `backend`. The container can reach the local Windows host through `host.docker.internal`; the scan target remains the SecureHub API health endpoint on port 5000. No credentials or tokens are supplied.

   ```powershell
   New-Item -ItemType Directory -Force .\zap-reports | Out-Null
   $reportPath = (Resolve-Path .\zap-reports).Path
   docker run --rm --mount "type=bind,source=$reportPath,target=/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t 'http://host.docker.internal:5000/api/health' -m 1 -r securehub-baseline.html -J securehub-baseline.json
   ```

   This generates a one-minute baseline report under `backend/zap-reports/`. Keep the scan target on `host.docker.internal:5000`; do not add external seeds, import public API definitions, or supply authentication material. Confirm every reported URL uses that host and port. Stop and investigate if a report lists any other host.

4. Review each alert in the HTML or JSON report. ZAP alerts are findings to triage, not automatically confirmed vulnerabilities: examine the alert's risk, confidence, evidence, and request/response, then reproduce it with a safe request against the same local endpoint. Record the ZAP version, scan date, alert ID/name, affected local URL, risk/confidence, sanitized evidence, triage decision, remediation owner, and status. Do not put passwords, JWTs, secrets, or production data in evidence. Retest after remediation and keep reports out of source control unless they have been reviewed and sanitized.

Run the existing automated backend tests separately with `npm test -- --runInBand` from `backend`. A passing test suite or completed baseline scan does not establish that the application is secure. This baseline covers only what the unauthenticated passive spider reaches; it does not validate login abuse resistance, authenticated authorization/IDOR paths, database security, or active attack classes.
