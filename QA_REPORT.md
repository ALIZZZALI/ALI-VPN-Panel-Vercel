# ALI VPN PANEL — QA Report (Vercel-ready build)

## What changed

- Added a pure WSGI entrypoint (`app` in root `app.py`) compatible with the Vercel Python runtime; kept the original local `run.bat` HTTP server path.
- Added `vercel.json`, `.python-version`, `.vercelignore`, and a no-third-party-dependency `requirements.txt`.
- Added persistent settings/session/temporary-backup storage through Upstash Redis REST, supporting Vercel environment variable names `KV_REST_API_URL` / `KV_REST_API_TOKEN` and `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`.
- When storage is not configured, the panel shows a deployment setup message and does not pretend local files are durable.
- Replaced a seeded first-run password on Vercel with a first-visit admin password setup (minimum 12 characters); creation is gated by a server-only `ALI_VPN_SETUP_TOKEN`, a distributed one-time lock, and rate-limiting for invalid tokens. Both API key fields start empty, owner maps and logs start empty, and there is no preconfigured admin account.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` on Vercel. Sessions persist in KV; password changes and full restore rotate the session epoch. Login attempts and invalid setup tokens are rate-limited in KV across instances; warm instances refresh the shared state from KV per request.
- Full backup work runs synchronously inside the serverless invocation rather than relying on detached background threads. Temporary KV storage refuses full backup results above 4 MiB; Vercel function duration limits still apply.
- Updated README and `.gitignore` to warn against committing local settings or environment files.

## Verification performed

- `python -m py_compile app.py`: passed.
- `node --check` on the embedded JavaScript extracted from `static/index.html`: passed.
- `python -m unittest discover -s tests -v`: **38 tests passed** after cold-instance authentication, setup-conflict, and Redis logout regression checks (no real API calls made by tests).
- WSGI smoke test: `/` responds with the app HTML, `/api/auth/check` reports setup state, and mocked first-admin setup writes an empty API-key state and issues a Secure/HttpOnly/SameSite cookie.
- WSGI test suite covers: first-run setup, rejection of invalid setup tokens, competing setup attempts, and short/mismatched passwords, missing KV guidance, cookie/session persistence through a mocked Redis REST implementation, cross-instance state refresh, and shared login-rate-limit behavior.
- `index.html` and `static/index.html` are byte-identical.
- The deployment ZIP was scanned for the previously disclosed test key values; neither appears in the project source.

- Additional regression tests verify migration of legacy Redis records missing `session_version` and API-key persistence across a simulated new serverless request.

## Authentication / session review

- Root cause: this module exported both a `handler` subclass and a WSGI callable named `app`. The Redis refresh existed only in `app()`, but Vercel can call the `BaseHTTPRequestHandler` entrypoint directly. A cold instance then began with an empty admin record and random session version, so `/api/auth/check` could show setup while `/api/setup` re-read Redis and reported that an admin already existed. The same stale state could reject the session on the next protected request.
- Redis refresh now runs in the request handler before each API GET/POST, so direct-handler and WSGI execution use the same persisted state.
- Setup conflicts switch the UI to login after re-checking state; login/setup verify that the session works on a subsequent request; logout checks server success before switching the UI.
- Added tests for cold-instance admin/session restore, existing-admin setup conflict, login persistence, and Redis logout revocation.

## Not verified live

- No live Vercel deployment was created from this environment. The user's Vercel account, Git integration, deployment settings and Upstash credentials are not available here.
- No real Upstash database or Iranisystem API account was contacted. Unit tests use local mocks and prove the application's request handling, not validity of credentials or upstream API availability.
- The WSGI entrypoint was exercised locally through a WSGI harness; the actual Vercel build/runtime must still be verified after deployment.

## Deployment requirements and limitations

1. Connect Upstash Redis from the Vercel Dashboard's Storage section. Ensure the REST URL and write token appear in the project environment, then redeploy. Persistent settings and sessions are intentionally unavailable without this storage connection.
2. Set `ALI_VPN_SETUP_TOKEN` as a long random secret in Vercel Environment Variables before the first setup. On first visit enter that token and create the admin password; remove the setup-token variable after setup is complete. Then enter the direct/tunnel API keys from the panel settings page. Never commit any secrets into Git.
3. The API keys are stored server-side in the Redis-backed JSON record, but are not additionally encrypted by the application before storage. Restrict access to the Vercel project and the Upstash token.
4. Full backup generation is constrained by the Vercel function time limit and the 4 MiB temporary KV result limit in this build. Large account backups may need a dedicated object-storage path.
5. Upstream operations depend on Iranisystem API behavior and network availability; no real create/renew/delete operation was performed during QA.
