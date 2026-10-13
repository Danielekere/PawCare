# Validation report

Executed: `npm test` with Node 24.19.0 against an isolated in-memory SQLite database. Result: 1 integrated suite passed, 0 failures.

The suite verifies health, registration, password hashing, wrong-password rejection, anonymous access denial, CSRF rejection, origin rejection, invalid birth-date rejection, pet persistence, cross-user pet isolation, cross-user edit denial, cross-user booking denial, successful booking, slot conflict rejection, availability exclusion, cross-user appointment isolation, cross-user cancellation denial, owner confirmation denial, operator-assigned admin confirmation, owner cancellation, invalid status-transition rejection, slot reuse, parameterized handling of SQL-like profile input, signup/profile role protection, password change, session invalidation, login with the new password and logout revocation.

Frontend JavaScript syntax check passed using `node --check public/app.js`.

## Hosted verification — 13 October 2026

Render build on Node 24.21.0 passed both the SQLite suite and the same suite against live Neon PostgreSQL using an isolated temporary schema. The temporary schema was removed after testing. The tests used an explicit local origin; test-schema setup used Neon's direct endpoint because its transaction pooler rejects search_path startup options. The production application uses the pooled URL provided by the operator.

Render reported the deployment live. HTTPS `/health` returned `{"status":"ok"}`. Browser checks verified that login and signup render labelled fields, the public veterinarian list loads all three sample records from Neon, and searching for Tunde returns only that veterinarian.

Not yet performed: authenticated browser journeys with a real owner or clinic account, screen-reader audits, mobile device testing, concurrent load tests, backup restore verification and independent penetration testing. Automated PostgreSQL tests verify server workflows, not every browser interaction.
