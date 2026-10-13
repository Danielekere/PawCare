# Validation report

Executed: `npm test` with Node 24.19.0 against an isolated in-memory SQLite database. Result: 1 integrated suite passed, 0 failures.

The suite verifies health, registration, password hashing, wrong-password rejection, anonymous access denial, CSRF rejection, origin rejection, invalid birth-date rejection, pet persistence, cross-user pet isolation, cross-user edit denial, cross-user booking denial, successful booking, slot conflict rejection, availability exclusion, cross-user appointment isolation, cross-user cancellation denial, owner confirmation denial, operator-assigned admin confirmation, owner cancellation, invalid status-transition rejection, slot reuse, parameterized handling of SQL-like profile input, signup/profile role protection, password change, session invalidation, login with the new password and logout revocation.

Frontend JavaScript syntax check passed using `node --check public/app.js`.

Not yet performed: browser interaction tests, screen-reader checks, mobile visual checks, real Neon/PostgreSQL integration tests, concurrent request tests against PostgreSQL, Render deployment checks, backup restore verification, load tests and independent penetration testing. Local SQLite behavior is not proof that every PostgreSQL path works.
