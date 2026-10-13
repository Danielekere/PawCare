# PawCare

Veterinary Appointment System for matric 23/SCI01/066. A responsive Node.js app with PostgreSQL (Neon in production) and a local SQLite development store.

## Local development

Node 24 or newer. Run `npm test` to verify the local backend. Run `npm install` then `npm start`; open http://localhost:3000. SQLite local data persists in an ignored `pawcare.sqlite` file. Never deploy SQLite on ephemeral hosting; production refuses to start without DATABASE_URL.

## Deployment

Connect the private GitHub repository to Render. Use Node 24, `npm ci`, `npm start`, and `/health`. Set DATABASE_URL to Neon's connection URL and APP_ORIGIN to the exact Render HTTPS origin. Database setup runs at startup with idempotent tables/indexes. Database TLS verifies certificates. Keep DATABASE_URL out of commits, frontend files, logs and screenshots. Use a limited app database role after provisioning, reserving schema-owner credentials for migrations.

## Administrator provisioning

Register the intended clinic operator normally, verify their identity out of band, then run a parameterized database update setting that existing user's role to `admin`. Never let signup fields assign roles. The app reads roles from the database on every authenticated request.

## Implemented

Registration, login/logout, salted scrypt passwords, hashed database session tokens, session expiry and revocation, CSRF and origin checks, input validation, parameterized SQL, role/ownership checks, profiles, password change, pets, search, guided booking, appointment collision protection, cancellation and clinic confirmation/decline/completion. Sample veterinarian records are labelled as fictional teaching data. No real clinic is contacted.

## Verification limits

Run `npm test` for authentication, ownership, booking, CSRF, password and clinic role checks against local SQLite. Neon/PostgreSQL integration and browser usability/accessibility checks must be run separately after database provisioning. Node syntax checks do not prove browser accessibility or live database behavior.

Email verification, email-based password recovery, notifications, file uploads, configurable clinic calendars and a separate veterinarian role are not implemented. Booking uses four predefined daily slots in West Africa Time. To reschedule, cancel then make a new request; these operations are not atomic. Rate limiting is per server instance and network peer, so a shared proxy may cause broad throttling; use a trusted ingress-aware distributed limiter before larger public usage. HTTPS requires the Render deployment to be verified. Export backups and test restores; monitor `/health` and structured error logs. No claim of production readiness is made until these deployment and operational checks pass.
