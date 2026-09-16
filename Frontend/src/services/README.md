# API services

All backend requests go through `api.js` (`apiGet`, `apiPost`), which talks to the
Spring Boot backend and attaches the JWT from `auth.js`.

Backend contract (base URL from `src/config/api.js`):

- `POST /api/auth/login` → `{ token, email, fullName }` (public)
- `GET  /api/health` → `{ status: "UP" }` (public)
- `GET  /api/dashboard/summary` → summary cards (JWT required)
- `GET  /api/dashboard/alerts` → recent alerts (JWT required)

Import `API_BASE_URL` from `src/config/api.js` instead of writing backend URLs in components.
