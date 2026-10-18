# SecureHub

SecureHub is a security-focused web application that demonstrates practical design and implementation of an authentication API. I developed it to explore how common application security risks can be addressed through clear service boundaries, defensive input handling, explicit authorization, and automated tests.

> **Project status:** The Express API implements the features listed below. The React/Vite frontend is currently the original Vite starter screen; it is not yet connected to the API and is not a usable SecureHub dashboard. This repository is under active development, and later versions will build out the frontend and expand the security workflows.

## Why SecureHub Exists

Authentication code can appear to work while missing important security boundaries: revealing whether an account exists, storing raw passwords, trusting client-supplied roles, exposing another user's record, or interpreting MongoDB operators as query conditions. SecureHub makes these risks explicit and demonstrates mitigations that can be reviewed in the implementation and verified by tests.

## Engineering Objectives

- Organize the Express API into routes, controllers, services, middleware, models, and tests.
- Apply safer account flows with bcrypt password hashing, generic login errors, JWT verification, role-based access, and IDOR prevention.
- Validate and normalize request data before using it in database queries or authentication logic.
- Use automated tests to make security expectations repeatable and catch regressions.
- Provide a foundation for frontend integration and additional security controls.
- Support local review with OWASP ZAP's passive baseline scan.

SecureHub is an educational project, not a security certification or a guarantee that a deployment is secure. Review the code, configuration, infrastructure, and scan findings before using it with real users or sensitive data.

## Current Features

### Backend API

- `POST /api/auth/register`: validates email and password, normalizes email, hashes the password with bcrypt, and handles duplicate email addresses.
- `POST /api/auth/login`: checks credentials with bcrypt and issues a signed JWT containing the user ID and role.
- `GET /api/users/:userId`: requires a valid bearer token; regular users can view their own profile, while admins can view other profiles.
- `GET /api/health`: reports API health.
- Mongoose User model with unique email, password hash, role, and timestamps.
- Request type and length validation, MongoDB ObjectId validation, and protection against operator-shaped input.
- Login and registration rate limits using `express-rate-limit`.
- Helmet security headers, explicit CORS origin allowlisting, generic server error responses, and 404 handling.
- Jest and Supertest coverage for authentication, authorization, validation, rate limiting, CORS, and security headers.

### Frontend

The React/Vite project currently contains the starter screen only. It has not yet implemented SecureHub registration, login, token handling, profile views, or API integration.

## Languages and Technology

**Languages used in the repository:**

- JavaScript: CommonJS JavaScript for the Node.js backend and JSX for React components.
- HTML: Vite's frontend document.
- CSS: frontend stylesheets.
- JSON: package manifests, lockfiles, and configuration.

**Runtime, frameworks, and libraries:**

- Frontend: React and Vite.
- Backend: Node.js and Express.
- Database: MongoDB with Mongoose.
- Authentication: bcrypt and JSON Web Token (`jsonwebtoken`).
- API middleware: Helmet, `cors`, and `express-rate-limit`.
- Tests: Jest and Supertest.

## Project Structure

```text
SecureHub/
|-- backend/
|   |-- src/
|   |   |-- config/       # MongoDB, CORS, and rate-limit configuration
|   |   |-- controllers/  # HTTP request/response handlers
|   |   |-- middleware/   # Authentication, authorization, and HTTP middleware
|   |   |-- models/       # Mongoose models
|   |   |-- routes/       # Express route definitions
|   |   |-- services/     # Authentication and business logic
|   |   |-- tests/        # Jest/Supertest tests
|   |   `-- validators/   # Request validation and normalization
|   |-- .env.example
|   `-- package.json
`-- frontend/
    |-- src/              # React starter application
    |-- index.html
    `-- package.json
```

## Run Locally

Requirements: a supported Node.js installation, npm, and a local MongoDB instance or MongoDB-compatible development database.

1. Start MongoDB and configure the backend environment:

   ```powershell
   cd backend
   Copy-Item .env.example .env
   ```

2. Edit `backend/.env` for your local environment. Set `MONGODB_URI` to your local database and replace the example `JWT_SECRET` with a long, random development secret. Keep `.env` private; it is ignored by Git. Do not use development secrets or data in production.

3. Install and start the backend:

   ```powershell
   npm install
   npm run dev
   ```

   The example configuration uses port `5000` and allows the Vite origin `http://localhost:5173`.

4. In another terminal, start the frontend starter:

   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

   Vite normally serves on `http://localhost:5173`. The current frontend is a starter screen and does not call the backend yet.

## Tests

Run backend tests from the `backend` directory:

```powershell
npm test -- --runInBand
```

The tests use mocked user-model calls and do not require a live MongoDB server. They check expected behavior; they are not a complete security assessment.

## Deployment Guide

The frontend and backend are separate deployable applications. The frontend is currently a starter and does not use the API; build and deploy it only as a placeholder until integration is implemented.

### Backend

Deploy `backend` as a Node.js web service. Configure its build/install step as `npm install` and start command as `npm start`. Configure these environment variables in the hosting provider's secret/environment settings:

- `NODE_ENV=production`
- `PORT`: use the port assigned by the hosting platform when it requires one.
- `MONGODB_URI`: a production MongoDB connection string stored only in the provider's secret settings.
- `JWT_SECRET`: a strong, unique production secret stored only in the provider's secret settings.
- `JWT_EXPIRES_IN`: desired token lifetime, for example `1h`.
- `CORS_ALLOWED_ORIGINS`: the exact HTTPS origin of the deployed frontend, with no wildcard. Multiple origins can be comma-separated.

Use TLS/HTTPS at the hosting platform or trusted reverse proxy. Set proxy trust only when the deployment's proxy topology is known and configured. The included rate limiter uses in-process memory, so multiple backend instances do not share counters; use a compatible shared store before relying on rate limiting across a scaled deployment. Back up and restrict access to the production database.

### Frontend

Build the Vite project from `frontend` with `npm install` and `npm run build`; the static output is `frontend/dist`. Configure a static hosting service to publish that directory. When frontend API integration is added, configure its API base URL for the deployed backend and update the backend's `CORS_ALLOWED_ORIGINS` to the frontend's exact origin. Do not put JWT signing keys, database credentials, or other server secrets in frontend build variables; browser-delivered values are public.

## Local OWASP ZAP Baseline

The backend README documents a safe local OWASP ZAP baseline workflow targeting only the local health endpoint. See [backend/README.md](backend/README.md) for start, health-check, scan, and findings-review instructions. A baseline scan is passive and limited in coverage; completing it does not establish that the application is secure.

## Roadmap

Planned work for future versions may include:

- Replace the Vite starter with SecureHub's actual React experience and connect it to the API.
- Add frontend registration/login forms and handle bearer tokens without exposing them in logs or URLs.
- Add profile views and user-friendly handling for authentication and authorization errors.
- Add automated end-to-end tests and a documented CI workflow.
- Add a shared rate-limit store for multi-instance deployments and expand operational monitoring.
- Continue reviewing ZAP findings and add regression tests for confirmed issues.

The roadmap is directional, not a promise or release schedule. Version notes should be added here or in a changelog as changes are delivered.

## Contributing and Security Reports

Keep changes scoped, avoid committing `.env` files or scan reports containing sensitive data, and add tests for behavioral changes. For a suspected security issue, do not publish secrets or exploit details in a public issue; report it privately to the project maintainer.
