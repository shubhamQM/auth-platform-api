# @org/auth-platform-api

Reusable authentication API package and standalone authentication server for applications sharing the central `userManagement` authentication database.

The package provides authentication, two-factor verification, JWT access tokens, refresh sessions, logout, authenticated user lookup, and Role → Portal access resolution.

---

## Architecture

```text
                    userManagement
               SHARED MASTER DATABASE
                         │
                         ▼
               auth-platform-api
                BACKEND NPM PACKAGE
                         │
                 deployed centrally
                         │
                         ▼
               auth-platform-ui
                 FRONTEND PACKAGE
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      Marketing         QBMS           OSM
```

The authentication API owns:

- credential verification
- CAPTCHA validation
- two-factor authentication
- JWT access-token issuance
- refresh-session management
- logout
- authenticated user lookup
- Role → Portal access resolution

Fine-grained Feature / Privilege authorization is not yet part of the public authentication contract.

---

## Package usage

```js
import express from 'express';

import {
  createAuthRouter,
} from '@org/auth-platform-api';

const app = express();

app.use(express.json());

app.use(
  '/api/auth',
  createAuthRouter({
    masterEncryptionKey:
      process.env.MASTER_ENCRYPTION_KEY,

    masterHmacKey:
      process.env.MASTER_HMAC_KEY,

    encryptionKeyVersion:
      process.env.ENCRYPTION_KEY_VERSION,

    hmacKeyVersion:
      process.env.HMAC_KEY_VERSION,

    captchaSecretKey:
      process.env.CAPTCHA_SECRET_KEY,

    authentication: {
      // authentication configuration
    },

    twoFactor: {
      // two-factor configuration
    },
  }),
);
```

`createAuthRouter(options = {})` returns a new Express router for every call.

Configuration is normalized per router instance without shared mutable configuration state.

Unknown top-level configuration options are rejected.

---

## Public package export

The public package export is:

```js
createAuthRouter
```

Importing the package does not:

- load `.env`
- connect to MongoDB
- start an HTTP server
- terminate the consuming process

The host application owns middleware, database lifecycle, and server startup.

---

# API Contract

All authentication endpoints are mounted relative to the router.

When the standalone server mounts the router at:

```text
/api/auth
```

the endpoints become:

```text
POST /api/auth/login
POST /api/auth/2fa/verify
POST /api/auth/2fa/resend
POST /api/auth/refresh
POST /api/auth/logout
GET  /api/auth/me
POST /api/auth/forgot-password
```

---

## Common success contract

Successful responses use:

```json
{
  "success": true
}
```

Endpoint-specific fields are returned at the top level.

Responses are intentionally not wrapped in a `data` property.

Example:

```json
{
  "success": true,
  "accessToken": "...",
  "refreshToken": "...",
  "user": {}
}
```

---

## Common error contract

API errors use:

```json
{
  "success": false,
  "code": "STABLE_MACHINE_CODE",
  "message": "Human-readable message"
}
```

Some errors may also contain structured metadata:

```json
{
  "success": false,
  "code": "INVALID_OTP",
  "message": "Invalid verification code",
  "details": {
    "attemptsRemaining": 4
  }
}
```

Client applications should use `code` for application logic and `message` for user-facing or diagnostic information.

---

# Authentication Endpoints

## POST `/login`

Authenticates the user's credentials and creates a two-factor authentication challenge.

### Request

```json
{
  "email": "user@example.edu",
  "password": "Password@123",
  "captchaToken": "captcha-token"
}
```

### Success

```json
{
  "success": true,
  "requiresTwoFactor": true,
  "challengeId": "challenge-id",
  "mode": "email",
  "expiresAt": "2026-09-17T10:00:00.000Z"
}
```

When development OTP exposure is explicitly enabled in a development environment, the response may additionally contain:

```json
{
  "developmentOtp": {
    "email": "123456",
    "mobile": null
  }
}
```

Development OTP exposure must not be enabled in production.

### Errors

Possible error codes include:

```text
CAPTCHA_INVALID
INVALID_CREDENTIALS
ACCOUNT_INACTIVE
INTERNAL_ERROR
```

`INVALID_CREDENTIALS` returns HTTP `401`.

`ACCOUNT_INACTIVE` returns HTTP `403`.

CAPTCHA verification is part of the API design but may be temporarily bypassed in local development. It must be enabled for production deployment.

---

## POST `/2fa/verify`

Verifies the OTP associated with an authentication challenge.

The required OTP fields depend on the mode with which the challenge was created.

### Email mode

```json
{
  "challengeId": "challenge-id",
  "emailCode": "123456"
}
```

### Mobile mode

```json
{
  "challengeId": "challenge-id",
  "mobileCode": "123456"
}
```

### Email + mobile mode

```json
{
  "challengeId": "challenge-id",
  "emailCode": "123456",
  "mobileCode": "654321"
}
```

### Success

Successful verification completes authentication and returns the access and refresh credentials.

```json
{
  "success": true,
  "twoFactorVerified": true,
  "accessToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "refreshToken": "...",
  "session": {},
  "user": {}
}
```

### Invalid OTP

```json
{
  "success": false,
  "code": "INVALID_OTP",
  "message": "Invalid verification code",
  "details": {
    "attemptsRemaining": 4
  }
}
```

### Errors

Possible error codes include:

```text
INVALID_CHALLENGE
CHALLENGE_EXPIRED
INVALID_OTP
MAX_ATTEMPTS_EXCEEDED
INTERNAL_ERROR
```

---

## POST `/2fa/resend`

Generates a replacement OTP for an active authentication challenge.

### Request

```json
{
  "challengeId": "challenge-id",
  "channel": "email"
}
```

Supported channels are:

```text
email
mobile
```

The requested channel must be required by the challenge's original 2FA mode.

### Success

```json
{
  "success": true,
  "challengeId": "challenge-id",
  "mode": "email",
  "channel": "email",
  "expiresAt": "2026-09-17T10:00:00.000Z",
  "resendCount": 1,
  "resendsRemaining": 2
}
```

Development environments may additionally receive `developmentOtp` when explicit OTP exposure is enabled.

### Errors

Possible error codes include:

```text
INVALID_CHALLENGE
CHALLENGE_EXPIRED
INVALID_CHANNEL
CHANNEL_NOT_REQUIRED
MAX_ATTEMPTS_EXCEEDED
MAX_RESENDS_EXCEEDED
INTERNAL_ERROR
```

---

## POST `/refresh`

Rotates a valid refresh token and issues a new access token and refresh token.

Refresh tokens are opaque credentials.

Only the refresh-token hash is persisted by the authentication session layer.

### Request

```json
{
  "refreshToken": "refresh-token"
}
```

### Success

```json
{
  "success": true,
  "accessToken": "...",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "refreshToken": "...",
  "session": {},
  "user": {}
}
```

The supplied refresh token is rotated during a successful refresh.

The previous refresh token must no longer be treated as a valid current token.

### Errors

Possible error codes include:

```text
INVALID_REFRESH_TOKEN
SESSION_EXPIRED
REFRESH_TOKEN_REUSED
USER_NOT_FOUND
ACCOUNT_INACTIVE
INTERNAL_ERROR
```

---

## POST `/logout`

Revokes the session represented by the supplied refresh token.

### Request

```json
{
  "refreshToken": "refresh-token"
}
```

### Success

```json
{
  "success": true,
  "session": {}
}
```

### Errors

Possible error codes include:

```text
INVALID_REFRESH_TOKEN
INTERNAL_ERROR
```

Logout currently revokes the server-side refresh session.

An already-issued access JWT remains independently valid until its access-token expiration unless additional revocation infrastructure is introduced.

---

## GET `/me`

Returns the currently authenticated user and resolved portal access.

### Authentication

Send the access token using:

```http
Authorization: Bearer <access-token>
```

The authenticated `userId` and `tenantId` are derived from the verified JWT.

Clients must not supply those values as trusted request parameters.

### Success

```json
{
  "success": true,
  "user": {
    "userId": "USR-...",
    "tenantId": "TEN-...",
    "firstName": "Example",
    "lastName": "User",
    "email": "user@example.edu",
    "portals": [
      {
        "portalId": "PORTAL-...",
        "portalCode": "MarketingPortal",
        "portalName": "Marketing Portal",
        "websiteUrl": "https://example.edu"
      }
    ]
  }
}
```

Portal access is currently resolved using the compatibility relationship:

```text
User.roleIds[]
      ↓
Role.roleCode
      ↓
Role.portalCode[]
      ↓
Portal.portalCode
```

### Authentication middleware errors

Missing Authorization header:

```json
{
  "success": false,
  "code": "AUTHENTICATION_REQUIRED",
  "message": "Authentication required"
}
```

Malformed Bearer header:

```json
{
  "success": false,
  "code": "INVALID_AUTHORIZATION_HEADER",
  "message": "Invalid authorization header"
}
```

Expired access token:

```json
{
  "success": false,
  "code": "ACCESS_TOKEN_EXPIRED",
  "message": "Access token has expired"
}
```

Invalid access token:

```json
{
  "success": false,
  "code": "INVALID_ACCESS_TOKEN",
  "message": "Invalid access token"
}
```

Additional authenticated-user errors may include:

```text
INVALID_AUTH_CONTEXT
USER_NOT_FOUND
ACCOUNT_INACTIVE
INTERNAL_ERROR
```

---

## POST `/forgot-password`

Password recovery is reserved in the API but is not implemented yet.

### Current response

HTTP `501`:

```json
{
  "success": false,
  "code": "NOT_IMPLEMENTED",
  "message": "Not implemented"
}
```

Forgot/reset password will be implemented in a later authentication step.

---

# JWT Access Tokens

The authentication API currently uses signed JWT access tokens.

Current design:

```text
Algorithm   HS256
Lifetime    short-lived
Issuer      auth-platform-api
Audience    auth-platform
```

The access token contains a minimal authentication identity.

Conceptually:

```json
{
  "sub": "USR-...",
  "tenantId": "TEN-..."
}
```

Roles, portals, features, and privileges are intentionally not embedded in the access JWT.

Authorization information should be resolved from authoritative server-side data rather than relying on long-lived authorization state inside the token.

---

# Refresh Sessions

Refresh authentication uses server-side sessions with rotating opaque refresh tokens.

```text
Login + successful 2FA
        ↓
Create AuthSession
        ↓
Issue opaque refresh token
        ↓
Store token hash only
        ↓
Client submits refresh token
        ↓
Validate session
        ↓
Rotate refresh token
        ↓
Issue new access token
```

The current design supports multiple sessions for the same user, allowing multiple devices or browsers.

The current default absolute session lifetime is seven days unless changed through configuration.

---

# Password Security

Passwords are stored using Argon2id password hashing.

Passwords must not be encrypted using the reversible field-encryption mechanism.

```text
plaintext password
        ↓
Argon2id
        ↓
password hash
        ↓
User.password
```

Login verification uses the plaintext candidate password against the stored Argon2 hash.

Malformed or unsupported password hashes fail authentication rather than exposing Argon2 errors.

---

# Master Encryption Compatibility

Sensitive reversible user fields use the master system's encryption compatibility layer.

The standalone server maps:

```text
MASTER_ENCRYPTION_KEY
MASTER_HMAC_KEY
ENCRYPTION_KEY_VERSION
HMAC_KEY_VERSION
```

into router configuration.

Keys must be supplied through the deployment environment.

`.env.example` must contain placeholders only and must never contain production keys.

Versions must match the master system.

No encryption-key or key-version defaults are assumed.

Encrypted email lookup uses the field-specific exact HMAC search index rather than decrypting every user record.

Password fields are explicitly excluded from reversible field encryption.

---

# Role → Portal Resolution

The current compatibility model resolves portal access through:

```text
User.roleIds[]
        ↓
Role.roleCode
        ↓
Role.portalCode[]
        ↓
Portal.portalCode
```

Portal responses expose safe portal information such as:

```text
portalId
portalCode
portalName
websiteUrl
```

Fine-grained Feature / Privilege authorization is intentionally deferred until the shared authorization schema is finalized.

---

# Standalone Server

Copy:

```text
.env.example
```

to:

```text
.env
```

and configure the required environment variables.

Install dependencies:

```bash
npm install
```

Development:

```bash
npm run dev
```

Production-style startup:

```bash
npm start
```

The standalone server connects to MongoDB before beginning to listen for HTTP requests.

Health endpoint:

```text
GET /api/health
```

Authentication router:

```text
/api/auth
```

---

# Testing

Run the complete test suite with:

```bash
npm test
```

HTTP API contract tests can be run independently with:

```bash
node --test tests/authApiContract.test.js
```

The API contract suite verifies, among other cases:

```text
/login invalid credentials
/2fa/verify invalid challenge
/2fa/verify invalid OTP + details contract
/2fa/resend invalid challenge
/refresh invalid refresh token
/logout invalid refresh token
/me missing authentication
/forgot-password not implemented
```

The current HTTP contract suite passes all eight contract tests.

Additional service-level tests cover refresh-token rotation, session expiration, logout, inactive users, missing users, and tenant mismatch handling.

---

# Packaging

The package uses JavaScript ES modules directly and does not require a build step.

Only the root package entry is publicly exported.

The package source and standard npm package metadata are included in the published package.

`.env` is excluded.

Publishing defaults to restricted access and requires access to the configured private `@org` package scope and registry.

---

# Current Limitations / Pending Work

The following items are intentionally not considered complete production functionality:

- CAPTCHA backend verification is temporarily bypassed during local development and must be restored before production.
- Production email/SMS OTP providers are not yet connected.
- Development OTP exposure must remain disabled in production.
- Fine-grained Feature / Privilege authorization is on hold pending the final shared authorization model.
- Forgot/reset password is not implemented.
- Browser refresh-token cookie transport is not finalized.
- Refresh-token reuse-detection hardening remains pending.
- JWT signing-key rotation remains pending.
- Existing access JWTs are not immediately revoked by logout.
- SSO portal handoff is not implemented yet.
- Portal URL data must be validated before production navigation.
- Legacy/new User schema and password-storage migration must be finalized before production rollout.