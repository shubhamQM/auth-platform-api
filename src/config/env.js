import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';

dotenv.config({
  path: fileURLToPath(
    new URL('../../.env', import.meta.url),
  ),
  quiet: true,
});

const port = Number(
  process.env.PORT || 5000,
);

const nodeEnv =
  process.env.NODE_ENV || 'development';

if (
  !Number.isInteger(port) ||
  port < 1 ||
  port > 65535
) {
  throw new Error(
    'PORT must be an integer between 1 and 65535',
  );
}

if (!process.env.CLIENT_ORIGIN) {
  throw new Error(
    'CLIENT_ORIGIN is required',
  );
}

if (!process.env.USER_MONGO_URI?.trim()) {
  throw new Error(
    'USER_MONGO_URI is required',
  );
}

if (
  !process.env.RECAPTCHA_SECRET_KEY?.trim()
) {
  throw new Error(
    'RECAPTCHA_SECRET_KEY is required',
  );
}

// --------------------------------------------------
// JWT access-token signing secret
// --------------------------------------------------

if (
  !process.env.JWT_ACCESS_SECRET?.trim()
) {
  throw new Error(
    'JWT_ACCESS_SECRET is required',
  );
}

// --------------------------------------------------
// Development OTP exposure
// --------------------------------------------------

const exposeDevelopmentOtp =
  nodeEnv === 'development' &&
  process.env.EXPOSE_DEVELOPMENT_OTP ===
    'true';

// --------------------------------------------------
// Refresh-token cookie configuration
//
// The refresh token will eventually be stored in an
// HttpOnly browser cookie instead of being managed
// directly by frontend JavaScript.
//
// Do not configure a cookie domain here. Keeping the
// cookie host-only limits it to the Auth API host.
// --------------------------------------------------

const refreshCookieName =
  process.env.AUTH_REFRESH_COOKIE_NAME
    ?.trim() ||
  'auth_refresh';

const refreshCookie =
  Object.freeze({
    name:
      refreshCookieName,

    httpOnly:
      true,

    secure:
      nodeEnv === 'production',

    sameSite:
      nodeEnv === 'production'
        ? 'none'
        : 'lax',

    path:
      '/api/auth',
  });

// --------------------------------------------------
// Application configuration
// --------------------------------------------------

export const config = {
  nodeEnv,

  port,

  clientOrigin:
    process.env.CLIENT_ORIGIN,

  userMongoUri:
    process.env.USER_MONGO_URI,

  encryption: Object.freeze({
    masterEncryptionKey:
      process.env.MASTER_ENCRYPTION_KEY,

    masterHmacKey:
      process.env.MASTER_HMAC_KEY,

    encryptionKeyVersion:
      process.env.ENCRYPTION_KEY_VERSION,

    hmacKeyVersion:
      process.env.HMAC_KEY_VERSION,
  }),

  captcha: Object.freeze({
    secretKey:
      process.env.RECAPTCHA_SECRET_KEY,
  }),

  authentication: Object.freeze({
    accessToken: Object.freeze({
      secret:
        process.env.JWT_ACCESS_SECRET,
    }),

    refreshCookie,
  }),

  twoFactor: Object.freeze({
    development: Object.freeze({
      exposeOtp:
        exposeDevelopmentOtp,
    }),
  }),
};