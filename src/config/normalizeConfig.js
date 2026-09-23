import { defaultConfig } from './defaultConfig.js';

// --------------------------------------------------
// Authentication configuration
// --------------------------------------------------

const AUTHENTICATION_KEYS = Object.freeze([
  'accessToken',
  'session',
]);

const ACCESS_TOKEN_KEYS = Object.freeze([
  'algorithm',
  'expiresInSeconds',
  'issuer',
  'audience',
  'secret',
]);

const ACCESS_TOKEN_ALGORITHMS =
  Object.freeze([
    'HS256',
  ]);

const SESSION_KEYS = Object.freeze([
  'expiresInSeconds',
  'refreshToken',
]);

const REFRESH_TOKEN_KEYS = Object.freeze([
  'bytes',
]);

// --------------------------------------------------
// Two-factor configuration
// --------------------------------------------------

const TWO_FACTOR_MODES = Object.freeze([
  'email',
  'mobile',
  'email_mobile',
]);

const TWO_FACTOR_KEYS = Object.freeze([
  'mode',
  'otp',
  'development',
]);

const OTP_KEYS = Object.freeze([
  'length',
  'expiresInSeconds',
  'maxAttempts',
  'maxResends',
]);

const DEVELOPMENT_KEYS = Object.freeze([
  'exposeOtp',
]);

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    [Object.prototype, null].includes(
      Object.getPrototypeOf(value),
    )
  );
}

function hasUnsupportedKeys(
  object,
  supportedKeys,
) {
  return Reflect.ownKeys(object).some(
    (key) =>
      typeof key !== 'string' ||
      !supportedKeys.includes(key),
  );
}

// --------------------------------------------------
// Normalize configuration
// --------------------------------------------------

export function normalizeConfig(options = {}) {
  if (!isPlainObject(options)) {
    throw new TypeError(
      'Auth router options must be a plain object',
    );
  }

  const supported = [
    'masterEncryptionKey',
    'masterHmacKey',
    'encryptionKeyVersion',
    'hmacKeyVersion',
    'captchaSecretKey',
    'authentication',
    'twoFactor',
  ];

  if (
    hasUnsupportedKeys(
      options,
      supported,
    )
  ) {
    throw new TypeError(
      'Unsupported auth router configuration option',
    );
  }

  // --------------------------------------------------
  // Authentication configuration
  // --------------------------------------------------

  const providedAuthentication =
    Object.prototype.hasOwnProperty.call(
      options,
      'authentication',
    )
      ? options.authentication
      : {};

  if (
    !isPlainObject(
      providedAuthentication,
    )
  ) {
    throw new TypeError(
      'authentication must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedAuthentication,
      AUTHENTICATION_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported authentication configuration option',
    );
  }

  // --------------------------------------------------
  // Access token configuration
  // --------------------------------------------------

  const providedAccessToken =
    Object.prototype.hasOwnProperty.call(
      providedAuthentication,
      'accessToken',
    )
      ? providedAuthentication.accessToken
      : {};

  if (
    !isPlainObject(
      providedAccessToken,
    )
  ) {
    throw new TypeError(
      'authentication.accessToken must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedAccessToken,
      ACCESS_TOKEN_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported authentication.accessToken configuration option',
    );
  }

  const accessToken = {
    ...defaultConfig.authentication
      .accessToken,

    ...providedAccessToken,
  };

  // --------------------------------------------------
  // Validate access token algorithm
  // --------------------------------------------------

  if (
    !ACCESS_TOKEN_ALGORITHMS.includes(
      accessToken.algorithm,
    )
  ) {
    throw new TypeError(
      'authentication.accessToken.algorithm must be HS256',
    );
  }

  // --------------------------------------------------
  // Validate access token expiry
  // --------------------------------------------------

  if (
    !Number.isInteger(
      accessToken.expiresInSeconds,
    ) ||
    accessToken.expiresInSeconds < 60
  ) {
    throw new TypeError(
      'authentication.accessToken.expiresInSeconds must be an integer of at least 60',
    );
  }

  // --------------------------------------------------
  // Validate access token issuer
  // --------------------------------------------------

  if (
    typeof accessToken.issuer !==
      'string' ||
    !accessToken.issuer.trim()
  ) {
    throw new TypeError(
      'authentication.accessToken.issuer must be a non-empty string',
    );
  }

  // --------------------------------------------------
  // Validate access token audience
  // --------------------------------------------------

  if (
    typeof accessToken.audience !==
      'string' ||
    !accessToken.audience.trim()
  ) {
    throw new TypeError(
      'authentication.accessToken.audience must be a non-empty string',
    );
  }

  // --------------------------------------------------
  // Validate access token signing secret
  // --------------------------------------------------

  if (
    typeof accessToken.secret !==
      'string' ||
    !accessToken.secret.trim()
  ) {
    throw new TypeError(
      'authentication.accessToken.secret must be a non-empty string',
    );
  }

  // --------------------------------------------------
  // Session configuration
  // --------------------------------------------------

  const providedSession =
    Object.prototype.hasOwnProperty.call(
      providedAuthentication,
      'session',
    )
      ? providedAuthentication.session
      : {};

  if (
    !isPlainObject(
      providedSession,
    )
  ) {
    throw new TypeError(
      'authentication.session must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedSession,
      SESSION_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported authentication.session configuration option',
    );
  }

  // --------------------------------------------------
  // Refresh token configuration
  // --------------------------------------------------

  const providedRefreshToken =
    Object.prototype.hasOwnProperty.call(
      providedSession,
      'refreshToken',
    )
      ? providedSession.refreshToken
      : {};

  if (
    !isPlainObject(
      providedRefreshToken,
    )
  ) {
    throw new TypeError(
      'authentication.session.refreshToken must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedRefreshToken,
      REFRESH_TOKEN_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported authentication.session.refreshToken configuration option',
    );
  }

  const refreshToken = {
    ...defaultConfig.authentication
      .session.refreshToken,

    ...providedRefreshToken,
  };

  const session = {
    ...defaultConfig.authentication
      .session,

    ...providedSession,

    refreshToken,
  };

  // --------------------------------------------------
  // Validate session expiry
  // --------------------------------------------------

  if (
    !Number.isInteger(
      session.expiresInSeconds,
    ) ||
    session.expiresInSeconds < 60
  ) {
    throw new TypeError(
      'authentication.session.expiresInSeconds must be an integer of at least 60',
    );
  }

  // --------------------------------------------------
  // Validate refresh token entropy
  // --------------------------------------------------

  if (
    !Number.isInteger(
      refreshToken.bytes,
    ) ||
    refreshToken.bytes < 32
  ) {
    throw new TypeError(
      'authentication.session.refreshToken.bytes must be an integer of at least 32',
    );
  }

  // --------------------------------------------------
  // Build normalized authentication configuration
  // --------------------------------------------------

  const authentication = {
    ...defaultConfig.authentication,
    ...providedAuthentication,

    accessToken,
    session,
  };

  // --------------------------------------------------
  // Two-factor configuration
  // --------------------------------------------------

  const providedTwoFactor =
    Object.prototype.hasOwnProperty.call(
      options,
      'twoFactor',
    )
      ? options.twoFactor
      : {};

  if (
    !isPlainObject(
      providedTwoFactor,
    )
  ) {
    throw new TypeError(
      'twoFactor must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedTwoFactor,
      TWO_FACTOR_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported twoFactor configuration option',
    );
  }

  // --------------------------------------------------
  // OTP configuration
  // --------------------------------------------------

  const providedOtp =
    Object.prototype.hasOwnProperty.call(
      providedTwoFactor,
      'otp',
    )
      ? providedTwoFactor.otp
      : {};

  if (!isPlainObject(providedOtp)) {
    throw new TypeError(
      'twoFactor.otp must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedOtp,
      OTP_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported twoFactor.otp configuration option',
    );
  }

  const otp = {
    ...defaultConfig.twoFactor.otp,
    ...providedOtp,
  };

  // --------------------------------------------------
  // Development configuration
  // --------------------------------------------------

  const providedDevelopment =
    Object.prototype.hasOwnProperty.call(
      providedTwoFactor,
      'development',
    )
      ? providedTwoFactor.development
      : {};

  if (
    !isPlainObject(
      providedDevelopment,
    )
  ) {
    throw new TypeError(
      'twoFactor.development must be a plain object',
    );
  }

  if (
    hasUnsupportedKeys(
      providedDevelopment,
      DEVELOPMENT_KEYS,
    )
  ) {
    throw new TypeError(
      'Unsupported twoFactor.development configuration option',
    );
  }

  const development = {
    ...defaultConfig.twoFactor.development,
    ...providedDevelopment,
  };

  // --------------------------------------------------
  // Build normalized 2FA configuration
  // --------------------------------------------------

  const twoFactor = {
    ...defaultConfig.twoFactor,
    ...providedTwoFactor,

    otp,
    development,
  };

  // --------------------------------------------------
  // Validate 2FA mode
  // --------------------------------------------------

  if (
    !TWO_FACTOR_MODES.includes(
      twoFactor.mode,
    )
  ) {
    throw new TypeError(
      'twoFactor.mode must be one of: email, mobile, email_mobile',
    );
  }

  // --------------------------------------------------
  // Validate OTP configuration
  // --------------------------------------------------

  if (
    !Number.isInteger(otp.length) ||
    otp.length < 4 ||
    otp.length > 8
  ) {
    throw new TypeError(
      'twoFactor.otp.length must be an integer between 4 and 8',
    );
  }

  if (
    !Number.isInteger(
      otp.expiresInSeconds,
    ) ||
    otp.expiresInSeconds < 60
  ) {
    throw new TypeError(
      'twoFactor.otp.expiresInSeconds must be an integer of at least 60',
    );
  }

  if (
    !Number.isInteger(
      otp.maxAttempts,
    ) ||
    otp.maxAttempts < 1
  ) {
    throw new TypeError(
      'twoFactor.otp.maxAttempts must be a positive integer',
    );
  }

  if (
    !Number.isInteger(
      otp.maxResends,
    ) ||
    otp.maxResends < 0
  ) {
    throw new TypeError(
      'twoFactor.otp.maxResends must be a non-negative integer',
    );
  }

  // --------------------------------------------------
  // Validate development configuration
  // --------------------------------------------------

  if (
    typeof development.exposeOtp !==
      'boolean'
  ) {
    throw new TypeError(
      'twoFactor.development.exposeOtp must be a boolean',
    );
  }

  // --------------------------------------------------
  // Return normalized configuration
  // --------------------------------------------------

  return Object.freeze({
    ...defaultConfig,
    ...options,

    authentication: Object.freeze({
      ...authentication,

      accessToken: Object.freeze({
        ...accessToken,
      }),

      session: Object.freeze({
        ...session,

        refreshToken: Object.freeze({
          ...refreshToken,
        }),
      }),
    }),

    twoFactor: Object.freeze({
      ...twoFactor,

      otp: Object.freeze({
        ...otp,
      }),

      development: Object.freeze({
        ...development,
      }),
    }),
  });
}