export const defaultConfig = Object.freeze({
  authentication: Object.freeze({
    accessToken: Object.freeze({
      algorithm: 'HS256',
      expiresInSeconds: 900,
      issuer: 'auth-platform-api',
      audience: 'auth-platform',
    }),

    session: Object.freeze({
      expiresInSeconds: 604800,

      refreshToken: Object.freeze({
        bytes: 32,
      }),
    }),
  }),

  twoFactor: Object.freeze({
    mode: 'email',

    otp: Object.freeze({
      length: 6,
      expiresInSeconds: 300,
      maxAttempts: 5,
      maxResends: 3,
    }),

    development: Object.freeze({
      exposeOtp: false,
    }),
  }),
});