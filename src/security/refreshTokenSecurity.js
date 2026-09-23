import crypto from 'node:crypto';

import {
  normalizeConfig,
} from '../config/normalizeConfig.js';

import {
  deriveKey,
} from './keyManagement.js';

export function createRefreshTokenSecurity(
  options = {},
) {
  const config = normalizeConfig(options);

  const refreshTokenConfig =
    config.authentication
      .session
      .refreshToken;

  /*
   * Derive a dedicated key for refresh-token hashing.
   *
   * This intentionally uses a different derivation
   * context from OTP hashes and searchable-field
   * blind indexes.
   */
  const refreshTokenHmacKey =
    deriveKey(
      config.masterHmacKey,
      `datamaster:auth:refresh-token:${config.hmacKeyVersion}`,
    );

  // --------------------------------------------------
  // Generate refresh token
  // --------------------------------------------------

  function generateRefreshToken({
    sessionId,
  } = {}) {
    requireSessionId(sessionId);

    const secret =
      crypto
        .randomBytes(
          refreshTokenConfig.bytes,
        )
        .toString('base64url');

    return `${sessionId}.${secret}`;
  }

  // --------------------------------------------------
  // Parse refresh token
  // --------------------------------------------------

  function parseRefreshToken(token) {
    if (
      typeof token !== 'string' ||
      !token.trim()
    ) {
      return null;
    }

    const normalized =
      token.trim();

    const separatorIndex =
      normalized.indexOf('.');

    if (
      separatorIndex <= 0 ||
      separatorIndex ===
        normalized.length - 1
    ) {
      return null;
    }

    /*
     * Exactly one separator is expected.
     * base64url does not contain ".".
     */
    if (
      normalized.indexOf(
        '.',
        separatorIndex + 1,
      ) !== -1
    ) {
      return null;
    }

    const sessionId =
      normalized.slice(
        0,
        separatorIndex,
      );

    const secret =
      normalized.slice(
        separatorIndex + 1,
      );

    if (
      !sessionId.trim() ||
      !secret ||
      !/^[A-Za-z0-9_-]+$/.test(
        secret,
      )
    ) {
      return null;
    }

    return Object.freeze({
      sessionId,
      secret,
    });
  }

  // --------------------------------------------------
  // Hash refresh token
  // --------------------------------------------------

  function hashRefreshToken(token) {
    const parsed =
      parseRefreshToken(token);

    if (!parsed) {
      throw new TypeError(
        'Invalid refresh token',
      );
    }

    return crypto
      .createHmac(
        'sha256',
        refreshTokenHmacKey,
      )
      .update(token.trim(), 'utf8')
      .digest('hex');
  }

  // --------------------------------------------------
  // Verify refresh token
  // --------------------------------------------------

  function verifyRefreshToken({
    token,
    tokenHash,
  } = {}) {
    if (
      typeof tokenHash !== 'string' ||
      !/^[a-f0-9]{64}$/i.test(
        tokenHash,
      )
    ) {
      return false;
    }

    let calculatedHash;

    try {
      calculatedHash =
        hashRefreshToken(token);
    } catch {
      return false;
    }

    const expected =
      Buffer.from(
        tokenHash,
        'hex',
      );

    const actual =
      Buffer.from(
        calculatedHash,
        'hex',
      );

    if (
      expected.length !==
      actual.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      expected,
      actual,
    );
  }

  // --------------------------------------------------
  // Helpers
  // --------------------------------------------------

  function requireSessionId(
    sessionId,
  ) {
    if (
      typeof sessionId !== 'string' ||
      !sessionId.trim()
    ) {
      throw new TypeError(
        'sessionId is required to create a refresh token',
      );
    }

    if (sessionId.includes('.')) {
      throw new TypeError(
        'sessionId cannot contain "."',
      );
    }
  }

  return Object.freeze({
    generateRefreshToken,
    parseRefreshToken,
    hashRefreshToken,
    verifyRefreshToken,
  });
}