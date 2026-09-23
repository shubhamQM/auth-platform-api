import crypto from 'node:crypto';

import {
  normalizeConfig,
} from '../config/normalizeConfig.js';

import {
  deriveKey,
} from './keyManagement.js';

export function createOtpSecurity(options = {}) {
  const config = normalizeConfig(options);

  const otpConfig = config.twoFactor.otp;

  /*
   * Derive a dedicated key for 2FA OTP hashing.
   *
   * This uses the existing master HMAC key but a
   * separate context so OTP hashes cannot overlap
   * with field-search HMAC usage.
   */
  const otpHmacKey = deriveKey(
    config.masterHmacKey,
    `datamaster:auth:otp:${config.hmacKeyVersion}`,
  );

  // --------------------------------------------------
  // Generate OTP
  // --------------------------------------------------

  function generateOtp() {
    const length = otpConfig.length;

    const max = 10 ** length;

    const value = crypto.randomInt(0, max);

    return value
      .toString()
      .padStart(length, '0');
  }

  // --------------------------------------------------
  // Hash OTP
  // --------------------------------------------------

  function hashOtp({
    challengeId,
    channel,
    otp,
  }) {
    if (
      typeof challengeId !== 'string' ||
      !challengeId.trim()
    ) {
      throw new TypeError(
        'challengeId is required for OTP hashing',
      );
    }

    if (
      channel !== 'email' &&
      channel !== 'mobile'
    ) {
      throw new TypeError(
        'OTP channel must be email or mobile',
      );
    }

    if (
      typeof otp !== 'string' ||
      otp.length !== otpConfig.length ||
      !/^\d+$/.test(otp)
    ) {
      throw new TypeError(
        `OTP must contain exactly ${otpConfig.length} digits`,
      );
    }

    return crypto
      .createHmac(
        'sha256',
        otpHmacKey,
      )
      .update(
        `${challengeId}:${channel}:${otp}`,
        'utf8',
      )
      .digest('hex');
  }

  // --------------------------------------------------
  // Verify OTP
  // --------------------------------------------------

function verifyOtp(input = {}) {
  if (
    input === null ||
    typeof input !== 'object' ||
    Array.isArray(input)
  ) {
    return false;
  }

  const {
    challengeId,
    channel,
    otp,
    otpHash,
  } = input;

  if (
    typeof otpHash !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(otpHash)
  ) {
    return false;
  }

  let calculatedHash;

  try {
    calculatedHash = hashOtp({
      challengeId,
      channel,
      otp,
    });
  } catch {
    return false;
  }

  const expected =
    Buffer.from(otpHash, 'hex');

  const actual =
    Buffer.from(
      calculatedHash,
      'hex',
    );

  if (
    expected.length !== actual.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    expected,
    actual,
  );
}

  return Object.freeze({
    generateOtp,
    hashOtp,
    verifyOtp,
  });
}