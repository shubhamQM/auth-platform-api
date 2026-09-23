import mongoose from 'mongoose';

import {
  createAuthChallengeModel,
} from '../models/AuthChallenge.js';

export function createAuthChallengeRepository(
  connection = mongoose.connection,
) {
  const AuthChallenge =
    createAuthChallengeModel(connection);

  // --------------------------------------------------
  // Create challenge
  // --------------------------------------------------

  async function createChallenge({
    challengeId,
    userId,
    tenantId,
    mode,
    emailOtpHash,
    mobileOtpHash,
    expiresAt,
  }) {
    return AuthChallenge.create({
      challengeId,
      userId,
      tenantId,
      mode,

      ...(emailOtpHash
        ? { emailOtpHash }
        : {}),

      ...(mobileOtpHash
        ? { mobileOtpHash }
        : {}),

      emailVerified: false,
      mobileVerified: false,

      attempts: 0,
      resendCount: 0,

      expiresAt,

      isConsumed: false,
      consumedAt: null,
    });
  }

  // --------------------------------------------------
  // Find active challenge
  // OTP hashes are explicitly selected because
  // they are select:false in the schema.
  // --------------------------------------------------

  async function findChallengeForVerification(
    challengeId,
  ) {
    return AuthChallenge.findOne({
      challengeId,
      isConsumed: false,
    })
      .select(
        '+emailOtpHash +mobileOtpHash',
      )
      .exec();
  }

  // --------------------------------------------------
  // Increment failed verification attempts
  // --------------------------------------------------

  async function incrementAttempts(
    challengeId,
  ) {
    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,
      },
      {
        $inc: {
          attempts: 1,
        },
      },
      {
        new: true,
      },
    ).exec();
  }

  // --------------------------------------------------
  // Increment resend count
  // --------------------------------------------------

  async function incrementResendCount(
    challengeId,
  ) {
    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,
      },
      {
        $inc: {
          resendCount: 1,
        },
      },
      {
        new: true,
      },
    ).exec();
  }

  // --------------------------------------------------
  // Mark individual channel as verified
  // --------------------------------------------------

  async function markEmailVerified(
    challengeId,
  ) {
    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,
      },
      {
        $set: {
          emailVerified: true,
        },
      },
      {
        new: true,
      },
    ).exec();
  }

  async function markMobileVerified(
    challengeId,
  ) {
    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,
      },
      {
        $set: {
          mobileVerified: true,
        },
      },
      {
        new: true,
      },
    ).exec();
  }

  // --------------------------------------------------
  // Consume completed challenge
  // --------------------------------------------------

  async function consumeChallenge(
    challengeId,
  ) {
    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,
      },
      {
        $set: {
          isConsumed: true,
          consumedAt: new Date(),
        },
      },
      {
        new: true,
      },
    ).exec();
  }
    // --------------------------------------------------
  // Resend OTP
  //
  // Atomically:
  // - enforce resend limit
  // - replace OTP hash
  // - reset channel verification
  // - refresh challenge expiry
  // - increment resend count
  //
  // Returns null when the challenge is unavailable
  // or the resend limit has already been reached.
  // --------------------------------------------------

  async function updateForResend({
    challengeId,
    channel,
    otpHash,
    expiresAt,
    maxResends,
  }) {
    const setFields = {
      expiresAt,
    };

    if (channel === 'email') {
      setFields.emailOtpHash = otpHash;
      setFields.emailVerified = false;
    } else if (channel === 'mobile') {
      setFields.mobileOtpHash = otpHash;
      setFields.mobileVerified = false;
    } else {
      throw new TypeError(
        'channel must be email or mobile',
      );
    }

    return AuthChallenge.findOneAndUpdate(
      {
        challengeId,
        isConsumed: false,

        resendCount: {
          $lt: maxResends,
        },
      },
      {
        $set: setFields,

        $inc: {
          resendCount: 1,
        },
      },
      {
        new: true,
      },
    )
      .select(
        '+emailOtpHash +mobileOtpHash',
      )
      .exec();
  }

    return Object.freeze({
    createChallenge,
    findChallengeForVerification,
    incrementAttempts,
    incrementResendCount,
    updateForResend,
    markEmailVerified,
    markMobileVerified,
    consumeChallenge,
  });
}