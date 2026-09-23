import mongoose from 'mongoose';

export function createAuthChallengeModel(
  connection = mongoose.connection,
) {
  const authChallengeSchema =
    new mongoose.Schema(
      {
        challengeId: {
          type: String,
          required: true,
          unique: true,
          index: true,
        },

        userId: {
          type: String,
          required: true,
          index: true,
        },

        tenantId: {
          type: String,
          required: true,
          index: true,
        },

        mode: {
          type: String,
          required: true,
          enum: [
            'email',
            'mobile',
            'email_mobile',
          ],
        },

        emailOtpHash: {
          type: String,
          select: false,
        },

        mobileOtpHash: {
          type: String,
          select: false,
        },

        emailVerified: {
          type: Boolean,
          default: false,
        },

        mobileVerified: {
          type: Boolean,
          default: false,
        },

        attempts: {
          type: Number,
          default: 0,
        },

        resendCount: {
          type: Number,
          default: 0,
        },

        expiresAt: {
          type: Date,
          required: true,
        },

        isConsumed: {
          type: Boolean,
          default: false,
        },

        consumedAt: {
          type: Date,
          default: null,
        },
      },
      {
        timestamps: true,
        versionKey: false,
        collection: 'authChallenges',
      },
    );

  /*
   * Automatically remove expired challenges.
   *
   * MongoDB TTL cleanup is asynchronous, so application
   * code must still check expiresAt during verification.
   */
  authChallengeSchema.index(
    {
      expiresAt: 1,
    },
    {
      expireAfterSeconds: 0,
    },
  );

  return connection.model(
    'AuthChallenge',
    authChallengeSchema,
    'authChallenges',
    {
      cache: false,
    },
  );
}