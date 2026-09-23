import mongoose from 'mongoose';

export function createAuthSessionModel(
  connection = mongoose.connection,
) {
  const authSessionSchema =
    new mongoose.Schema(
      {
        sessionId: {
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

        refreshTokenHash: {
          type: String,
          required: true,
          select: false,
        },

        expiresAt: {
          type: Date,
          required: true,
          index: true,
        },

        isRevoked: {
          type: Boolean,
          default: false,
          index: true,
        },

        revokedAt: {
          type: Date,
          default: null,
        },
      },
      {
        timestamps: true,
        versionKey: false,
        collection: 'authSessions',
      },
    );

  authSessionSchema.index({
    userId: 1,
    tenantId: 1,
    isRevoked: 1,
  });

  return connection.model(
    'AuthSession',
    authSessionSchema,
    'authSessions',
    {
      cache: false,
    },
  );
}