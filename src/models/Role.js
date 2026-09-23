import mongoose from 'mongoose';

export function createRoleModel() {
  const roleSchema =
    new mongoose.Schema(
      {
        roleCode: {
          type: String,
          required: true,
        },

        roleName: {
          type:
            mongoose.Schema.Types.Mixed,
        },

        profileCode: [
          {
            type: String,
          },
        ],

        portalCode: [
          {
            type: String,
          },
        ],

        orgCode: {
          type: String,
        },
      },
      {
        timestamps: true,
        versionKey: false,
        strict: false,
        collection: 'roles',

        // Auth API only reads the existing
        // master collection.
        autoCreate: false,
        autoIndex: false,
      },
    );

  return mongoose.connection.model(
    'Role',
    roleSchema,
    'roles',
    {
      cache: false,
    },
  );
}