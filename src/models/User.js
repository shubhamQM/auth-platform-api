import mongoose from 'mongoose';

import {
  createFieldEncryptionPlugin,
} from '../security/fieldEncryptionPlugin.js';

export function createUserModel(
  config = {},
  connection = mongoose.connection,
) {
  const userSchema = new mongoose.Schema(
    {
      userId: {
        type: String,
        required: true,
      },

      userCode: {
        type: String,
        required: true,
      },

      fullName: {
        type: String,
        required: true,
      },

      firstName: {
        type: String,
        required: true,
      },

      middleName: {
        type: String,
        default: null,
      },

      lastName: {
        type: String,
        required: true,
      },

      email: {
        type: String,
        required: true,
      },

      phoneNo: {
        type: String,
        required: true,
      },

      // Authentication code explicitly selects
      // this field when password verification
      // is required.
      //
      // IMPORTANT:
      // Password contains an Argon2id hash.
      // It must NOT be encrypted by the field
      // encryption plugin.
      password: {
        type: String,
        required: true,
        select: false,
      },

      roleCode: {
        type: [String],
        default: [],
      },

      activeRoleCode: {
        type: String,
        default: null,
      },

      orgCode: {
        type: String,
        required: true,
      },

      userType: {
        type: String,
        enum: [
          'candidate',
          'employee',
        ],
        required: true,
      },

      isActive: {
        type: Boolean,
        default: true,
      },
    },
    {
      timestamps: true,
      versionKey: false,
      strict: false,
      collection: 'users',

      // Auth API only reads the existing
      // master collection structure.
      autoCreate: false,
      autoIndex: false,
    },
  );

  // --------------------------------------------------
  // Encryption compatibility
  //
  // This configuration must remain compatible with
  // the master userManagement.users model.
  // --------------------------------------------------

  userSchema.plugin(
    createFieldEncryptionPlugin(config),
    {
      dbName: 'userManagement',
      collectionName: 'users',

      deterministic: [
        'email',
        'phoneNo',
      ],

      searchable: [
        'email',
        'phoneNo',
      ],

      searchablePartial: [
        'fullName',
        'firstName',
        'middleName',
        'lastName',
      ],

      random: [
        'fullName',
        'firstName',
        'middleName',
        'lastName',
      ],
    },
  );

  // --------------------------------------------------
  // Model
  // --------------------------------------------------

  return connection.model(
    'User',
    userSchema,
    'users',
    {
      cache: false,
    },
  );
}
