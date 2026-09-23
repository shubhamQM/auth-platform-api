import mongoose from 'mongoose';

import {
  createFieldEncryptionPlugin,
} from '../security/fieldEncryptionPlugin.js';

export function createPortalModel(
  config = {},
  connection = mongoose.connection,
) {
  const portalSchema =
    new mongoose.Schema(
      {
        portalCode: {
          type: String,
          required: true,
        },

        name: {
          type: String,
          required: true,
        },
websiteUrl: {
  type: String,
  required: true,
},
        description: {
          type: String,
          default: null,
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
        collection: 'portals',

        // Auth API reads the existing
        // master collection.
        autoCreate: false,
        autoIndex: false,
      },
    );

  portalSchema.plugin(
    createFieldEncryptionPlugin(config),
    {
      dbName: 'userManagement',

      collectionName: 'portals',

      random: [
        'name',
        'description',
      ],

      searchable: [
        'name',
      ],

      searchablePartial: [
        'name',
      ],
    },
  );

  return connection.model(
    'Portal',
    portalSchema,
    'portals',
    {
      cache: false,
    },
  );
}