import { createUserModel } from '../models/User.js';

import {
  createFieldEncryption,
} from '../security/fieldEncryption.js';

import {
  normalizeConfig,
} from '../config/normalizeConfig.js';

export function createUserRepository(
  options = {},
  connection,
) {
  const config = normalizeConfig(options);

  const User = createUserModel(
    config,
    connection,
  );

  const {
    blindIndex,
  } = createFieldEncryption(config);

  function emailBlindIndex(email) {
    requireString(email, 'email');

    return blindIndex(email, {
      dbName: 'userManagement',
      collectionName: 'users',
      fieldName: 'email',
    });
  }

  return Object.freeze({
    async findByUserId(userId) {
      requireString(userId, 'userId');

      return User.findOne({
        userId,
      })
        .lean()
        .exec();
    },

    async findByEncryptedEmail(email) {
      const index =
        emailBlindIndex(email);

      return User.findOne({
        '__search.email': index,
      })
        .lean()
        .exec();
    },

    async findByEncryptedEmailWithPassword(
      email,
    ) {
      const index =
        emailBlindIndex(email);

      return User.findOne({
        '__search.email': index,
      })
        .select('+password')
        .lean()
        .exec();
    },
  });
}

function requireString(value, name) {
  if (
    typeof value !== 'string' ||
    !value.trim()
  ) {
    throw new TypeError(
      `${name} must be a non-empty string`,
    );
  }
}

// Preserve internal operation names while
// allowing configuration injection.

export async function findByUserId(
  userId,
  config = {},
) {
  return createUserRepository(
    config,
  ).findByUserId(userId);
}

export async function findByEncryptedEmail(
  email,
  config = {},
) {
  return createUserRepository(
    config,
  ).findByEncryptedEmail(email);
}