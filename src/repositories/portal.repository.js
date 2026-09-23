import {
  createPortalModel,
} from '../models/Portal.js';

export function createPortalRepository(
  config = {},
  connection,
) {
  const Portal = createPortalModel(
    config,
    connection,
  );

  return Object.freeze({
    async findByPortalCodes(portalCodes) {
      requireStringArray(
        portalCodes,
        'portalCodes',
      );

      return Portal.find({
        portalCode: {
          $in: portalCodes,
        },
      })
        .select(
          'portalCode name websiteUrl description isActive',
        )
        .lean()
        .exec();
    },
  });
}

function requireStringArray(
  values,
  name,
) {
  if (
    !Array.isArray(values) ||
    values.length === 0
  ) {
    throw new TypeError(
      `${name} must be a non-empty array`,
    );
  }

  const isValid =
    values.every(
      (value) =>
        typeof value === 'string' &&
        value.trim(),
    );

  if (!isValid) {
    throw new TypeError(
      `${name} must contain only non-empty strings`,
    );
  }
}