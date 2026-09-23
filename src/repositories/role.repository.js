import {
  createRoleModel,
} from '../models/Role.js';

export function createRoleRepository() {
  const Role = createRoleModel();

  return Object.freeze({
   async findByRoleCodes(roleCodes) {
  requireStringArray(
    roleCodes,
    'roleCodes',
  );

  console.log(
    '[AUTH DEBUG] Role DB:',
    Role.db.name,
  );

  console.log(
    '[AUTH DEBUG] Role collection:',
    Role.collection.name,
  );

  console.log(
    '[AUTH DEBUG] Requested roleCodes:',
    roleCodes,
  );

  const roles = await Role.find({
    roleCode: {
      $in: roleCodes,
    },
  })
    .select(
      'roleCode portalCode',
    )
    .lean()
    .exec();

  console.log(
    '[AUTH DEBUG] Found roles:',
    roles,
  );

  return roles;
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