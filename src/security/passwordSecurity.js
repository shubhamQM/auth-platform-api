import argon2 from 'argon2';

/**
 * Verify a plaintext password against an Argon2 password hash.
 *
 * Returns false for invalid/missing input or malformed hashes
 * instead of exposing Argon2 errors to authentication callers.
 */
export async function verifyPassword(
  password,
  passwordHash,
) {
  if (
    typeof password !== 'string' ||
    password.length === 0 ||
    typeof passwordHash !== 'string' ||
    passwordHash.length === 0
  ) {
    return false;
  }

  try {
    return await argon2.verify(
      passwordHash,
      password,
    );
  } catch {
    return false;
  }
}