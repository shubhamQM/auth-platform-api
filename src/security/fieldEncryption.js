import crypto from 'node:crypto';
import { createKeyManagement } from './keyManagement.js';

export function createFieldEncryption(config = {}) {
  const { encryptionKey, hmacKey } = createKeyManagement(config);

  const PREFIX = 'enc:v1:';

  const IV_LENGTH = 12;

  const TAG_LENGTH = 16;

  const SEARCH_GRAM_SIZE = 3;

  // -------------------------------------------------------------
  // Encryption helpers
  // -------------------------------------------------------------

  function typeTag(value) {
    if (value instanceof Date) return 'date';
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';

    return 'json';
  }

  function serialize(value) {
    const tag = typeTag(value);

    return Buffer.from(
      JSON.stringify({
        value: tag === 'date' ? value.toISOString() : value,
        type: tag,
      }),
      'utf8',
    );
  }

  function restore(payload) {
    if (payload.type === 'date') {
      return new Date(payload.value);
    }

    return payload.value;
  }

  function isEncrypted(value) {
    return typeof value === 'string' && value.startsWith(PREFIX);
  }

  function deterministicIv(key, plaintext) {
    return crypto
      .createHmac('sha256', key)
      .update(plaintext)
      .digest()
      .subarray(0, IV_LENGTH);
  }

  function encryptField(
    value,
    {
      dbName,
      collectionName,
      fieldName,
      deterministic = false,
    },
  ) {
    if (
      value === undefined ||
      value === null ||
      isEncrypted(value)
    ) {
      return value;
    }

    const key = encryptionKey(
      dbName,
      collectionName,
      fieldName,
    );

    const plaintext = serialize(value);

    const iv = deterministic
      ? deterministicIv(key, plaintext)
      : crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      key,
      iv,
    );

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return (
      PREFIX +
      Buffer.concat([
        iv,
        tag,
        ciphertext,
      ]).toString('base64')
    );
  }

  function decryptField(
    value,
    {
      dbName,
      collectionName,
      fieldName,
    },
  ) {
    if (!isEncrypted(value)) {
      return value;
    }

    const key = encryptionKey(
      dbName,
      collectionName,
      fieldName,
    );

    const buffer = Buffer.from(
      value.slice(PREFIX.length),
      'base64',
    );

    const iv = buffer.subarray(
      0,
      IV_LENGTH,
    );

    const tag = buffer.subarray(
      IV_LENGTH,
      IV_LENGTH + TAG_LENGTH,
    );

    const ciphertext = buffer.subarray(
      IV_LENGTH + TAG_LENGTH,
    );

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      iv,
    );

    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return restore(
      JSON.parse(
        plaintext.toString('utf8'),
      ),
    );
  }

  // -------------------------------------------------------------
  // Existing exact searchable-field helper
  // -------------------------------------------------------------

  function blindIndex(
    value,
    {
      dbName,
      collectionName,
      fieldName,
    },
  ) {
    if (
      value === undefined ||
      value === null
    ) {
      return null;
    }

    return crypto
      .createHmac(
        'sha256',
        hmacKey(
          dbName,
          collectionName,
          fieldName,
        ),
      )
      .update(
        String(value)
          .trim()
          .toLowerCase(),
      )
      .digest('hex');
  }

  // -------------------------------------------------------------
  // Partial / substring search helpers
  // -------------------------------------------------------------

  function normalizeSearchText(value) {
    return String(value ?? '')
      .trim()
      .toLowerCase()
      .replace(/\s+/g, ' ');
  }

  /**
   * Converts text into unique 3-character n-grams.
   *
   * Example:
   *
   * "shubham"
   *
   * becomes:
   * shu
   * hub
   * ubh
   * bha
   * ham
   *
   * Spaces are ignored as standalone grams.
   */
  function getSearchNgrams(
    value,
    minGram = SEARCH_GRAM_SIZE,
  ) {
    const text = normalizeSearchText(value);

    if (text.length < minGram) {
      return [];
    }

    const grams = new Set();

    for (
      let i = 0;
      i <= text.length - minGram;
      i++
    ) {
      const gram = text.slice(
        i,
        i + minGram,
      );

      // Do not create tokens consisting
      // mainly of whitespace.
      if (
        gram.replace(/\s/g, '').length <
        minGram
      ) {
        continue;
      }

      grams.add(gram);
    }

    return [...grams];
  }

  /**
   * Creates a secure HMAC token for a search gram.
   *
   * The same gram will always generate
   * the same token for the same collection,
   * but the plaintext gram is never stored.
   */
  function blindSearchToken(
    value,
    {
      dbName,
      collectionName,
    },
  ) {
    if (
      value === undefined ||
      value === null ||
      value === ''
    ) {
      return null;
    }

    return crypto
      .createHmac(
        'sha256',
        hmacKey(
          dbName,
          collectionName,
          '__search',
        ),
      )
      .update(String(value))
      .digest('hex');
  }

  /**
   * Converts a plaintext value into
   * HMAC-based partial-search tokens.
   */
  function buildSearchTokens(
    value,
    {
      dbName,
      collectionName,
      minGram = SEARCH_GRAM_SIZE,
    },
  ) {
    const grams = getSearchNgrams(
      value,
      minGram,
    );

    return grams
      .map((gram) =>
        blindSearchToken(gram, {
          dbName,
          collectionName,
        }),
      )
      .filter(Boolean);
  }

  return {
    encryptField,
    decryptField,
    blindIndex,
    isEncrypted,

    // Partial search helpers
    normalizeSearchText,
    getSearchNgrams,
    blindSearchToken,
    buildSearchTokens,
  };
}
