import crypto from 'node:crypto';
import { normalizeConfig } from '../config/normalizeConfig.js';
export function deriveKey(masterHex, context) {
  if (typeof masterHex !== 'string' || !/^(?:[a-fA-F0-9]{2})+$/.test(masterHex)) throw new Error('A non-empty hex-encoded master key is required');
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(masterHex, 'hex'), Buffer.alloc(0), Buffer.from(context), 32));
}
export function createKeyManagement(options = {}) {
  const config = normalizeConfig(options);
  function fieldKey(keyName, versionName, purpose, db, collection, field) {
    const version = config[versionName];
    if (!((typeof version === 'string' && version.trim()) || (typeof version === 'number' && Number.isFinite(version)))) throw new Error(versionName + ' is required');
    return deriveKey(config[keyName], 'datamaster:' + purpose + ':' + db + ':' + collection + ':' + field + ':' + version);
  }
  return {
    encryptionKey: (db, collection, field) => fieldKey('masterEncryptionKey', 'encryptionKeyVersion', 'enc', db, collection, field),
    hmacKey: (db, collection, field) => fieldKey('masterHmacKey', 'hmacKeyVersion', 'hmac', db, collection, field),
  };
}
