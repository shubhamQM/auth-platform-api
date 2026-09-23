import test from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";

import {
  createFieldEncryption,
} from "../src/security/fieldEncryption.js";

import {
  createUserModel,
} from "../src/models/User.js";

import {
  createUserRepository,
} from "../src/repositories/user.repository.js";

// -------------------------------------------------------------
// Test configuration
//
// The reusable auth package now validates the full auth config,
// including the access-token signing secret.
//
// These values are test-only and must never be reused outside
// the test suite.
// -------------------------------------------------------------

const config = {
  masterEncryptionKey:
    "11".repeat(32),

  masterHmacKey:
    "22".repeat(32),

  encryptionKeyVersion:
    "1",

  hmacKeyVersion:
    "1",

  authentication: {
    accessToken: {
      secret:
        "TEST_ONLY_ACCESS_TOKEN_SECRET_FOR_UNIT_TESTS",
    },
  },
};

const context = {
  dbName:
    "userManagement",

  collectionName:
    "users",

  fieldName:
    "email",
};

const security =
  createFieldEncryption(config);

// -------------------------------------------------------------
// Core encryption compatibility
// -------------------------------------------------------------

test(
  "serialization, deterministic/random encryption, and prefix compatibility",
  () => {
    for (const value of [
      "Dummy@example.invalid",
      42,
      false,
      new Date(
        "2020-01-01"
      ),
      {
        a: 1,
      },
      [
        "a",
      ],
      null,
      undefined,
    ]) {
      const encrypted =
        security.encryptField(
          value,
          context
        );

      assert.deepEqual(
        security.decryptField(
          encrypted,
          context
        ),
        value
      );
    }

    const deterministicOptions = {
      ...context,

      deterministic:
        true,
    };

    assert.equal(
      security.encryptField(
        "dummy",
        deterministicOptions
      ),
      security.encryptField(
        "dummy",
        deterministicOptions
      )
    );

    assert.notEqual(
      security.encryptField(
        "dummy",
        context
      ),
      security.encryptField(
        "dummy",
        context
      )
    );

    assert.equal(
      security.isEncrypted(
        "enc:v1:malformed"
      ),
      true
    );

    assert.equal(
      security.isEncrypted(
        "plaintext"
      ),
      false
    );

    assert.equal(
      security.encryptField(
        "enc:v1:malformed",
        context
      ),
      "enc:v1:malformed"
    );
  }
);

// -------------------------------------------------------------
// Key / normalization behavior
// -------------------------------------------------------------

test(
  "normalization, missing/wrong keys and independent configurations",
  () => {
    assert.equal(
      security.blindIndex(
        " User@Example.invalid ",
        context
      ),
      security.blindIndex(
        "user@example.invalid",
        context
      )
    );

    const other =
      createFieldEncryption({
        ...config,

        masterEncryptionKey:
          "33".repeat(32),

        masterHmacKey:
          "44".repeat(32),
      });

    assert.throws(() =>
      other.decryptField(
        security.encryptField(
          "dummy",
          context
        ),
        context
      )
    );

    assert.notEqual(
      other.blindIndex(
        "dummy",
        context
      ),
      security.blindIndex(
        "dummy",
        context
      )
    );

    assert.throws(() =>
      createFieldEncryption()
        .blindIndex(
          "dummy",
          context
        )
    );
  }
);

// -------------------------------------------------------------
// User schema password protection
// -------------------------------------------------------------

test(
  "User password remains String, select:false, and excluded from field encryption",
  async () => {
    const connection =
      mongoose.createConnection();

    const model =
      createUserModel(
        config,
        connection
      );

    const passwordPath =
      model.schema.path(
        "password"
      );

    // Password must remain a normal String.
    assert.equal(
      passwordPath.instance,
      "String"
    );

    // Password must be excluded from ordinary queries.
    assert.equal(
      passwordPath.options.select,
      false
    );

    const doc =
      new model({
        userId:
          "fixture",

        userCode:
          "USR-CODE-001",

        fullName:
          "Test Employee",

        firstName:
          "Test",

        middleName:
          null,

        lastName:
          "Employee",

        email:
          "Dummy@example.invalid",

        phoneNo:
          "9000000001",

        password:
          "$argon2id$dummy-only",

        roleCode: [
          "ROLE-002",
        ],

        activeRoleCode:
          "ROLE-002",

        orgCode:
          "ORG-001",

        userType:
          "employee",

        isActive:
          true,
      });

    await model.schema.s.hooks.execPre(
      "save",
      doc,
      []
    );

    // ---------------------------------------------------------
    // Encrypted fields
    // ---------------------------------------------------------

    assert.ok(
      security.isEncrypted(
        doc.email
      )
    );

    assert.ok(
      security.isEncrypted(
        doc.phoneNo
      )
    );

    assert.ok(
      security.isEncrypted(
        doc.fullName
      )
    );

    assert.ok(
      security.isEncrypted(
        doc.firstName
      )
    );

    assert.ok(
      security.isEncrypted(
        doc.lastName
      )
    );

    // ---------------------------------------------------------
    // Password protection
    //
    // Password MUST NOT be encrypted by the field-encryption
    // plugin. It remains an Argon2 hash.
    // ---------------------------------------------------------

    assert.equal(
      doc.password,
      "$argon2id$dummy-only"
    );

    assert.equal(
      security.isEncrypted(
        doc.password
      ),
      false
    );

    // ---------------------------------------------------------
    // Current role contract
    // ---------------------------------------------------------

    assert.deepEqual(
      doc.roleCode,
      [
        "ROLE-002",
      ]
    );

    assert.equal(
      doc.activeRoleCode,
      "ROLE-002"
    );

    // ---------------------------------------------------------
    // Plaintext structural fields
    // ---------------------------------------------------------

    assert.equal(
      doc.userId,
      "fixture"
    );

    assert.equal(
      doc.userCode,
      "USR-CODE-001"
    );

    assert.equal(
      doc.orgCode,
      "ORG-001"
    );

    // isActive is no longer part of the configured
    // field-encryption lists.
    assert.equal(
      doc.isActive,
      true
    );

    assert.equal(
      security.isEncrypted(
        doc.isActive
      ),
      false
    );

    // ---------------------------------------------------------
    // Hydration / post-init decryption
    // ---------------------------------------------------------

    const raw =
      doc.toObject();

    const hydrated =
      model.hydrate(raw);

    assert.equal(
      hydrated.password,
      "$argon2id$dummy-only"
    );

    assert.deepEqual(
      hydrated.roleCode,
      [
        "ROLE-002",
      ]
    );

    assert.equal(
      hydrated.activeRoleCode,
      "ROLE-002"
    );

    assert.equal(
      hydrated.fullName,
      "Test Employee"
    );

    assert.equal(
      hydrated.firstName,
      "Test"
    );

    assert.equal(
      hydrated.lastName,
      "Employee"
    );

    assert.equal(
      hydrated.email,
      "Dummy@example.invalid"
    );

    assert.equal(
      hydrated.phoneNo,
      "9000000001"
    );

    assert.equal(
      hydrated.orgCode,
      "ORG-001"
    );

    assert.equal(
      hydrated.isActive,
      true
    );

    // ---------------------------------------------------------
    // Lean query decryption
    // ---------------------------------------------------------

    const lean = {
      ...raw,
    };

    await model.schema.s.hooks.execPost(
      "findOne",
      {},
      [
        lean,
      ]
    );

    assert.equal(
      lean.fullName,
      "Test Employee"
    );

    assert.equal(
      lean.firstName,
      "Test"
    );

    assert.equal(
      lean.lastName,
      "Employee"
    );

    assert.equal(
      lean.email,
      "Dummy@example.invalid"
    );

    assert.equal(
      lean.phoneNo,
      "9000000001"
    );

    assert.equal(
      lean.password,
      "$argon2id$dummy-only"
    );

    assert.equal(
      lean.isActive,
      true
    );

    // ---------------------------------------------------------
    // Master collection safety
    // ---------------------------------------------------------

    assert.equal(
      model.schema.options
        .autoCreate,
      false
    );

    assert.equal(
      model.schema.options
        .autoIndex,
      false
    );

    await connection.close();
  }
);

// -------------------------------------------------------------
// Encrypted email repository lookup
// -------------------------------------------------------------

test(
  "User repository searches email using blind index without database writes",
  async () => {
    const expectedIndex =
      security.blindIndex(
        "dummy@example.invalid",
        context
      );

    const repoConnection = {
      model(
        name,
        schema,
        collection,
        options
      ) {
        assert.equal(
          collection,
          "users"
        );

        assert.equal(
          options.cache,
          false
        );

        return {
          findOne(filter) {
            assert.deepEqual(
              filter,
              {
                "__search.email":
                  expectedIndex,
              }
            );

            return {
              lean() {
                return {
                  exec:
                    async () =>
                      null,
                };
              },
            };
          },
        };
      },
    };

    const repository =
      createUserRepository(
        config,
        repoConnection
      );

    const result =
      await repository
        .findByEncryptedEmail(
          " DUMMY@example.invalid "
        );

    assert.equal(
      result,
      null
    );
  }
);