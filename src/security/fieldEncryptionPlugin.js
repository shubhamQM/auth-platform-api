import mongoose from "mongoose";

import {
  createFieldEncryption,
} from "./fieldEncryption.js";

export function createFieldEncryptionPlugin(
  config = {},
) {
  const {
    encryptField,
    decryptField,
    blindIndex,
    buildSearchTokens,
    isEncrypted,
  } = createFieldEncryption(
    config,
  );

  // -------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------

  function walkPath(
    root,
    path,
    visit,
  ) {
    const parts =
      path.split(".");

    function walk(
      node,
      index,
    ) {
      if (
        node === null ||
        node === undefined
      ) {
        return;
      }

      if (
        index ===
        parts.length - 1
      ) {
        if (
          Array.isArray(node)
        ) {
          return;
        }

        visit(
          node,
          parts[index],
        );

        return;
      }

      const child =
        node[parts[index]];

      if (
        Array.isArray(child)
      ) {
        child.forEach(
          (item) =>
            walk(
              item,
              index + 1,
            ),
        );
      } else {
        walk(
          child,
          index + 1,
        );
      }
    }

    walk(
      root,
      0,
    );
  }

  // -------------------------------------------------------------
  // Encryption plugin
  // -------------------------------------------------------------

  function fieldEncryptionPlugin(
    schema,
    options = {},
  ) {
    const {
      dbName,
      collectionName,

      // Random ciphertext fields.
      random = [],

      // Deterministic ciphertext fields.
      deterministic = [],

      // Exact-search fields.
      //
      // Searchable fields are encrypted and receive
      // a blind-index value in __search.
      searchable = [],

      // Partial / substring searchable fields.
      //
      // This controls search-token generation only.
      // If the field must also be encrypted, it must
      // additionally appear in random or deterministic.
      searchablePartial = [],
    } = options;

    // -----------------------------------------------------------
    // Explicit encryption fields only
    //
    // IMPORTANT:
    //
    // Do NOT automatically encrypt every schema field.
    //
    // Structural/master fields such as:
    //
    // - userId
    // - userCode
    // - roleCode
    // - activeRoleCode
    // - orgCode
    // - userType
    // - isActive
    //
    // must remain plaintext unless the model explicitly
    // opts them into encryption.
    //
    // Password is also explicitly excluded because it contains
    // an Argon2id hash and is protected separately.
    // -----------------------------------------------------------

    const all = [
      ...new Set([
        ...random,
        ...deterministic,
        ...searchable,
      ]),
    ].filter(
      (path) =>
        path !== "password",
    );

    const deterministicSet =
      new Set(
        deterministic,
      );

    // -----------------------------------------------------------
    // Search fields
    // -----------------------------------------------------------

    if (
      searchable.length
    ) {
      schema.add({
        __search: {
          type:
            Map,

          of:
            String,

          select:
            false,
        },
      });
    }

    if (
      searchablePartial.length
    ) {
      schema.add({
        __searchTokens: {
          type: [
            String,
          ],

          select:
            false,

          index:
            true,

          default: [],
        },
      });
    }

    // -----------------------------------------------------------
    // Convert encrypted paths to Mixed
    //
    // Only explicitly encrypted fields are converted.
    // Structural fields retain their original Mongoose types.
    // -----------------------------------------------------------

    all.forEach(
      (path) => {
        const schemaType =
          schema.path(
            path,
          );

        if (
          !schemaType
        ) {
          return;
        }

        const optionsCopy = {
          type:
            mongoose
              .Schema
              .Types
              .Mixed,
        };

        for (
          const key of [
            "required",
            "default",
            "unique",
            "index",
            "sparse",
            "select",
          ]
        ) {
          if (
            Object.prototype
              .hasOwnProperty.call(
                schemaType.options,
                key,
              )
          ) {
            optionsCopy[key] =
              schemaType
                .options[key];
          }
        }

        schema.path(
          path,
          optionsCopy,
        );
      },
    );

    // -----------------------------------------------------------
    // Encrypt document
    // -----------------------------------------------------------

    function encryptDoc(
      doc,
    ) {
      // ---------------------------------------------------------
      // Exact blind indexes
      // ---------------------------------------------------------

      if (
        searchable.length
      ) {
        const search = {};

        searchable.forEach(
          (path) => {
            walkPath(
              doc,
              path,
              (
                container,
                key,
              ) => {
                const value =
                  container[key];

                if (
                  value !==
                    undefined &&
                  value !==
                    null &&
                  !isEncrypted(
                    value,
                  )
                ) {
                  search[path] =
                    blindIndex(
                      value,
                      {
                        dbName,
                        collectionName,
                        fieldName:
                          path,
                      },
                    );
                }
              },
            );
          },
        );

        doc.__search = {
          ...(
            doc.__search ||
            {}
          ),

          ...search,
        };
      }

      // ---------------------------------------------------------
      // Partial / substring search tokens
      // ---------------------------------------------------------

      if (
        searchablePartial.length
      ) {
        const tokens =
          new Set();

        searchablePartial
          .forEach(
            (path) => {
              walkPath(
                doc,
                path,
                (
                  container,
                  key,
                ) => {
                  const value =
                    container[key];

                  if (
                    value ===
                      undefined ||
                    value ===
                      null
                  ) {
                    return;
                  }

                  /*
                   * Tokens must be generated before
                   * the configured field is encrypted.
                   */
                  if (
                    isEncrypted(
                      value,
                    )
                  ) {
                    return;
                  }

                  const fieldTokens =
                    buildSearchTokens(
                      value,
                      {
                        dbName,
                        collectionName,
                      },
                    );

                  fieldTokens
                    .forEach(
                      (
                        token,
                      ) =>
                        tokens
                          .add(
                            token,
                          ),
                    );
                },
              );
            },
          );

        /*
         * Rebuild instead of merging.
         *
         * This prevents stale tokens after a
         * searchable field changes.
         */
        doc.__searchTokens = [
          ...tokens,
        ];
      }

      // ---------------------------------------------------------
      // Encrypt explicitly configured fields
      // ---------------------------------------------------------

      all.forEach(
        (path) => {
          walkPath(
            doc,
            path,
            (
              container,
              key,
            ) => {
              const value =
                container[key];

              if (
                value !==
                  undefined &&
                value !==
                  null &&
                !isEncrypted(
                  value,
                )
              ) {
                container[key] =
                  encryptField(
                    value,
                    {
                      dbName,
                      collectionName,

                      fieldName:
                        path,

                      deterministic:
                        deterministicSet
                          .has(
                            path,
                          ),
                    },
                  );
              }
            },
          );
        },
      );
    }

    // -----------------------------------------------------------
    // Decrypt document
    // -----------------------------------------------------------

    function decryptDoc(
      doc,
    ) {
      if (!doc) {
        return;
      }

      all.forEach(
        (path) => {
          walkPath(
            doc,
            path,
            (
              container,
              key,
            ) => {
              if (
                isEncrypted(
                  container[key],
                )
              ) {
                container[key] =
                  decryptField(
                    container[key],
                    {
                      dbName,
                      collectionName,

                      fieldName:
                        path,
                    },
                  );
              }
            },
          );
        },
      );
    }

    // -----------------------------------------------------------
    // Encryption hooks
    // -----------------------------------------------------------

    schema.pre(
      "save",
      function encryptBeforeSave() {
        encryptDoc(
          this,
        );
      },
    );

    schema.pre(
      "insertMany",
      {
        model:
          true,

        document:
          false,

        query:
          false,
      },

      function encryptBeforeInsertMany(
        docs,
      ) {
        docs.forEach(
          encryptDoc,
        );
      },
    );

    // -----------------------------------------------------------
    // Decryption hooks
    // -----------------------------------------------------------

    schema.post(
      "save",
      decryptDoc,
    );

    schema.post(
      "init",
      decryptDoc,
    );

    schema.post(
      "insertMany",
      {
        model:
          true,

        document:
          false,

        query:
          false,
      },

      (docs) =>
        docs.forEach(
          decryptDoc,
        ),
    );

    schema.post(
      [
        "find",
        "findOne",
        "findOneAndUpdate",
      ],

      (result) => {
        if (!result) {
          return;
        }

        (
          Array.isArray(
            result,
          )
            ? result
            : [
                result,
              ]
        ).forEach(
          decryptDoc,
        );
      },
    );
  }

  return fieldEncryptionPlugin;
}