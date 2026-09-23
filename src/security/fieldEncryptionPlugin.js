import mongoose from 'mongoose';
import { createFieldEncryption } from './fieldEncryption.js';

export function createFieldEncryptionPlugin(config = {}) {

  const {
    encryptField,
    decryptField,
    blindIndex,
    buildSearchTokens,
    isEncrypted,
  } = createFieldEncryption(config);

  // -------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------

  function walkPath(root, path, visit) {
    const parts = path.split(".");

    function walk(node, index) {
      if (node === null || node === undefined) {
        return;
      }

      if (index === parts.length - 1) {
        if (Array.isArray(node)) {
          return;
        }

        visit(node, parts[index]);
        return;
      }

      const child = node[parts[index]];

      if (Array.isArray(child)) {
        child.forEach((item) =>
          walk(item, index + 1),
        );
      } else {
        walk(child, index + 1);
      }
    }

    walk(root, 0);
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

      // Existing exact searchable fields
      random = [],
      deterministic = [],
      searchable = [],

      // Partial / substring searchable fields
      searchablePartial = [],
    } = options;

    // -----------------------------------------------------------
    // Automatically encrypted fields
    // -----------------------------------------------------------

    const automaticRandom = Object.keys(
      schema.paths,
    ).filter((path) => {
      const schemaType = schema.path(path);

      const lastPart = path
        .split(".")
        .at(-1);

      return (
        path !== "_id" &&
        path !== "__v" &&
        path !== "createdAt" &&
        path !== "updatedAt" &&
        path !== "__search" &&
        path !== "__searchTokens" &&

        // Passwords are one-way hashed separately.
        // They must never be encrypted by this plugin.
        path !== "password" &&

        !/Id(s)?$/i.test(lastPart) &&
        schemaType.instance !== "Boolean"
      );
    });

    const all = [
      ...new Set([
        ...automaticRandom,
        ...random,
        ...deterministic,
        ...searchable,
      ]),
    ].filter((path) => path !== "password");

    const deterministicSet =
      new Set(deterministic);

    // -----------------------------------------------------------
    // Search fields
    // -----------------------------------------------------------

    if (searchable.length) {
      schema.add({
        __search: {
          type: Map,
          of: String,
          select: false,
        },
      });
    }

    if (searchablePartial.length) {
      schema.add({
        __searchTokens: {
          type: [String],
          select: false,
          index: true,
          default: [],
        },
      });
    }

    // -----------------------------------------------------------
    // Convert encrypted paths to Mixed
    // -----------------------------------------------------------

    all.forEach((path) => {
      const schemaType = schema.path(path);

      if (!schemaType) {
        return;
      }

      const optionsCopy = {
        type: mongoose.Schema.Types.Mixed,
      };

      for (const key of [
        "required",
        "default",
        "unique",
        "index",
        "sparse",
        "select",
      ]) {
        if (
          Object.prototype.hasOwnProperty.call(
            schemaType.options,
            key,
          )
        ) {
          optionsCopy[key] =
            schemaType.options[key];
        }
      }

      schema.path(
        path,
        optionsCopy,
      );
    });

    // -----------------------------------------------------------
    // Encrypt document
    // -----------------------------------------------------------

    function encryptDoc(doc) {
      // ---------------------------------------------------------
      // Existing exact blind indexes
      // ---------------------------------------------------------

      if (searchable.length) {
        const search = {};

        searchable.forEach((path) => {
          walkPath(
            doc,
            path,
            (container, key) => {
              const value =
                container[key];

              if (
                value !== undefined &&
                value !== null &&
                !isEncrypted(value)
              ) {
                search[path] =
                  blindIndex(value, {
                    dbName,
                    collectionName,
                    fieldName: path,
                  });
              }
            },
          );
        });

        doc.__search = {
          ...(doc.__search || {}),
          ...search,
        };
      }

      // ---------------------------------------------------------
      // Partial / substring search tokens
      // ---------------------------------------------------------

      if (searchablePartial.length) {
        const tokens = new Set();

        searchablePartial.forEach(
          (path) => {
            walkPath(
              doc,
              path,
              (container, key) => {
                const value =
                  container[key];

                if (
                  value === undefined ||
                  value === null
                ) {
                  return;
                }

                /*
                 * searchablePartial fields may also
                 * be encrypted by the plugin.
                 *
                 * Therefore tokens must be generated
                 * BEFORE encryption happens.
                 */
                if (isEncrypted(value)) {
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

                fieldTokens.forEach(
                  (token) =>
                    tokens.add(token),
                );
              },
            );
          },
        );

        /*
         * Rebuild instead of merging with the
         * existing array.
         *
         * This prevents stale search tokens when
         * a searchable field is updated.
         */
        doc.__searchTokens = [
          ...tokens,
        ];
      }

      // ---------------------------------------------------------
      // Encrypt normal fields
      // ---------------------------------------------------------

      all.forEach((path) => {
        walkPath(
          doc,
          path,
          (container, key) => {
            const value =
              container[key];

            if (
              value !== undefined &&
              value !== null &&
              !isEncrypted(value)
            ) {
              container[key] =
                encryptField(value, {
                  dbName,
                  collectionName,
                  fieldName: path,
                  deterministic:
                    deterministicSet.has(
                      path,
                    ),
                });
            }
          },
        );
      });
    }

    // -----------------------------------------------------------
    // Decrypt document
    // -----------------------------------------------------------

    function decryptDoc(doc) {
      if (!doc) {
        return;
      }

      all.forEach((path) => {
        walkPath(
          doc,
          path,
          (container, key) => {
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
                    fieldName: path,
                  },
                );
            }
          },
        );
      });
    }

    // -----------------------------------------------------------
    // Mongoose hooks
    // -----------------------------------------------------------

    schema.pre(
      "save",
      function encryptBeforeSave() {
        encryptDoc(this);
      },
    );

    schema.pre(
      "insertMany",
      {
        model: true,
        document: false,
        query: false,
      },
      function encryptBeforeInsertMany(
        docs,
      ) {
        docs.forEach(encryptDoc);
      },
    );

    // -----------------------------------------------------------
    // Decryption hooks
    // -----------------------------------------------------------

    schema.post("save", decryptDoc);

    schema.post(
      "init",
      decryptDoc,
    );

    schema.post(
      "insertMany",
      {
        model: true,
        document: false,
        query: false,
      },
      (docs) =>
        docs.forEach(decryptDoc),
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
          Array.isArray(result)
            ? result
            : [result]
        ).forEach(decryptDoc);
      },
    );
  }

  return fieldEncryptionPlugin;
}