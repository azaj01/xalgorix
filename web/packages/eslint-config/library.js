/**
 * ESLint configuration for non-React TypeScript packages
 * (e.g. web/packages/api-client, web/packages/i18n).
 *
 * Disables React/Next-only rules and forbids default exports so generated
 * libraries expose a stable named-export surface.
 */
module.exports = {
  extends: [require.resolve("./index.js")],
  rules: {
    "import/no-default-export": "error",
  },
};
