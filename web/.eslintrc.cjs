/**
 * Root ESLint config for the Xalgorix SaaS web monorepo.
 *
 * Each app and package overrides this with `root: true` and extends the
 * shared `@xalgorix/eslint-config` package (see web/packages/eslint-config).
 */
module.exports = {
  root: true,
  extends: ["@xalgorix/eslint-config"],
  ignorePatterns: [
    "node_modules/",
    "**/dist/**",
    "**/.next/**",
    "**/out/**",
    "**/coverage/**",
    "**/playwright-report/**",
    "**/test-results/**",
    "e2e/.auth/**",
  ],
};
