/**
 * Base ESLint configuration shared by every TypeScript package and app in the
 * Xalgorix SaaS web monorepo.
 *
 * Extending configurations:
 *   - `@xalgorix/eslint-config`        -> this base (libraries, generic TS).
 *   - `@xalgorix/eslint-config/next`   -> Next.js apps (web/marketing, web/app, web/admin).
 *   - `@xalgorix/eslint-config/library` -> non-React TS libraries (e.g. api-client).
 *
 * Implements parts of Requirements 18.1 (a11y), 19.1/19.2 (perf gating via lint
 * hygiene) and the cross-app TypeScript-strict mandate from task 0.4.
 */
module.exports = {
  root: false,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
    ecmaFeatures: { jsx: true },
  },
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  plugins: ["@typescript-eslint", "import", "jsx-a11y"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:@typescript-eslint/recommended-requiring-type-checking",
    "plugin:import/recommended",
    "plugin:import/typescript",
    "plugin:jsx-a11y/recommended",
    "turbo",
    "prettier",
  ],
  settings: {
    "import/resolver": {
      typescript: { alwaysTryTypes: true },
      node: { extensions: [".js", ".jsx", ".ts", ".tsx"] },
    },
  },
  rules: {
    // TypeScript hygiene — strict configs treat unknowns as errors.
    "@typescript-eslint/consistent-type-imports": [
      "error",
      { prefer: "type-imports", fixStyle: "inline-type-imports" },
    ],
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-floating-promises": "error",
    "@typescript-eslint/no-misused-promises": "error",
    "@typescript-eslint/require-await": "error",
    "@typescript-eslint/await-thenable": "error",

    // Import ordering keeps generated clients and shared packages predictable.
    "import/order": [
      "error",
      {
        groups: ["builtin", "external", "internal", "parent", "sibling", "index", "type"],
        pathGroups: [
          { pattern: "@xalgorix/**", group: "internal", position: "before" },
        ],
        "newlines-between": "always",
        alphabetize: { order: "asc", caseInsensitive: true },
      },
    ],
    "import/no-default-export": "off",

    // a11y — Requirement 18.
    "jsx-a11y/anchor-is-valid": "warn",
    "jsx-a11y/no-autofocus": "warn",
  },
  ignorePatterns: [
    "node_modules/",
    "dist/",
    ".next/",
    "out/",
    "coverage/",
    "build/",
    "*.config.js",
    "*.config.cjs",
  ],
  overrides: [
    {
      files: ["*.test.ts", "*.test.tsx", "**/__tests__/**/*"],
      rules: {
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/no-non-null-assertion": "off",
      },
    },
  ],
};
