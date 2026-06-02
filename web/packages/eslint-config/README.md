# `@xalgorix/eslint-config`

Shared ESLint and Prettier configuration for every TypeScript package and Next.js 14 app in the
Xalgorix SaaS monorepo.

## Usage

`.eslintrc.cjs` in a Next.js app:

```js
module.exports = {
  root: true,
  extends: ["@xalgorix/eslint-config/next"],
  parserOptions: {
    project: "./tsconfig.json",
    tsconfigRootDir: __dirname,
  },
};
```

`.eslintrc.cjs` in a non-React library:

```js
module.exports = {
  root: true,
  extends: ["@xalgorix/eslint-config/library"],
  parserOptions: {
    project: "./tsconfig.json",
    tsconfigRootDir: __dirname,
  },
};
```

`prettier.config.cjs`:

```js
module.exports = require("@xalgorix/eslint-config/prettier");
```

## Scope

- TypeScript strictness baseline (no implicit `any`, no floating promises).
- Import ordering with `@xalgorix/*` resolved as internal.
- Accessibility (`jsx-a11y/recommended`) enabled for Requirement 18.
- Prettier integration so formatting and linting do not conflict.

The accessibility, performance, and bundle-size thresholds enforced in CI live in
`web/lighthouserc.json` and `web/.axe-ci.json` and are wired up in Phase 18.
