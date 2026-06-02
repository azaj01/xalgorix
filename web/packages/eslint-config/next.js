/**
 * ESLint configuration for the three Next.js 14 apps:
 *   web/marketing, web/app, web/admin.
 *
 * Layered on top of the base config so React, Next, and a11y rules apply
 * uniformly. Per task 0.4 in tasks.md.
 */
module.exports = {
  extends: [
    require.resolve("./index.js"),
    "next/core-web-vitals",
    "plugin:react/recommended",
    "plugin:react/jsx-runtime",
    "plugin:react-hooks/recommended",
    "prettier",
  ],
  settings: {
    react: { version: "detect" },
  },
  rules: {
    "react/prop-types": "off",
    "react/react-in-jsx-scope": "off",
    "react-hooks/rules-of-hooks": "error",
    "react-hooks/exhaustive-deps": "warn",
    // Next pages and app routes need default exports.
    "import/no-default-export": "off",
  },
};
