module.exports = {
  root: true,
  extends: ["@xalgorix/eslint-config/library"],
  parserOptions: {
    project: "./tsconfig.json",
    tsconfigRootDir: __dirname,
  },
  rules: {
    "import/no-default-export": "off",
  },
};
