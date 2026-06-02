# `@xalgorix/tsconfig`

Shared TypeScript configurations enforcing strict mode across the Xalgorix SaaS web monorepo.

## Variants

| File                  | Used by                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `base.json`           | Base strict settings (every package extends this directly or indirectly). |
| `next.json`           | Next.js 14 apps (`web/marketing`, `web/app`, `web/admin`).              |
| `nextjs.json`         | Alias of `next.json` retained for legacy apps.                          |
| `library.json`        | TypeScript libraries that emit declarations (`api-client`, `i18n`).     |
| `react-library.json`  | React component libraries (`ui`).                                       |

## Strictness baseline

`base.json` enables every TypeScript strictness flag that catches real bugs:

- `strict`, `noImplicitAny`, `noImplicitOverride`, `noImplicitReturns`
- `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`
- `noUnusedLocals`, `noUnusedParameters`, `noFallthroughCasesInSwitch`
- `useUnknownInCatchVariables`, `alwaysStrict`, `verbatimModuleSyntax`
- `forceConsistentCasingInFileNames`, `isolatedModules`

## Usage

`tsconfig.json` for a Next.js app:

```json
{
  "extends": "@xalgorix/tsconfig/next.json",
  "compilerOptions": {
    "baseUrl": "."
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"],
  "exclude": ["node_modules"]
}
```

`tsconfig.json` for a library:

```json
{
  "extends": "@xalgorix/tsconfig/library.json",
  "include": ["src/**/*"]
}
```
