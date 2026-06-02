# Xalgorix SaaS — Web Monorepo

This directory hosts the three Next.js 14 frontends for the Cloud_Platform and the shared packages they consume. It implements the layout described in `.kiro/specs/xalgorix-saas/design.md` § "Marketing Site & Dashboard Frontend".

## Layout

```
web/
├── marketing/           # xalgorix.com           (Next.js 14, SSG + ISR)   — Requirement 2
├── app/                 # app.xalgorix.com       (Next.js 14, RSC + WS)    — Requirement 6
├── admin/               # admin.xalgorix.com     (Next.js 14, MFA-gated)   — Requirement 11
└── packages/
    ├── ui/              # shadcn/ui registry + Tailwind preset + Framer Motion primitives
    ├── api-client/      # generated TypeScript client for /api/v1/openapi.json
    ├── i18n/            # next-intl message catalogs + missing-key logger
    └── tsconfig/        # shared TS configs (base, nextjs, react-library)
```

## Tooling

- **Workspaces**: pnpm (see `../pnpm-workspace.yaml`)
- **Pipeline**: Turbo (see `../turbo.json`) with `build`, `lint`, `test`, `typecheck`
- **Tailwind preset**: `@xalgorix/ui/tailwind-preset`, applied by every app's `tailwind.config.ts`
- **shadcn registry**: `@xalgorix/ui/registry` (file: `packages/ui/registry.json`)

## Common scripts

Run from the repository root:

```bash
pnpm install
pnpm build       # turbo run build
pnpm lint        # turbo run lint
pnpm typecheck   # turbo run typecheck
pnpm test        # turbo run test
pnpm dev         # turbo run dev --parallel
```

ESLint/Prettier/strict-TypeScript shared configs and Playwright/Lighthouse/axe wiring land in spec task 0.4.
