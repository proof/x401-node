# @proof.com/x401-node - AI Assistant Guide

ESM TypeScript library implementing the x401 protocol (https://x401.proof.com/spec):
the PROOF-REQUIRED / PROOF-PRESENTATION / PROOF-RESPONSE wire format, the Verifier Challenge,
the VP Artifact, the x401 Token / Error objects, and the OAuth Token Exchange profile.

Two consumer roles, exported as namespaces:

- `agent.*` — decode PROOF-REQUIRED (header or embedded `<data>`), package a wallet result as a VP
  Artifact, encode PROOF-PRESENTATION, build a token-exchange request, decode PROOF-RESPONSE errors.
- `verifier.*` — create/verify the Verifier Challenge, build/encode the payload, emit the embedded
  `<data>` mirror, decode incoming VP Artifacts / Token Objects, parse token-exchange requests,
  encode error objects.

Plus `createEncryptor` (AES-GCM verifier-protected nonce state).

## Hard Rules

1. **Minimize runtime dependencies.** The only permitted runtime dependency is
   `@owf/identity-common` (encoding helpers), which proof-vc-common also uses. Otherwise rely on the
   WebCrypto-era globals. Do not add credential, crypto, or HTTP-framework dependencies.
2. **Never verify credentials here.** `vp_token` is opaque. SD-JWT-VC verification, issuer trust,
   and claim checks belong to the credential library (`@proof.com/proof-vc-common`). Do not add
   `@sd-jwt/*`, `jose`, X.509, or DCQL evaluation logic.
3. **Building the OpenID4VP request / wallet transport stays out.** That is the Agent's job.
4. **Prompt before publishing.** Never bump version, push tags, create a Release, or trigger the
   publish workflow without explicit confirmation. Publishes are permanent.
5. **Run `yarn check-all` and `yarn test` before any commit or push.**
6. **Keep `yarn publint` on `--pack npm`.**
7. **Don't lower `engines.node` below `>=22.0.0`.**
8. **Never use `eslint-disable`, `@ts-ignore`, or `@ts-expect-error` as a workaround.** Fix the
   underlying code or surface the rule to the user for a config decision.

## TypeScript Conventions

- `verbatimModuleSyntax: true` — use `import type` / `export type`.
- `noUncheckedIndexedAccess: true` — indexing returns `T | undefined`; use `!` only when access is
  provably safe (e.g. after a length check).
- `exactOptionalPropertyTypes: true` — set optional fields with conditional spread:
  `...(value !== undefined && { value })`.
- Local imports use the `.ts` extension (`rewriteRelativeImportExtensions` rewrites to `.js`).
- Wire-level types use snake_case to match the JSON wire format (`token_endpoint`, `vp_token`).

## Essential Commands

| Command          | Purpose                                            |
| ---------------- | -------------------------------------------------- |
| `yarn check-all` | Full check: format, lint, typecheck, test, publint |
| `yarn build`     | `tsc` emit to `dist/`                              |
| `yarn test`      | `node --test tests/*.test.ts`                      |
| `yarn typecheck` | `tsc --noEmit`                                     |
| `yarn lint`      | `eslint --fix`                                     |
| `yarn format`    | `prettier --write`                                 |
| `yarn publint`   | `publint --pack npm` (keep the flag)               |

## Source Map

- `src/constants.ts` — scheme/version, header names, schema URL, token-exchange URNs.
- `src/types.ts` — wire-format types (no runtime code).
- `src/encoding.ts` — base64url JSON helpers over `@owf/identity-common`; proof-header comma guard.
- `src/validate.ts` — structural validators / type guards (`X401ValidationError`).
- `src/encryptor.ts` — `createEncryptor` (AES-GCM + HKDF verifier-protected nonce state; `encrypt`/`decrypt`).
- `src/challenge.ts` — Verifier Challenge construct/verify (binds verifier id, route, method, expiry).
- `src/agent.ts` — agent-side primitives.
- `src/verifier.ts` — verifier-side primitives (re-exports challenge functions).
- `src/index.ts` — public barrel (explicit named exports; `agent`/`verifier` namespaces).

## Publishing

Prompt before publishing (Hard Rule 2).

- **Auth**: npm Trusted Publishing via OIDC (no `NPM_TOKEN`).
- **Trigger**: GitHub Release published → `.github/workflows/publish.yml`.
- **Registry**: https://www.npmjs.com/package/@proof.com/x401-node

### Release flow (after user confirms)

`main` is branch-protected: direct pushes are rejected. Bump on a branch, merge the PR, then create the Release against the exact merged commit SHA.

1. Bump on a branch (no auto-tag from npm — the tag is created by `gh release create` in step 4):
   ```bash
   git switch -c release-X.Y.Z origin/main
   npm version patch --no-git-tag-version          # or minor / major; writes package.json only
   git commit -am "Release X.Y.Z"
   git push -u origin release-X.Y.Z
   ```
2. Open a PR. Approve and merge in the GitHub UI.
3. Locate the merged commit SHA on `main` by grepping for the release commit subject:
   ```bash
   git fetch origin main
   SHA=$(git log origin/main --grep='Release X.Y.Z' --format=%H -n 1)
   echo "$SHA"   # sanity-check before using
   ```
   Expect exactly one match. If zero matches, the PR isn't merged yet. If multiple, narrow the grep further.
4. Create the Release against that SHA — `gh release create` creates the tag automatically when it doesn't exist:
   ```bash
   gh release create vX.Y.Z --target "$SHA" --generate-notes
   ```

The Release triggers `publish.yml`: check suite → tag must match `package.json` → `npm publish --provenance --access public`.

Never `git push --follow-tags` to `main`: the commit is rejected but the tag still pushes, stranding it on an unmerged commit. Delete a stray tag with `git push --delete origin vX.Y.Z`.

## Notes

- `yarn.lock` is the only lockfile (no `package-lock.json`).
- Scope is `@proof.com` (with the dot), not `@proof`.
