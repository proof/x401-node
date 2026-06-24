# Upgrading this SDK to a new x401 spec revision

A repeatable loop: read the spec diff → re-pin spec-authored fixtures → see exactly which
normative statements changed → update the code → let the harness prove the code matches the
spec, not a paraphrase of it. Requires the GitHub CLI (`gh`) authenticated against `proof/x401`.

## The harness (what does the checking)

| Artifact                            | Role                                                                       |
| ----------------------------------- | -------------------------------------------------------------------------- |
| `spec/SPEC_SOURCE.json`             | Pins the exact spec repo + git ref the fixtures came from                  |
| `spec/spec.md`                      | Cached spec text at that ref (so normative checks run offline)             |
| `spec/fixtures/request.schema.json` | Appendix C JSON Schema, extracted verbatim                                 |
| `spec/fixtures/*.json`              | Every JSON example from the spec (payloads, VP artifacts, error/token)     |
| `spec/normative-ledger.json`        | Snapshot of every MUST/SHALL/REQUIRED statement at the ref                 |
| `spec/conformance.md`               | Human map: each in-scope requirement → code + test; out-of-scope rationale |
| `scripts/sync-spec-fixtures.ts`     | Fetches spec at a ref; rewrites `spec.md`, fixtures, `SPEC_SOURCE.json`    |
| `scripts/extract-normative.ts`      | Diffs spec vs ledger; lists ADDED/REMOVED statements to triage             |
| `tests/spec-schema.test.ts`         | Validates payloads (and `buildPayload` output) against Appendix C          |
| `tests/spec-fixtures.test.ts`       | Parses + round-trips every spec example fixture                            |
| `tests/x401.test.ts`                | Hand-written unit + negative cases for the current wire shapes             |

## Steps

1. **Read the diff in full** — do not summarize away details:

   ```sh
   gh pr diff <PR#> --repo proof/x401      # or: gh api repos/proof/x401/compare/<old>...<new>
   ```

2. **Re-pin the fixtures** to the new ref (PR head SHA, or the merged `main` SHA once merged):

   ```sh
   node scripts/sync-spec-fixtures.ts <git-ref>
   ```

   This rewrites `spec/spec.md`, `spec/fixtures/*`, and the `ref`/`fetched_at` in `SPEC_SOURCE.json`.
   Also update `branch`/`version` in `SPEC_SOURCE.json` by hand if they changed.

3. **See what changed normatively:**

   ```sh
   node scripts/extract-normative.ts        # prints ADDED / REMOVED vs the ledger
   ```

   Triage each ADDED statement in `spec/conformance.md` (enforce it + cite the test, or mark it
   out of scope with the responsible layer). Drop handling/tests for REMOVED statements. Then:

   ```sh
   node scripts/extract-normative.ts --update
   ```

4. **Update the code** in dependency order:
   `src/constants.ts` → `src/types.ts` → `src/validate.ts` → `src/agent.ts` / `src/verifier.ts`
   → `src/index.ts`. Keep wire fields snake_case; carry externally-signed/opaque blobs opaque.

5. **Run the harness:**

   ```sh
   yarn test
   ```

   `spec-schema` + `spec-fixtures` fail loudly if a field name, enum value, required/optional, or
   object shape drifts from the spec's own schema and examples.

6. **Adversarial review** — have an independent reviewer (subagent or person) read the spec diff
   against the changed `src/` files and try to _refute_ the implementation: wrong field names /
   enum values / `version`; VP Artifact one-of and by-reference semantics; and any straggler of a
   removed concept left behind in `src/`. Resolve every confirmed finding.

7. **Full gate:**

   ```sh
   yarn check-all      # format, lint, typecheck, test, publint
   ```

8. **Publishing** is separate and gated — see `CLAUDE.md` › Publishing. Do not bump the npm
   package version or release without explicit confirmation.

## Hard rules that constrain every upgrade

From `CLAUDE.md`: only runtime dep is `@owf/identity-common`; never verify credentials here; do
not build/sign the OpenID4VP request or wallet transport; no `eslint-disable`/`@ts-ignore`;
`engines.node >= 22`. Schema/test tooling (`ajv`, `ajv-formats`) is **devDependencies** only.
