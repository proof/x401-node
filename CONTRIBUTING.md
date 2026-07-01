# Contributing

## Requirements

- `node` >= 22.0.0 (published floor, `engines.node`). Develop on Node 24 (active LTS), pinned in [.node-version](.node-version).
- `yarn` 4 - run `corepack enable`; the version is pinned via `packageManager` in `package.json`.

## Design Principles

`@proof.com/x401-node` implements the x401 protocol wire format and processing rules
(https://x401.proof.com/spec) and nothing else:

- **Minimal runtime dependencies.** Only `@owf/identity-common` (encoding helpers) plus the
  WebCrypto-era globals (`crypto.subtle`, `TextEncoder`/`TextDecoder`) are used.
- **Credential-format agnostic.** The wallet `vp_token` is treated as opaque. Verifying it
  (SD-JWT-VC, issuer trust, disclosed claims) is the job of a credential library such as
  `@proof.com/proof-vc-common`, not this package.
- **No wallet transport.** Building the OpenID4VP Authorization Request and talking to a wallet is
  the Agent's responsibility and is intentionally out of scope.

## Commands

- `yarn build`
- `yarn format`
- `yarn lint`
- `yarn typecheck`
- `yarn test`
- `yarn publint`

## Pull Requests

To submit a pull request:

- Start by forking the repo and branching off of `main`.
- Include a clear title and description explaining what changed and why.
- Keep changes focused, try to limit one issue or feature per PR.

CI runs `test` on a matrix of Node 22 (the `engines.node` floor) and Node 24 (active LTS). The other jobs run on Node 24 from `.node-version`.

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this standard.
