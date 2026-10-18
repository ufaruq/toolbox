# Implementation status

This separate implementation PR follows [design PR #1](https://github.com/ufaruq/toolbox/pull/1) at commit `0851595a4238359b25e8426b45878f6e5fb5a0ee`. The design has not been merged or modified by this implementation.

## Increment 1: identity and authorization primitives

- Separate agent credential format with 256-bit random secrets and keyed hashes.
- Five-minute Ed25519 delegation JWTs with fixed issuer, audience, algorithm, token type, agent, owner, grant, resource and output constraints.
- Strict JSON parsing rejects duplicate keys, unknown arguments, case aliases and trailing data.
- Shared non-secret domain model and transactional repository contract.

Checked locally: focused security and strict JSON tests pass with official checksum-verified Go 1.27.2. Integration, provider, browser and production validation are not claimed at this checkpoint.

## Release gates

Production human OIDC provider/hosting remain unselected. Real Google client/Picker configuration, positive and negative PKCE enforcement, restricted downloads and document fidelity require a separately authorized test project and account. Fixture tests are not live Google validation. No deployment, merge, live credential generation or OAuth application provisioning is included.
