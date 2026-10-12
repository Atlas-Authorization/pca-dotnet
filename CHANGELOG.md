# Changelog

## 0.4.1

- Security (policy layer): caveats on the root grant outside the envelope are now evaluated like delegated caveats; new policy_caveats/evaluate_caveats helpers (incl. max_spend). The core verifier still does not evaluate caveats. .NET: `Caveats.PolicyCaveats(grant, chain)` (the grant's caveats minus its first `envelope` caveat, then the caveats the hops appended) and `Caveats.EvaluateCaveats(caveats, ctx)` -> `Caveats.Result(Ok, Failed)` (total; `expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc`, and the new `max_spend {usd}`; anything else fails closed). `Pca.VerifyPcactnCore` and the ASP.NET Core `PcaMiddleware` are unchanged and still treat caveats as opaque: a resource server enforcing a grant's caveats calls `Caveats.EvaluateCaveats(Caveats.PolicyCaveats(grant, chain), ctx)` with its own action params (snake_case context keys, as in the `primitives.caveat_eval` vectors). New `primitives.caveat_eval` vectors run in the Conformance runner and `R041Tests`.
- Wire: threshold-share signatures are validated per suite (`Pca.ValidateShareSignatureWire`): `alg` absent = ed25519 (64-byte `sig`, no `pq_sig`), `ml-dsa-65` (3309-byte `sig`, no `pq_sig`), `hybrid-ed25519-ml-dsa-65` (64-byte `sig` + 3309-byte `pq_sig`); a non-string (incl. null) or unknown `alg` is a wire refusal. Before, every share `sig` had to be 64 bytes, so a pure ML-DSA-65 share could not be carried. A share's `pq_pk` is still judged only by the threshold check. Reason text is now `threshold.shares[i]: 'sig' is not canonical base64url (N bytes) for alg '<alg>'`. The Conformance runner and `CorpusTests` skip a vector whose `requires` names a registered suite this verifier does not implement.
- Middleware: the `PCA-Action` header is decoded STRICTLY (`Pca.DecodePcaHeader`, null when invalid): unpadded base64url only (no padding, standard alphabet or whitespace; nothing is trimmed) and well-formed UTF-8. Invalid UTF-8 (overlong forms, encoded surrogates, truncated sequences) used to be replaced with U+FFFD and reach the JSON parser; it is now the 401 `not canonical base64url` path. A leading BOM is kept (and refused by the strict JSON parser). New `primitives.pca_header` vectors run in the Conformance runner, `R041Tests` and `PcaMiddlewareTests`.
- Version: `<Version>0.4.1</Version>` in AtlasPca.csproj and AtlasPca.AspNetCore.csproj (no version was set before).

## Unreleased (BREAKING)

- Parity: `Pca.ParseStrictEnvelope` (middleware body mode) caps depth at `MaxJsonDepth` counted from the `{"pcactn": ...}` envelope, like the TypeScript reference (`strictParse` of the whole body) and the Go / Python middleware. It allowed one extra level (`MaxJsonDepth + 1`), so a body of total depth 33 that the reference refuses reached the verifier.

- R6-05 (robustness): `VerifyRaw(null, ...)` is a `wire` deny and `SignerSetHashB64u(null)` returns null (both threw `NullReferenceException`). The round-6 depth vectors (`primitives.depth`: chain / threshold share / PCActn / strict JSON at 31, 32, 33 and 100000 levels) are part of the corpus suite and pass on a 1 MiB stack.

- R6-01 (security): the ASP.NET Core middleware's body mode parses the `{"pcactn": ...}` envelope with the strict profile (`Pca.ParseStrictEnvelope`): duplicate keys anywhere are refused, as in header mode. A lenient parse collapsed them last-wins before verification while a first-wins downstream parser of the rewound body saw the other value.
- R6-03/R6-04 (parity): `VerifyThresholdShare` validates the WHOLE signer set like the reference (unknown or wrong-case roles, malformed keys, empty / null / short `pq_pk` anywhere, one key per role, one role per key, a duplicate (role, key) only with the same `pq_pk`); `t` must be 1, 2 or 3 (0..255 was accepted); `share.role` is required; the signer-set hash sorts by UTF-8 bytes (UTF-16 ordinal order differed for non-BMP strings). New `SignerSetHashB64u` and a total `VerifyThresholdShare(object?)` overload.
- R6-05 (robustness): `VerifyChain` and `VerifyPcactnCore` are total (a malformed input is a verdict, never an exception); the per-hop type check now also requires `alg` / `pq_pk` / `pq_sig` to be absent or strings, like the reference (a hop with a numeric `pq_pk` was accepted).
- R6-02 (security): a signer-set role that registers a `pq_pk` now REQUIRES a PQ (pure or hybrid) threshold share; an ed25519-only share for that role is refused, so an Ed25519 break no longer forges a hybrid-registered role (parity with the TypeScript reference). Corpus: `agent-bound-signerset-with-pq-pk` is now `valid:false`; new positive `agent-hybrid-signerset-with-pq-pk`.
- R5-A1 (security): threshold-share verification is now signer-set PINNED, no longer self-vouched. The share must be for the one key the signer set registers for its role, a PQ/hybrid share verifies only under the set's registered `pq_pk` (a differing share `pq_pk` is refused), the share-suite tag is part of the signed bytes (a classical share cannot be relabelled hybrid), and the signer-set hash now includes a registered `pq_pk` (parity with the TypeScript reference). New corpus vectors: `agent-not-in-signer-set`, `agent-bound-signerset-with-pq-pk`, `agent-hybrid-relabel-*`.
- R5-A1 also: `SignerSetHash` previously omitted `pq_pk`.

- Suite policy defaults documented: no list = no restriction, an empty list refuses everything, and the hosted API defaults to ed25519 + Ed25519 hybrids (README lists the exact list to pass offline).

- **R4-01: root PQ pin for `Pca.VerifyChain`.** The standalone chain verifier used to verify a non-Ed25519 root hop
  (pure `ml-dsa-65` or `hybrid-ed25519-ml-dsa-65`) under the root's OWN `pq_pk`, so an attacker-minted root naming a victim
  Ed25519 issuer, signed with the attacker's own ML-DSA key, verified. `VerifyChain` now takes two optional trailing
  parameters, `IReadOnlyDictionary<string,string>? pqPins` (root issuer Ed25519 b64u -> PQ public key b64u) and
  `Dictionary<string,object?>? trustedRoot` (the verifier's own stored root capability). A root whose suite carries a PQ key
  is accepted only if `trustedRoot` has the same content hash as the root (its `pq_pk` is used), else `pqPins` has an entry
  for `root.issuer` that equals the root's `pq_pk` exactly (a differing pin is a refusal); otherwise it is refused with
  `hop 0: root suite '<alg>' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant
  (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`. Ed25519 roots are unaffected.
  Check order at hop 0: shape, expected issuer, `allowedSuites`, root PQ authority, signature.
  Migration: callers of the standalone `VerifyChain` with PQ/hybrid roots must pass `pqPins` or `trustedRoot`. The PCActn
  path (`VerifyPcactnCore` / `VerifyRaw`) is unchanged: it passes its grant as `trustedRoot`.
- All PQ verification now goes through one key-resolution function that mints an opaque private `PinnedPq`; the low-level
  suite verify accepts only that type. `VerifySuiteSig` (threshold shares, pq_artifact primitives) is explicitly
  caller-vouched.
