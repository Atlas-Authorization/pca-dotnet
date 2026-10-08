# pca-dotnet — Proof-Carrying Authority verifier for .NET

An **offline verifier for Proof-Carrying Actions (PCActns)** in .NET. A PCActn is the credential an
autonomous agent presents with *every* action it takes: a self-contained, cryptographically-checkable
object proving the action is a faithful execution of authority its principal actually granted. Your
resource server verifies it locally — no token introspection, no network call on the hot path.

This library is the .NET member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

## Install

The library project is `AtlasPca/` (namespace `AtlasPca`, targeting `net8.0`). Clone the repo and add a
project reference, or vendor the project into your solution:

```sh
dotnet add reference path/to/AtlasPca/AtlasPca.csproj
```

```csharp
using AtlasPca;
```

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (raw JSON via `VerifyRaw`, or a parsed value via
`VerifyPcactnCore`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check
results.

```csharp
using AtlasPca;

// `raw` is the PCActn as received (strict canonical JSON, wire version 2).
// `grant` is the Root Intent Grant the action's capability chain roots in.
long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

Verdict verdict = Pca.VerifyRaw(raw, grant, now, "https://api.example.com");

if (verdict.Allow)
{
    // every core check passed — execute the action
}
else
{
    Console.WriteLine($"denied: {verdict.Reason}");
}
```

`verdict.Checks` reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): over a hundred golden and adversarial PCActns with their expected verdicts,
plus canonical-JSON, strict-base64url, and Merkle primitive vectors. The `ConformanceRunner` project runs
the verifier against every vector; it must reproduce `allow` and every listed check exactly:

```sh
dotnet run --project ConformanceRunner
```

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and post-quantum public key are part of the signed body, so a suite downgrade or key swap
invalidates the action.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered. The broader
framework surface is implemented and tested in the reference implementation: threshold/step-up co-signing
(a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM allow),
TEE/hardware and model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof),
optimistic bonds and the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs
with abort). A few rungs carry a remaining production requirement, stated plainly rather than hidden
behind a label: a live TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested
against real-crypto mock reports); unforgeable FROST guardian custody needs each share in a separate trust
domain / HSM with a network signing protocol (the reference runs the signing round in-process); the MPC
Policy VM's offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and
the zero-knowledge circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller
policy coverage ongoing. See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the
full model.

## License

See `LICENSE`.
