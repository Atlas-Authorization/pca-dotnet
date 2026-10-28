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
`plan_inclusion`, `leaf_signature`, `counter_format`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Authorize an operation

`Pca.Authorize` (and `Pca.AuthorizeAsync`) is the full decision for one operation. It runs the core checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
  and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
  refused);
- checks revocation with your `IsRevoked` (only `false` passes);
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without `Audience`, `ResolveGrant`, `StateStore`, `IsRevoked` or `Operation`, the call is
refused and `result.Missing` names what is absent. It never throws: an internal error is a denial.

```csharp
using AtlasPca;

// one row per (grant, agent); SQLite or PostgreSQL through any ADO.NET provider
var store = new SqlStateStore(() => new NpgsqlConnection(connectionString));
store.EnsureSchema();

AuthorizeResult result = Pca.Authorize(pcactn, new AuthorizeInput
{
    Operation = new Operation("payments.send", "payments/acme", body), // what you will execute; body is a parsed JSON object
    Audience = "https://api.example.com",
    ResolveGrant = grantRef => grants.GetValueOrDefault(grantRef),     // grant_ref -> grant, from your own store
    StateStore = store,
    IsRevoked = (pcactn, grant) => revokedGrantIds.Contains((string)grant["id"]!),
    Plan = "single-step",
});
if (!result.Allow) throw new UnauthorizedAccessException(result.Reason); // e.g. "policy: caveat(s) not satisfied: max_spend"

SendPayment(body);
```

- `Plan = "single-step"` accepts a proof whose plan is this one operation. For a multi-step plan, return
  `plan` and `plan_authorized: true` from `Context`.
- `result.Status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.Checks` maps every check to
  `pass`, `fail` or `not-enforced`, and `result.Reason` is the decisive failure. On success `result.Operation` is the
  bound operation (verb, resource, params digest, and an `Id` for the proof), and
  `Pca.IsAuthorizedFor(result, operation)` re-checks it where the side effect runs.
- The operation comes from your own routing and parsed request, never from the proof.
- `MemoryStateStore` is for a single process. `SqlStateStore` runs one atomic
  `INSERT ... ON CONFLICT(key) DO UPDATE ... WHERE excluded.last_counter > last_counter` statement. Your own store
  implements `IStateStore.Claim(key, counter)` as one atomic operation.
- Not covered by `Authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

- The check names: `counter_format` is the stateless well-formed-counter check of the core verifier; `replay` is the
  stateful check `Authorize` adds (the counter must be strictly greater than the last one the store saw). The required
  list is `counter_format, replay, revocation, plan_root_authorized, audience, validity, grant_ref_bound, operation,
  params_digest, policy` plus `AuthorizeInput.Require`. An entry `counter` in `Require` is an alias of `replay`.
- A refusal of an envelope limit names the limit: `policy: amount <= 100 not satisfied for payments.send on payments/acme`
  (`currency in ["usd", "eur"]`, `approval present`, `all of (...)`). When no predicate covers the verb and resource the
  reason stays `policy: no predicate permits <verb> on <resource>`; an empty list stays `envelope grants no predicates`.
- A replay is `replay: 1 is not greater than last seen 1 (replay)`.

### ASP.NET Core middleware

`PcaMiddleware` runs the full `Authorize` pipeline by default. Configure it with `PcaOptions.Authorize` (a
`PcaAuthorizeOptions` with `StateStore`, `IsRevoked` and an `Operation` callback that maps the request to its operation;
a null result denies):

```csharp
app.UsePca(o =>
{
    o.Audience = "https://api.example.com";
    o.GrantResolver = async grantRef => await grants.FindAsync(grantRef);
    o.Authorize = new PcaAuthorizeOptions
    {
        StateStore = store,
        IsRevoked = (pcactn, grant) => revokedGrantIds.Contains((string)grant["id"]!),
        Operation = async ctx => new Operation("payments.send", "payments/acme", await ReadBodyAsync(ctx)),
    };
});
```

With no `Authorize` options the middleware refuses every request with 403 `authorize_config`, naming the missing
components; it never falls back to checking the signature only. A denial is a 401 or 403 response before your endpoint
runs; on success `HttpContext.Items["pca"]` is a `PcaAuthResult` whose `Operation` is the bound operation.

Signature-only verification is an explicit opt-in: `o.SignatureOnly = true` runs the core verifier alone (signature,
chain, audience, validity, counter format). It does not check the operation, predicates, caveats, revocation or replay.
Setting both `SignatureOnly` and `Authorize` throws at construction.

### Upgrading to 0.5

- The middleware default is now `Authorize`. To keep the old behaviour, set `SignatureOnly = true`; to adopt the new one,
  give it `Authorize` options.
- The core check `counter` is `counter_format` (in `verdict.Checks` and in its failure reason
  `counter_format: missing or not a non-negative safe integer`). The stateful check in `Authorize` results is `replay`,
  and its reasons start with `replay:`. Rename any code that reads `Checks["counter"]`. `Pca.DefaultRequiredChecks` lists
  the new names.

## Caveats (policy layer)

The verifier above checks that the PCActn is well formed and authentic; like every PCA core verifier it does not decide
whether the action satisfies the grant's caveats. A resource server that enforces caveats evaluates them with its own action
parameters: `Caveats.EvaluateCaveats(Caveats.PolicyCaveats(grant, chain), ctx)`. `policy_caveats` is every caveat on the root grant except its first `envelope` caveat (0.4.1: root caveats
are enforced exactly like delegated ones) followed by the caveats the delegation hops appended. Supported types: `expires`,
`not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`; any other
type is unsatisfied (fail closed). The `PCA-Action` header must be strict unpadded base64url of UTF-8 text (`Pca.DecodePcaHeader(value)` (null when invalid)).

## Protect a route in one call

```csharp
var pca = PcaProtect.Create("ins_acme", grants, async ctx => new Operation("stripe.refund", "charge:" + await ChargeOf(ctx), await ParamsOf(ctx)));
app.UsePcaProtect(pca);
pca.Revoke(grantId);   // later: every action under that grant is refused
```

`PcaProtect.Create` fills in what every server otherwise wires by hand: the grant lookup (your list, or a function; never the
request), an in-memory replay store, a revocation source and `Plan = "single-step"`. It is still the full authorize pipeline, bound to
the operation you return. Pass a callback to change any option (yours wins), and a durable `StateStore` when you run several workers.
There is no connector catalog in this SDK, so server-side risk is not filled in; supply it through `PcaAuthorizeOptions.Context`.

A refusal body is `{ "error", "error_description", "doc" }`; `doc` links the explanation of the failed check. In code,
`Refusals.Explain(reason)` returns what it means, how to fix it and the page (`Check`, `Meaning`, `Fix`, `Docs`). The reason strings are unchanged.

A runnable minimal API server using it is in `examples/MinimalApiServer`.

## What a passing result does not cover

`counter_format: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
The core verifier is stateless and signature-only. `Pca.Authorize` and the middleware (by default) add the replay store,
revocation, caveats, envelope predicates, plan authorization and the comparison of the request body with the signed
`params_digest`. A resource server that uses the core verifier alone, or the middleware with `SignatureOnly = true`, must do
those checks itself, or delegate the decision to a full verifier such as `requirePCA` from `@atlasauth/pca`.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): 676 golden and adversarial PCActns with their expected verdicts,
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
