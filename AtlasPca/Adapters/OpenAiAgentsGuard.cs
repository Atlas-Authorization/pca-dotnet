// OpenAI Agents SDK guard: make every agent tool call proof-carrying and policy-gated at the LOCAL execution boundary. WithPcaTool wraps a
// tool's execute(input, runContext) so it first REQUIRES a proof-carrying action (pulled from the run context by the PCA-Action
// convention), VERIFIES it (fail closed: PcaToolDenied), and only then runs the original tool. Guardrails trip a run that lacks a valid proof.
//
// Structural, no vendor package: a tool is a delegate over JSON trees, the run context a JSON object whose "context" member is the
// caller's bag (the proof rides there as "pca" / "pcaProof").
//
// Two modes. Full (the default): every call runs Pca.AuthorizeAsync, the input must hash to the signed params digest, the grant's predicates,
// limits and caveats are evaluated, revocation is required and a replay store makes each PCActn single-use; a missing component is refused.
// Signature-only: the proof's signature, capability chain, plan inclusion, audience and validity window are checked, NOT that the grant
// permits this call (limits are not read, nothing stops a replay). Either way this does not replace the resource server when a tool makes a
// remote call; it makes the local boundary refuse to act without a valid PCActn.
//
// Step-up: ReviewToolCall / PendingStepUps / PcaNeedsApproval / WithApproval map a risky tool to the SDK's needsApproval interruption through
// Approvals.ReviewAction (auto / deny / tier-2 or tier-3 co-sign). Not ported: withPCA / withPCATools (the JS Vercel-AI attach side).
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Adapters;

/// <summary>Why a guarded execute or guardrail refused: missing, malformed, verify, binding, policy, replay, revoked or config.</summary>
public sealed class PcaToolDenied(string message, string verb, string kind, IReadOnlyDictionary<string, string>? checks = null)
    : Exception($"PCA tool denied ({kind}) for {verb}: {message}")
{
    /// <summary>The PCA verb the proof claimed (or the configured verb / "(tool)" when unknown).</summary>
    public string Verb { get; } = verb;
    public string Kind { get; } = kind;
    /// <summary>The per-check verdicts when the denial was a verification failure.</summary>
    public IReadOnlyDictionary<string, string>? Checks { get; } = checks;
}

/// <summary>A verification outcome of a custom verifier.</summary>
public sealed record VerifyOutcome(bool Allow, string? Reason = null, IReadOnlyDictionary<string, string>? Checks = null);

/// <summary>Signature-only verification: the grant the proof must chain to. The plan-root policy defaults to "nothing authorized" (every call refused);
/// name the authorized roots, or <see cref="PlanRootPolicy.Skip"/> explicitly.</summary>
public sealed class VerifyGrant
{
    public required D Grant { get; init; }
    /// <summary>Verifier clock (epoch ms), evaluated per call; default the wall clock.</summary>
    public Func<long>? Now { get; init; }
    public IReadOnlyCollection<string>? AllowedSuites { get; init; }
    public PlanRootPolicy PlanRoots { get; init; } = new();
}

/// <summary>How the guard verifies in signature-only mode: a grant, or a custom verifier (exactly one).</summary>
public sealed record WithPcaToolOptions
{
    /// <summary>Find the proof for a call: (input, runContext) to a PCActn object or string; null fails closed. Default <see cref="OpenAiAgentsGuard.ProofFromRunContext"/>.</summary>
    public Func<D, D, object?>? Require { get; init; }
    /// <summary>"full" (default) or "signature-only".</summary>
    public string? Mode { get; init; }
    /// <summary>Signature-only: the grant to chain to.</summary>
    public VerifyGrant? Verify { get; init; }
    /// <summary>Signature-only: a custom verifier (instead of <see cref="Verify"/>).</summary>
    public Func<D, VerifyOutcome>? VerifyFn { get; init; }
    /// <summary>Full mode: builds the per-call <see cref="AuthorizeInput"/> (operation, grant resolver, state store, revocation check, ...). The guard
    /// sets its own audience, and the provenance bundle when the input carries none. A fresh input per call.</summary>
    public Func<D, D, AuthorizeInput>? Authorize { get; init; }
    /// <summary>This verifier's audience, matched against the PCActn's signed aud. Required (an accept-any audience is not supported).</summary>
    public string? Audience { get; init; }
    /// <summary>Defense in depth: the proof's action verb must equal this (bind the proof to THIS tool).</summary>
    public string? Verb { get; init; }
    /// <summary>Where the provenance bundle of this call is. Default <see cref="OpenAiAgentsGuard.ProvenanceFromRunContext"/>.</summary>
    public Func<D, D, object?>? Provenance { get; init; }
    /// <summary>When set, every result the tool returns is recorded as UNTRUSTED tool output.</summary>
    public IToolOutputRecorder? Recorder { get; init; }
    public Action<PcaToolDenied, D>? OnDeny { get; init; }
    /// <summary>Observe a successful verification (the PCActn, the tool input) before the original execute runs.</summary>
    public Action<D, D>? OnVerified { get; init; }
}

/// <summary>What an Agents-SDK guardrail returns: a tripwire plus free-form info.</summary>
public sealed record GuardrailOutput(bool TripwireTriggered, D OutputInfo);

public sealed record PcaGuardrailOptions
{
    /// <summary>Find the proof for a run: the guardrail args (<c>{context, ...}</c>) to a PCActn object or string. Default <see cref="OpenAiAgentsGuard.GuardrailProofFromContext"/>.</summary>
    public Func<D, object?>? Require { get; init; }
    public VerifyGrant? Verify { get; init; }
    public Func<D, VerifyOutcome>? VerifyFn { get; init; }
    public string? Audience { get; init; }
    public string? Verb { get; init; }
    public string? Name { get; init; }
}

/// <summary>A guardrail: a name and an execute over the SDK's guardrail args.</summary>
public sealed record AgentGuardrail(string Name, Func<D, Task<GuardrailOutput>> Execute);

public static class OpenAiAgentsGuard
{
    // ---- proof sources ----

    /// <summary>An encoded PCActn string from a <c>{pca | pcaProof}</c> bag; null when neither is a string.</summary>
    public static string? ProofFromBag(object? bag) =>
        bag is D d ? (d.GetValueOrDefault("pca") ?? d.GetValueOrDefault("pcaProof")) as string : null;

    /// <summary>Default proof source: <c>runContext.context.{pca|pcaProof}</c>, then <c>runContext.{pca|pcaProof}</c>.</summary>
    public static object? ProofFromRunContext(D input, D runContext) => ProofFromBag(runContext.GetValueOrDefault("context")) ?? ProofFromBag(runContext);

    /// <summary>Default provenance source: <c>{pcaProvenance | pca_provenance | PCA-Provenance}</c> on <c>runContext.context</c>, then on <c>runContext</c>.</summary>
    public static object? ProvenanceFromRunContext(D input, D runContext)
    {
        foreach (var bag in new[] { runContext.GetValueOrDefault("context"), runContext })
            if (bag is D d && (d.GetValueOrDefault("pcaProvenance") ?? d.GetValueOrDefault("pca_provenance") ?? d.GetValueOrDefault("PCA-Provenance")) is { } v) return v;
        return null;
    }

    /// <summary>A proof source reading a base64url PCA-Action header from a headers-like bag on the tool input.</summary>
    public static Func<D, D, object?> ProofFromInputHeaders(string field = "headers", string header = "PCA-Action") =>
        (input, runContext) => input.GetValueOrDefault(field) is D bag ? bag.GetValueOrDefault(header) as string : null;

    /// <summary>The guardrail-side default: the proof from the run context the SDK passes as <c>args.context</c>.</summary>
    public static object? GuardrailProofFromContext(D args)
    {
        var outer = args.GetValueOrDefault("context");
        var inner = outer is D o ? o.GetValueOrDefault("context") : null;
        return ProofFromBag(inner) ?? ProofFromBag(outer);
    }

    // ---- the proof pipeline ----

    // a string is tried as raw encoded JSON, then as a PCA-Action header value
    /// <summary>JavaScript's <c>String(cause)</c>: the error's name, then its message (a typed header error carries its own name).</summary>
    static string CauseText(Exception cause) => cause is PcaHeaderError ? "PcaHeaderError: " + cause.Message : cause.Message;

    static D ToPcActn(object? input)
    {
        if (input is D d) return d;
        if (input is not string s) throw new InvalidOperationException("a proof is a PCActn object or an encoded string");
        try { if (Pca.ParseStrict(s) is D raw) return raw; }
        catch (Exception) { /* fall through to the header form */ }
        return Pca.ParseStrict(PcaAdapters.DecodePcaHeader(s)) as D ?? throw new InvalidOperationException("the proof is not a JSON object");
    }

    static string VerbOf(D pcactn) => (pcactn.GetValueOrDefault("action") as D)?.GetValueOrDefault("verb") as string ?? "";

    static VerifyOutcome RunVerify(VerifyGrant? verify, Func<D, VerifyOutcome>? fn, D pcactn, string audience)
    {
        if (fn != null) return fn(pcactn);
        var v = verify!;
        var verdict = Pca.VerifyPcactnCore(pcactn, v.Grant, (v.Now ?? (() => AtlasPca.ReplayClock.NowMs()))(), audience, v.AllowedSuites, planRoots: v.PlanRoots);
        return new VerifyOutcome(verdict.Allow, verdict.Reason, verdict.Checks.ToDictionary(c => c.Key, c => c.Value ? "pass" : "fail"));
    }

    // the kind of a refused full-policy decision, from the first failing check
    static string KindOf(AuthorizeResult r)
    {
        if (r.Missing is { Count: > 0 }) return "config";
        var failed = r.Checks.FirstOrDefault(c => c.Value == "fail").Key ?? "";
        return failed switch
        {
            "authorize_config" => "config",
            "replay" => "replay",
            "revocation" or "freshness" => "revoked",
            "operation" or "params_digest" => "binding",
            "policy" or "plan_state" or "plan_root_authorized" or "provenance_flow" => "policy",
            _ => "verify",
        };
    }

    static void CheckMode(string? mode, bool hasVerify, bool hasAuthorize, string who)
    {
        var m = mode ?? "full";
        if (m != "full" && m != "signature-only") throw new ArgumentException($"{who}: unknown mode '{m}'");
        if (m == "signature-only")
        {
            if (hasAuthorize) throw new ArgumentException($"{who}: `Authorize` is the full mode; drop it, or drop mode 'signature-only'");
            if (!hasVerify) throw new ArgumentException($"{who}: mode 'signature-only' needs `Verify` or `VerifyFn`");
        }
        else
        {
            if (!hasAuthorize) throw new ArgumentException($"{who}: pass `Authorize` (full policy, the default mode), or set mode 'signature-only' with `Verify`");
            if (hasVerify) throw new ArgumentException($"{who}: `Verify` checks the signature only: set mode 'signature-only' to use it, and drop `Authorize`");
        }
    }

    /// <summary>Wrap a tool's <c>execute(input, runContext)</c> so each call first REQUIRES + VERIFIES a proof-carrying action (fail closed:
    /// <see cref="PcaToolDenied"/>), then runs the original. Throws <see cref="ArgumentException"/> at construction on a missing or contradictory configuration.</summary>
    public static Func<D, D?, Task<object?>> WithPcaTool(string? toolName, Func<D, D?, Task<object?>> execute, WithPcaToolOptions options)
    {
        CheckMode(options.Mode, options.Verify != null || options.VerifyFn != null, options.Authorize != null, "withPcaTool");
        if (options.Verify != null && options.VerifyFn != null) throw new ArgumentException("withPcaTool: give exactly one of `Verify` and `VerifyFn`");
        if (string.IsNullOrEmpty(options.Audience)) throw new ArgumentException("withPcaTool: `Audience` (this verifier's id) is required");
        var source = options.Require ?? ProofFromRunContext;
        var prov = options.Provenance ?? ProvenanceFromRunContext;
        var label = options.Verb ?? toolName ?? "(tool)";
        var audience = options.Audience;
        return async (input, runContextOrNull) =>
        {
            var runContext = runContextOrNull ?? new D();
            D pcactn;
            try
            {
                var raw = source(input, runContext);
                if (raw == null) throw new PcaToolDenied("no proof-carrying action present on the call", label, "missing");
                try { pcactn = ToPcActn(raw); }
                catch (Exception cause) { throw new PcaToolDenied("proof could not be decoded: " + CauseText(cause), label, "malformed"); }
                var verb = VerbOf(pcactn);
                if (options.Verb != null && verb != options.Verb)
                    throw new PcaToolDenied($"proof is for '{verb}', not this tool's '{options.Verb}'", verb, "binding");
                if (options.Authorize != null)
                {
                    AuthorizeResult d;
                    try
                    {
                        var ai = options.Authorize(input, runContext);
                        ai.Audience = audience;
                        ai.Provenance ??= PcaAdapters.ProvenanceFrom(prov(input, runContext));
                        d = await Pca.AuthorizeAsync(pcactn, ai).ConfigureAwait(false);
                    }
                    catch (Exception e) when (e is not PcaToolDenied) { throw new PcaToolDenied("the authorize configuration failed: " + e.Message, verb == "" ? label : verb, "config"); }
                    if (!d.Allow) throw new PcaToolDenied(d.Reason ?? "denied", verb == "" ? label : verb, KindOf(d), d.Checks);
                }
                else
                {
                    var r = RunVerify(options.Verify, options.VerifyFn, pcactn, audience);
                    if (!r.Allow) throw new PcaToolDenied(r.Reason ?? "verification failed", verb == "" ? label : verb, "verify", r.Checks);
                }
            }
            catch (PcaToolDenied e)
            {
                options.OnDeny?.Invoke(e, input);
                throw;
            }
            options.OnVerified?.Invoke(pcactn, input);
            var output = await execute(input, runContextOrNull).ConfigureAwait(false);
            options.Recorder?.Tool(VerbOf(pcactn) is { Length: > 0 } v ? v : label, output);
            return output;
        };
    }

    static WithPcaToolOptions Merge(WithPcaToolOptions b, WithPcaToolOptions? o)
    {
        if (o == null) return b;
        // a per-tool Verify or Authorize replaces the shared mode (the two are exclusive)
        var mode = o.Authorize != null
            ? b with { Authorize = o.Authorize, Verify = null, VerifyFn = null, Mode = o.Mode }
            : o.Verify != null || o.VerifyFn != null
                ? b with { Authorize = null, Verify = o.Verify, VerifyFn = o.VerifyFn, Mode = o.Mode ?? b.Mode }
                : b with { Mode = o.Mode ?? b.Mode };
        return mode with
        {
            Require = o.Require ?? b.Require, Audience = o.Audience ?? b.Audience, Verb = o.Verb ?? b.Verb, OnDeny = o.OnDeny ?? b.OnDeny,
            OnVerified = o.OnVerified ?? b.OnVerified, Provenance = o.Provenance ?? b.Provenance, Recorder = o.Recorder ?? b.Recorder,
        };
    }

    /// <summary>Guard a whole <c>{name: execute}</c> set in one call. Every tool is guarded with the shared options (override per tool via
    /// <paramref name="per"/>, or limit the set via <paramref name="only"/>; the others pass through unchanged).</summary>
    public static Dictionary<string, Func<D, D?, Task<object?>>> PcaTools(IReadOnlyDictionary<string, Func<D, D?, Task<object?>>> tools, WithPcaToolOptions options,
        IReadOnlyDictionary<string, WithPcaToolOptions>? per = null, IReadOnlyCollection<string>? only = null)
    {
        var res = new Dictionary<string, Func<D, D?, Task<object?>>>();
        foreach (var (name, tool) in tools)
            res[name] = only != null && !only.Contains(name) ? tool : WithPcaTool(name, tool, Merge(options, per != null && per.TryGetValue(name, out var o) ? o : null));
        return res;
    }

    // ---- guardrails: reject a run / tool call lacking a valid proof ----

    static Func<D, Task<GuardrailOutput>> GuardrailExecute(PcaGuardrailOptions opts)
    {
        if ((opts.Verify == null) == (opts.VerifyFn == null)) throw new ArgumentException("guardrail: give exactly one of `Verify` and `VerifyFn`");
        if (string.IsNullOrEmpty(opts.Audience)) throw new ArgumentException("guardrail: `Audience` (this verifier's id) is required");
        var source = opts.Require ?? GuardrailProofFromContext;
        var label = opts.Verb ?? "(run)";
        return args =>
        {
            try
            {
                var raw = source(args) ?? throw new PcaToolDenied("no proof-carrying action present on the call", label, "missing");
                D pcactn;
                try { pcactn = ToPcActn(raw); }
                catch (Exception cause) { throw new PcaToolDenied("proof could not be decoded: " + CauseText(cause), label, "malformed"); }
                var verb = VerbOf(pcactn);
                if (opts.Verb != null && verb != opts.Verb) throw new PcaToolDenied($"proof is for '{verb}', not this tool's '{opts.Verb}'", verb, "binding");
                var r = RunVerify(opts.Verify, opts.VerifyFn, pcactn, opts.Audience);
                if (!r.Allow) throw new PcaToolDenied(r.Reason ?? "verification failed", verb == "" ? label : verb, "verify", r.Checks);
                return Task.FromResult(new GuardrailOutput(false, new D { ["verb"] = verb }));
            }
            catch (PcaToolDenied e)
            {
                var checks = e.Checks == null ? null : new D(e.Checks.ToDictionary(c => c.Key, c => (object?)c.Value));
                return Task.FromResult(new GuardrailOutput(true, new D { ["kind"] = e.Kind, ["verb"] = e.Verb, ["reason"] = e.Message, ["checks"] = checks }));
            }
        };
    }

    /// <summary>An input guardrail: runs once at the top of a run and trips the tripwire (rejecting the run before any step executes) when the
    /// run context carries no valid proof. Signature-only: a run-level guardrail sees no single tool call to bind; put the authority check on the tool.</summary>
    public static AgentGuardrail PcaInputGuardrail(PcaGuardrailOptions options) => new(options.Name ?? "pca-input-guardrail", GuardrailExecute(options));

    /// <summary>A tool guardrail: the same proof gate scoped to a tool call (read the proof from the tool input with <c>Require</c>).</summary>
    public static AgentGuardrail PcaToolGuard(PcaGuardrailOptions options) => new(options.Name ?? "pca-tool-guard", GuardrailExecute(options));

    // ---- step-up: map a risky tool to needsApproval / the interruption flow ----

    /// <summary>Reviews one intended tool call against the agent's grant. <see cref="StepUpOptions.Intent"/> maps the tool to the PCA action to review; null treats the tool as unguarded (auto).</summary>
    public static ToolReview ReviewToolCall(AgentHandle agent, string tool, D? input, StepUpOptions opts)
    {
        var mapped = opts.Intent(tool, input);
        if (mapped == null) return new ToolReview(tool, new D { ["kind"] = "auto" });
        var review = Approvals.ReviewAction(agent, (string)mapped["verb"]!, (string)mapped["resource"]!, mapped.GetValueOrDefault("params") as D ?? input,
            new ReviewOptions { Now = opts.Now, Goal = opts.Goal, Standing = opts.Standing, Renderer = opts.Renderer, InsecureUnboundApproval = opts.InsecureUnboundApproval });
        return new ToolReview(tool, review);
    }

    /// <summary>The step-up requests from a batch of reviews (auto and deny are filtered out).</summary>
    public static List<ToolStepUp> PendingStepUps(IEnumerable<ToolReview> reviews) =>
        reviews.Where(r => r.Review.GetValueOrDefault("kind") is "step_up").Select(r => new ToolStepUp(r.Tool, (D)r.Review["request"]!)).ToList();

    /// <summary>Builds a needsApproval callback (run context, tool input) from PCA risk review: auto returns false; a step-up not yet approved is routed to
    /// <see cref="PcaNeedsApprovalOptions.OnStepUp"/> and returns true (the SDK interrupts for a tier-2/3 co-sign); an already approved step-up returns false;
    /// a deny returns <see cref="PcaNeedsApprovalOptions.DenyNeedsApproval"/> (default true: interrupt so the approver can reject it, fail safe).</summary>
    public static Func<D, D, bool> PcaNeedsApproval(AgentHandle agent, PcaNeedsApprovalOptions opts)
    {
        var toolName = opts.ToolName ?? "(tool)";
        return (runContext, input) =>
        {
            var review = ReviewToolCall(agent, toolName, input, opts).Review;
            var kind = review.GetValueOrDefault("kind") as string;
            if (kind == "auto") return false;
            if (kind == "deny") return opts.DenyNeedsApproval;
            var request = (D)review["request"]!;
            if (opts.Approved?.Invoke(request) == true) return false;
            opts.OnStepUp?.Invoke(new ToolStepUp(toolName, request));
            return true;
        };
    }

    /// <summary>The needsApproval callback of a tool named <paramref name="toolName"/> (the intent lookup is seeded with it unless <see cref="PcaNeedsApprovalOptions.ToolName"/> is set;
    /// a nameless tool is "(tool)"). Attach it to the tool as the SDK's needsApproval.</summary>
    public static Func<D, D, bool> WithApproval(string? toolName, AgentHandle agent, PcaNeedsApprovalOptions opts) =>
        PcaNeedsApproval(agent, opts with { ToolName = opts.ToolName ?? toolName ?? "(tool)" });
}

/// <summary>Maps a tool name (and its input) to the PCA action to review ({verb, resource, params?}); null treats the tool as unguarded (auto).</summary>
public delegate D? ToolIntent(string tool, D? input);

/// <summary>Options of <see cref="OpenAiAgentsGuard.ReviewToolCall"/>.</summary>
public record StepUpOptions
{
    /// <summary>Which PCA (verb, resource, params) a tool call maps to for risk review.</summary>
    public required ToolIntent Intent { get; init; }
    /// <summary>Standing "approve this class for N hours" grants that downgrade a matching step-up to auto.</summary>
    public IReadOnlyList<object?>? Standing { get; init; }
    /// <summary>Plaintext goal to carry on any step-up request.</summary>
    public string? Goal { get; init; }
    /// <summary>Review clock (epoch ms); null: the wall clock.</summary>
    public long? Now { get; init; }
    /// <summary>The canonical approval render of the action. A step-up without one is a deny.</summary>
    public Func<string, string, D?, D>? Renderer { get; init; }
    /// <summary>The documented INSECURE opt-out: create step-up requests with no render.</summary>
    public bool InsecureUnboundApproval { get; init; }
}

/// <summary>Options of <see cref="OpenAiAgentsGuard.PcaNeedsApproval"/>.</summary>
public sealed record PcaNeedsApprovalOptions : StepUpOptions
{
    /// <summary>The tool name to review (default "(tool)").</summary>
    public string? ToolName { get; init; }
    /// <summary>True when a step-up request has already been co-signed (your FROST / CIBA result): it is then let through.</summary>
    public Func<D, bool>? Approved { get; init; }
    /// <summary>Receives each step-up this call raised: push it to the approval inbox / open the co-sign round.</summary>
    public Action<ToolStepUp>? OnStepUp { get; init; }
    /// <summary>Whether a policy deny also routes to approval (so the run interrupts and the approver rejects it). Default true.</summary>
    public bool DenyNeedsApproval { get; init; } = true;
}

/// <summary>The outcome of reviewing one intended tool call: Review is {kind: auto} | {kind: deny, reason} | {kind: step_up, request}.</summary>
public sealed record ToolReview(string Tool, D Review);

/// <summary>A step-up a tool call raised (what the approval inbox / co-sign round / SDK interruption receives).</summary>
public sealed record ToolStepUp(string Tool, D Request);
