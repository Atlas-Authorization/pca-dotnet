// HTTP agent client (the TypeScript pca-agent package): commits a plan to a resource server, signs one PCActn per act(), posts it, and
// reports allowed / denied / step_up / error. An allow is only reported when the receipt's ledger inclusion proof verifies and (when the
// server discloses the salt) the receipt commits to THIS action; otherwise it is an error, never an allow.
//
//   var client = PcaAgent.CreateAgent(new CreateAgentOptions { Grant = grant, Signer = key, RsBaseUrl = "https://rs.example", Audience = "ins_123" });
//   await client.CommitPlanAsync(nodes);
//   var r = await client.ActAsync("n1", prms);
//
// Not thread-safe (counters are handed out in order): one client per thread, or serialize ActAsync.
using System.Globalization;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.AgentClient;

public sealed class PcaAgentError : Exception
{
    /// <summary>no_plan | unknown_node | no_secret | network | bad_response | build_failed</summary>
    public string Code { get; }
    public int? HttpStatus { get; }
    public PcaAgentError(string code, string message, int? httpStatus = null) : base(message) { Code = code; HttpStatus = httpStatus; }
}

public sealed record FetchInit(string Method, IReadOnlyDictionary<string, string> Headers, string? Body);
public sealed record FetchResponse(int Status, Func<Task<object?>> Json);
public delegate Task<FetchResponse> FetchLike(string url, FetchInit init);

public sealed record TrustBudget(double B, double Tau, double AsOf);

/// <summary>Optional signed slots of wire v2 (all signed into the PCActn when present).</summary>
public sealed class ActSlots
{
    /// <summary>Uncertainty attestation in [0,1]; monotone (the verifier takes the max with its own risk).</summary>
    public object? Caution;
    public string? RationaleCommitment;
    public JD? ProgressStep;
    public object? ProhibitionEvidence;
    public string? ToolBinding;
    public string? Nonce;
}

public sealed class CreateAgentOptions
{
    public JD Grant = new();
    /// <summary>Capability chain starting at the grant; null means <c>[grant]</c>.</summary>
    public IReadOnlyList<object?>? Chain;
    /// <summary>The leaf holder's signing key. Null only for a sub-agent client you do not drive.</summary>
    public SuiteKey? Signer;
    public string? AgentPublic;
    public string RsBaseUrl = "";
    /// <summary>REQUIRED: the audience the PCActns are FOR (the Atlas instance id, or the id the resource server expects).</summary>
    public string Audience = "";
    public long? TtlMs;
    public Func<long>? Now;
    public bool Nonce = true;
    public FetchLike? Fetch;
    /// <summary>Verify every receipt's inclusion proof before reporting allowed (default true).</summary>
    public bool VerifyReceipts = true;
    public long Counter;
    public TrustBudget? Budget;
    public ProvenanceRecorder? Provenance;
}

public sealed class Receipt
{
    public string? GrantRef;
    public long Index;
    public string Commit = "";
    public string Root = "";
    public long? Size;
    public string? Salt;
    public JD? InclusionProof;
}

/// <summary>Outcome of one act: Status is allowed | denied | step_up | error.</summary>
public sealed class ActResult
{
    public string Status = "";
    public JD? Verdict;
    public Receipt? Receipt;
    public JD? Pcactn;
    public int? HttpStatus;
    public string? StepupId;
    public long RequiredT;
    public PcaAgentError? Error;
}

/// <summary>Outcome of a step-up wait: Status is approved | denied | expired | timeout; Body is the server's answer.</summary>
public sealed class StepUpOutcome
{
    public string Status = "";
    public JD? Body;
    public int? HttpStatus;
}

public sealed class PcaAgentClient
{
    readonly CreateAgentOptions _o;
    readonly string _base;
    readonly FetchLike _fetch;
    readonly IReadOnlyList<object?> _chain;
    long _counter;
    TrustBudget? _budget;
    List<JD>? _plan;
    string? _planRoot;

    internal PcaAgentClient(CreateAgentOptions o, string baseUrl, FetchLike fetch)
    {
        _o = o; _base = baseUrl; _fetch = fetch;
        _chain = (o.Chain ?? new object?[] { o.Grant }).ToList();
        _counter = o.Counter; _budget = o.Budget;
    }

    public JD Grant => _o.Grant;
    public IReadOnlyList<object?> Chain => _chain;
    public string? AgentPublic => _o.AgentPublic;
    public long Counter => _counter;
    public TrustBudget? Budget => _budget;
    public string? PlanRoot => _planRoot;

    async Task<(int Status, JD Json)> Call(string method, string path, JD? body)
    {
        var res = await _fetch(_base + path, new FetchInit(method, new Dictionary<string, string> { ["content-type"] = "application/json", ["accept"] = "application/json" },
            body == null ? null : Pca.Canonicalize(body))).ConfigureAwait(false);
        JD json = new();
        try { json = await res.Json().ConfigureAwait(false) as JD ?? new JD(); } catch { /* non-JSON body */ }
        return (res.Status, json);
    }

    public async Task<string> CommitPlanAsync(IEnumerable<JD> nodes)
    {
        var list = nodes.ToList();
        var local = Issue.CommitPlan(list).Root;
        var res = await Call("POST", "/v1/pca/plans", new JD { ["grant_ref"] = _o.Grant.GetValueOrDefault("id"), ["nodes"] = new JL(list) }).ConfigureAwait(false);
        if (res.Status < 200 || res.Status >= 300) throw new PcaAgentError("bad_response", $"plan commit failed ({res.Status})", res.Status);
        // The server must echo the root it committed: a missing root cannot be told apart from a server that stored another plan.
        if (res.Json.GetValueOrDefault("plan_root") is not string remote || remote != local)
            throw new PcaAgentError("bad_response", "server plan_root is missing or differs from the locally computed root", res.Status);
        _plan = list; _planRoot = local;
        return local;
    }

    static ActResult Err(string code, string msg, int? http = null) => new() { Status = "error", Error = new PcaAgentError(code, msg, http) };

    static bool IsBudget(object? b) => b is JD d && Fin(d, "B") && Fin(d, "tau") && Fin(d, "asOf");
    static bool Fin(JD d, string k) => d.GetValueOrDefault(k) is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) && double.IsFinite(v);
    static double Dbl(object? v) => double.Parse(((Num)v!).Raw, CultureInfo.InvariantCulture);

    static bool ReceiptBinds(Receipt r, JD pcactn)
    {
        try { return r.Salt != null && Pca.HashCanonical(new JD { ["salt"] = r.Salt, ["pcactn_digest"] = Pca.HashCanonical(pcactn) }) == r.Commit; }
        catch { return false; }
    }

    public bool VerifyReceipt(Receipt r)
    {
        try { return r.InclusionProof != null && Ledger.VerifyLedgerInclusion(r.Root, r.InclusionProof, r.Commit); }
        catch { return false; }
    }

    static Receipt? ParseReceipt(object? v)
    {
        if (v is not JD d) return null;
        long L(string k) => d.GetValueOrDefault(k) is Num n && long.TryParse(n.Raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ? x : 0;
        return new Receipt
        {
            GrantRef = d.GetValueOrDefault("grant_ref") as string, Index = L("index"), Commit = d.GetValueOrDefault("commit") as string ?? "",
            Root = d.GetValueOrDefault("root") as string ?? "", Size = d.ContainsKey("size") ? L("size") : null,
            Salt = d.GetValueOrDefault("salt") as string, InclusionProof = d.GetValueOrDefault("inclusion_proof") as JD,
        };
    }

    public async Task<ActResult> ActAsync(string nodeId, JD? prms = null, ActSlots? slots = null)
    {
        if (_plan == null) return Err("no_plan", "CommitPlanAsync() first");
        if (_o.Signer == null) return Err("no_secret", "no signer for this client");
        var node = _plan.FirstOrDefault(n => Equals(n.GetValueOrDefault("id"), nodeId));
        if (node == null) return Err("unknown_node", $"unknown plan node {nodeId}");
        var next = _counter + 1;
        JD pcactn;
        try
        {
            var spec = new ActSpec
            {
                Grant = _o.Grant, Chain = new JL(_chain), Plan = Issue.CommitPlan(_plan), NodeId = nodeId, Params = prms, Counter = next, Signer = _o.Signer,
                Aud = _o.Audience, Iat = (_o.Now ?? (() => AtlasPca.ReplayClock.NowMs()))(), TtlMs = _o.TtlMs,
                Nonce = slots?.Nonce ?? (_o.Nonce ? Issue.RandomB64u(16) : null),
                Caution = slots?.Caution, RationaleCommitment = slots?.RationaleCommitment, ProgressStep = slots?.ProgressStep,
                ProhibitionEvidence = slots?.ProhibitionEvidence, ToolBinding = slots?.ToolBinding,
            };
            pcactn = Issue.BuildPCActn(spec);
        }
        catch (Exception e) { return Err("build_failed", e.Message); }
        _counter = next; // monotonic: never reuse a counter, even if the call fails
        JD? provenance = null;
        try
        {
            if (_o.Provenance != null)
                provenance = _o.Provenance.ForAction(node.GetValueOrDefault("verb") as string ?? "", node.GetValueOrDefault("resource") as string ?? "", prms ?? new JD());
        }
        catch (Exception e) { return Err("build_failed", e.Message); }
        (int Status, JD Json) res;
        try
        {
            var body = new JD { ["pcactn"] = pcactn };
            if (provenance != null) body["pca_provenance"] = provenance;
            res = await Call("POST", "/v1/pca/actions", body).ConfigureAwait(false);
        }
        catch (Exception e) { return Err("network", e.Message); }
        var j = res.Json;
        if (res.Status == 202 || j.GetValueOrDefault("status") as string == "step_up_required" || j.GetValueOrDefault("step_up_required") is true)
        {
            var id = j.GetValueOrDefault("stepup_id") ?? j.GetValueOrDefault("stepupId") ?? j.GetValueOrDefault("id");
            var t = j.GetValueOrDefault("required_t") ?? j.GetValueOrDefault("requiredT") ?? j.GetValueOrDefault("t");
            if (id is not string sid) return Err("bad_response", "step-up response missing stepup_id", res.Status);
            return new ActResult { Status = "step_up", StepupId = sid, RequiredT = t is Num tn && long.TryParse(tn.Raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var tv) ? tv : 2, Pcactn = pcactn };
        }
        var verdict = j.GetValueOrDefault("verdict") as JD ?? new JD { ["allow"] = j.GetValueOrDefault("allow") is true };
        // Allow only on an explicit boolean true from every place the server states it.
        var allowed = res.Status >= 200 && res.Status < 300 && verdict.GetValueOrDefault("allow") is true
            && (!j.ContainsKey("allow") || j["allow"] is true);
        if (verdict.GetValueOrDefault("budget") is JD bd && IsBudget(bd)) _budget = new TrustBudget(Dbl(bd["B"]), Dbl(bd["tau"]), Dbl(bd["asOf"]));
        if (!allowed) return new ActResult { Status = "denied", Verdict = verdict, HttpStatus = res.Status, Pcactn = pcactn };
        var receipt = ParseReceipt(j.GetValueOrDefault("receipt"));
        if (receipt == null) return Err("bad_response", "allow without receipt", res.Status);
        if (_o.VerifyReceipts)
        {
            if (!VerifyReceipt(receipt)) return Err("bad_response", "allow receipt inclusion proof does not verify", res.Status);
            if (receipt.Salt != null && !ReceiptBinds(receipt, pcactn)) return Err("bad_response", "allow receipt does not commit to this action", res.Status);
        }
        return new ActResult { Status = "allowed", Verdict = verdict, Receipt = receipt, Pcactn = pcactn };
    }

    public async Task<StepUpOutcome> AwaitStepUpAsync(string stepupId, long pollMs = 1000, long timeoutMs = 5 * 60_000)
    {
        var clock = _o.Now ?? (() => AtlasPca.ReplayClock.NowMs());
        var deadline = clock() + timeoutMs;
        for (;;)
        {
            (int Status, JD Json) res;
            try
            {
                // Long poll (the server answers as soon as the step-up is decided, at most 25 s); servers without it ignore wait.
                var wait = Math.Min(25, (deadline - clock()) / 1000);
                res = await Call("GET", $"/v1/pca/stepups/{Uri.EscapeDataString(stepupId)}{(wait > 0 ? $"?wait={wait}" : "")}", null).ConfigureAwait(false);
            }
            catch (Exception e) { throw new PcaAgentError("network", e.Message); }
            var s = res.Json.GetValueOrDefault("status") as string;
            var ok = res.Status >= 200 && res.Status < 300;
            // Only a 2xx answer can approve; a non-2xx answer that says "approved" is not an approval.
            if (ok && (s == "approved" || s == "denied" || s == "expired")) return new StepUpOutcome { Status = s, Body = res.Json };
            // 4xx other than 429 is final (unknown or foreign step-up): stop polling, never approve.
            if (res.Status >= 400 && res.Status < 500 && res.Status != 429) return new StepUpOutcome { Status = "denied", HttpStatus = res.Status };
            if (clock() + pollMs > deadline) return new StepUpOutcome { Status = "timeout" };
            await Task.Delay((int)pollMs).ConfigureAwait(false);
        }
    }

    /// <summary>A sub-agent client over the chain extended by one narrower hop signed by this client's key.</summary>
    public PcaAgentClient Delegate(SuiteKey child, JL? addedCaveats = null)
    {
        if (_o.Signer == null) throw new PcaAgentError("no_secret", "cannot delegate without a signer");
        if (child.Ed == null) throw new ArgumentException("a delegate holder needs an Ed25519 identity");
        var hop = Issue.Delegate((JD)_chain[^1]!, child.Ed.Id, addedCaveats, _o.Signer, child.PqPk);
        var o = new CreateAgentOptions
        {
            Grant = _o.Grant, Chain = _chain.Append(hop).ToList(), Signer = child, AgentPublic = child.Ed.Id, RsBaseUrl = _base, Audience = _o.Audience,
            TtlMs = _o.TtlMs, Now = _o.Now, Nonce = _o.Nonce, Fetch = _fetch, VerifyReceipts = _o.VerifyReceipts,
            Provenance = _o.Provenance, // same context session: its actions extend the same chain
            Counter = 0,
        };
        return new PcaAgentClient(o, _base, _fetch);
    }
}

public static class PcaAgent
{
    static readonly HttpClient Http = new();

    static async Task<FetchResponse> DefaultFetch(string url, FetchInit init)
    {
        using var req = new HttpRequestMessage(new HttpMethod(init.Method), url);
        if (init.Body != null) req.Content = new StringContent(init.Body, Encoding.UTF8, "application/json");
        foreach (var (k, v) in init.Headers) if (!k.Equals("content-type", StringComparison.OrdinalIgnoreCase)) req.Headers.TryAddWithoutValidation(k, v);
        var res = await Http.SendAsync(req).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
        return new FetchResponse((int)res.StatusCode, () => Task.FromResult(Pca.ParseJson(text)));
    }

    public static PcaAgentClient CreateAgent(CreateAgentOptions opts)
    {
        if (string.IsNullOrEmpty(opts.Audience))
            throw new PcaAgentError("build_failed", "createAgent: `audience` is required (the resource-server / Atlas instance id PCActns are for)");
        if (!Uri.TryCreate(opts.RsBaseUrl, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http"))
            throw new PcaAgentError("build_failed", "createAgent: `rsBaseUrl` must be an absolute http(s) URL");
        return new PcaAgentClient(opts, opts.RsBaseUrl.TrimEnd('/'), opts.Fetch ?? DefaultFetch);
    }
}
