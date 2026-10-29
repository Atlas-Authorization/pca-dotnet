// An agent that acts under a grant: it owns the leaf signing key, the capability chain and the monotonic counter, stamps a fresh nonce
// on every action, and encodes the PCActn the way the native middleware expects (the PCA-Action header, unpadded base64url of the
// JSON). No TypeScript process is needed.
//
//   var me = SuiteKey.Ed25519(EdKey.Generate());
//   var agent = new Agent(me, "ins_123", grant);                  // chain defaults to [grant]
//   var pcactn = agent.Act("pay", "invoice/7", new() { ["amount"] = 1200L });
//   request.Headers.Add(Agent.Header, Agent.HeaderValue(pcactn)); // any HttpClient
//
// Not thread-safe: counters are handed out in order, so use one Agent per thread or synchronize around Act.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public sealed class Agent
{
    /// <summary>The request header the native middleware reads.</summary>
    public const string Header = "PCA-Action";

    public SuiteKey Signer { get; }
    public string Aud { get; }
    public JD Grant { get; }
    public IReadOnlyList<object?> Chain { get; }
    /// <summary>The last counter used; the next action uses <c>Counter + 1</c>.</summary>
    public long Counter { get; set; }
    public long TtlMs { get; set; } = Issue.DefaultTtlMs;
    public Func<long> Clock { get; set; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public bool Nonces { get; set; } = true;
    Plan? _plan;

    /// <param name="chain">The capability chain starting at the grant; null means <c>[grant]</c>.</param>
    public Agent(SuiteKey signer, string aud, JD grant, IEnumerable<object?>? chain = null, long counter = 0)
    {
        if (string.IsNullOrEmpty(aud)) throw new ArgumentException("Agent: aud (the resource server / instance id) is required");
        Signer = signer;
        Aud = aud;
        Grant = grant;
        Chain = (chain ?? new object?[] { grant }).ToList();
        Counter = counter;
    }

    /// <summary>Commit a plan locally; the returned root is what a server must echo if the plan is registered with it.</summary>
    public Plan CommitPlan(IEnumerable<JD> nodes) => _plan = Issue.CommitPlan(nodes);

    JD Build(Plan p, string nodeId, JD? prms, JD? slots)
    {
        JD? Map(string k) => slots?.GetValueOrDefault(k) as JD;
        var next = Counter + 1;
        var spec = new ActSpec
        {
            Grant = Grant, Chain = new JL(Chain), Plan = p, NodeId = nodeId, Params = prms, Counter = next, Signer = Signer, Aud = Aud,
            Iat = Clock(), TtlMs = TtlMs,
            Nonce = slots?.GetValueOrDefault("nonce") as string ?? (Nonces ? Issue.RandomB64u(16) : null),
            Caution = slots?.GetValueOrDefault("caution"), RationaleCommitment = slots?.GetValueOrDefault("rationale_commitment") as string,
            ToolBinding = slots?.GetValueOrDefault("tool_binding") as string, ProhibitionEvidence = slots?.GetValueOrDefault("prohibition_evidence"),
            ProgressStep = Map("progress_step"), Intent = Map("intent"), IntentSession = Map("intent_session"), FreshAt = Map("fresh_at"),
            Provenance = Map("provenance"), Attestation = Map("attestation"), Freshness = Map("freshness"), RiskClaim = Map("risk_claim"),
        };
        var outp = Issue.BuildPCActn(spec);
        Counter = next; // monotonic: a counter is never reused, even if the call later fails
        return outp;
    }

    /// <summary>Act on node <paramref name="nodeId"/> of the committed plan. <paramref name="slots"/> carries the optional signed members (caution, intent, fresh_at, ...).</summary>
    public JD ActNode(string nodeId, JD? prms = null, JD? slots = null) =>
        Build(_plan ?? throw new InvalidOperationException("CommitPlan() first"), nodeId, prms, slots);

    /// <summary>Act on one verb and resource with an ad-hoc single-node plan. Use <see cref="CommitPlan"/> and <see cref="ActNode"/> when the
    /// server requires the plan to be registered first.</summary>
    public JD Act(string verb, string resource, JD? prms = null, JD? slots = null)
    {
        var id = "n" + (Counter + 1);
        var node = new JD { ["id"] = id, ["verb"] = verb, ["resource"] = resource, ["params_digest"] = Pca.ParamsDigest(prms) };
        return Build(Issue.CommitPlan(new[] { node }), id, prms, slots);
    }

    /// <summary>Delegate a narrower authority to a sub-agent. The child hop is signed by this agent; the returned Agent signs with
    /// <paramref name="child"/> (its counter starts at 0) over the extended chain.</summary>
    public Agent Delegate(SuiteKey child, JL? addedCaveats = null)
    {
        if (child.Ed == null) throw new ArgumentException("a delegate holder needs an Ed25519 identity");
        var hop = Issue.Delegate((JD)Chain[^1]!, child.Ed.Id, addedCaveats, Signer, child.PqPk);
        var a = new Agent(child, Aud, Grant, Chain.Append(hop), 0) { TtlMs = TtlMs, Clock = Clock, Nonces = Nonces };
        return a;
    }

    /// <summary>The header value for a PCActn.</summary>
    public static string HeaderValue(JD pcactn) => Issue.Header(pcactn);

    /// <summary>The JSON body <c>{"pcactn": ...}</c> that the Atlas <c>POST /v1/pca/actions</c> endpoint takes.</summary>
    public static string ActionsBody(JD pcactn) => Pca.Canonicalize(new JD { ["pcactn"] = pcactn });
}
