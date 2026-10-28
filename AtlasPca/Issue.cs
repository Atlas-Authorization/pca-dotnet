// The producer side of PCA: everything an agent or an issuer needs to MAKE a proof, with the same wire as the TypeScript reference
// (@atlasauth/pca). Root grants, delegation, plans, PCActns, and the signed artifacts (discharges, narrow blocks, escalation answers,
// passports, workflow commitments and step receipts, read grants).
//
// Values are the verifier's JSON model: Dictionary<string, object?> / List<object?> / string / bool / long / int / null, and a Num for a
// fractional number (for example new Num("0.5")). Everything signed passes through the STRICT canonical form, so an out-of-profile value
// throws instead of producing a proof no verifier would accept.
using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The result of <see cref="Issue.MintGrant"/>.</summary>
public sealed record MintedGrant(JD Grant, string GoalCommit, string GoalSalt);

/// <summary>A committed plan: its Merkle root and an inclusion proof for each node.</summary>
public sealed class Plan
{
    public string Root { get; }
    public IReadOnlyList<JD> Nodes { get; }
    readonly List<byte[]> _leaves;
    internal Plan(string root, List<JD> nodes, List<byte[]> leaves) { Root = root; Nodes = nodes; _leaves = leaves; }

    public JD ProofFor(string nodeId)
    {
        var idx = -1;
        for (var i = 0; i < Nodes.Count; i++) if (Equals(Nodes[i].GetValueOrDefault("id"), nodeId)) idx = i;
        if (idx < 0) throw new ArgumentException($"commitPlan: unknown node {nodeId}");
        var path = new JL();
        Prove(_leaves, idx, path);
        return new JD { ["index"] = (long)idx, ["size"] = (long)_leaves.Count, ["path"] = path };
    }

    static void Prove(List<byte[]> hs, int idx, JL outp)
    {
        if (hs.Count == 1) return;
        var k = (int)Pca.Split(hs.Count);
        if (idx < k)
        {
            Prove(hs.GetRange(0, k), idx, outp);
            outp.Add(new JD { ["side"] = "R", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(k, hs.Count - k))) });
        }
        else
        {
            Prove(hs.GetRange(k, hs.Count - k), idx - k, outp);
            outp.Add(new JD { ["side"] = "L", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(0, k))) });
        }
    }
}

/// <summary>Inputs of <see cref="Issue.BuildPCActn"/>. Only Grant, Chain, Plan, NodeId, Counter, Signer and Aud are required.</summary>
public sealed class ActSpec
{
    public JD Grant = new();
    public JL Chain = new();
    public Plan Plan = null!;
    public string NodeId = "";
    public JD? Params;
    public long Counter;
    public SuiteKey Signer = null!;
    /// <summary>The resource server / Atlas instance this action is FOR.</summary>
    public string Aud = "";
    public long? Iat, Exp, TtlMs;
    public string? Nonce;
    /// <summary>A number in [0,1] (a <see cref="Num"/> for a fraction): can only RAISE the verifier's risk.</summary>
    public object? Caution;
    public string? RationaleCommitment, ToolBinding;
    public JD? ProgressStep, Intent, IntentSession, FreshAt, Provenance, Attestation, Freshness, RiskClaim;
    public object? ProhibitionEvidence;
}

public static class Issue
{
    public const long DefaultTtlMs = 20L * 60_000L;
    public const string EnvelopeCaveat = "envelope";
    const string GoalCommitDomain = "atlas-pca/goal/v1\0";
    const string PassportType = "atlas-pca/passport";

    /// <summary>The reference default risk policy (the same numbers as <c>DEFAULT_RISK_POLICY</c> in the TypeScript package).</summary>
    public static JD DefaultRiskPolicy() => new()
    {
        ["weights"] = new JD { ["alpha"] = new Num("0.25"), ["beta"] = new Num("0.2"), ["gamma"] = new Num("0.2"), ["delta"] = new Num("0.2"), ["epsilon"] = new Num("0.1"), ["zeta"] = new Num("0.05") },
        ["theta1"] = new Num("0.25"), ["theta2"] = new Num("0.6"), ["kappa"] = 1L, ["lambda"] = new Num("0.0005"), ["rho"] = new Num("0.5"), ["bMax"] = 1L,
    };

    /// <summary>A deep copy through the strict canonical form (throws on anything out of profile); numbers come back as <see cref="Num"/>.</summary>
    public static object? Norm(object? v) => Pca.ParseStrict(Pca.Canonicalize(v));
    public static JD NormJ(JD v) => (JD)Norm(v)!;
    public static JL NormL(JL v) => (JL)Norm(v)!;

    public static string RandomB64u(int n) => Pca.B64u(RandomNumberGenerator.GetBytes(n));

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    // ---- capability chain ----------------------------------------------------------------------------------------

    static JD Seal(string issuer, string holder, JL caveats, string? parent, string? holderPq, SuiteKey signer)
    {
        var body = new JD { ["issuer"] = issuer, ["holder"] = holder, ["caveats"] = caveats, ["parent"] = parent };
        if (holderPq != null) body["holder_pq"] = holderPq;
        var pqPk = signer.PqPk;
        if (signer.Alg != "ed25519") { body["alg"] = signer.Alg; body["pq_pk"] = pqPk; }
        var digest = Pca.HashCanonical(body);
        var (sig, pqSig) = signer.Sign(Pca.Cat(Utf8(Pca.CapDomain), Pca.B64uDecode(digest, 32)!));
        var cap = new JD { ["id"] = digest, ["issuer"] = issuer, ["holder"] = holder, ["caveats"] = caveats, ["body_digest"] = digest, ["sig"] = sig };
        if (parent != null) cap["parent"] = parent;
        if (holderPq != null) cap["holder_pq"] = holderPq;
        if (signer.Alg != "ed25519")
        {
            cap["alg"] = signer.Alg;
            cap["pq_pk"] = pqPk;
            if (pqSig != null) cap["pq_sig"] = pqSig;
        }
        return cap;
    }

    static string? Commitment(string? holderPqPk) => holderPqPk == null ? null : Pca.HolderPqCommitment(holderPqPk);

    /// <summary>A root capability signed by the principal. <paramref name="holderPqPk"/> (b64u, optional) is the holder's post-quantum public key,
    /// committed into the body as <c>holder_pq</c>: required for a hybrid / pure-PQ agent.</summary>
    public static JD MintRoot(SuiteKey principal, string holder, string? holderPqPk, JL caveats)
    {
        if (principal.Ed == null) throw new ArgumentException("a root issuer needs an Ed25519 identity");
        return Seal(principal.Ed.Id, holder, NormL(caveats), null, Commitment(holderPqPk), principal);
    }

    /// <summary>The salted goal commitment: <c>b64u(sha256(canonical({d, goal, salt})))</c>.</summary>
    public static string GoalCommit(string goal, string salt) => Pca.HashCanonical(new JD { ["d"] = GoalCommitDomain, ["goal"] = goal, ["salt"] = salt });

    /// <summary>A root intent grant: a root capability whose first caveat is the <c>envelope</c>. <paramref name="envelope"/> needs <c>predicates</c>,
    /// <c>caveats</c> and <c>risk_policy</c>; <c>agent_binding</c> defaults to <c>{}</c> and <c>objective_risk</c>, <c>progress</c>, <c>units</c>,
    /// <c>tighten</c>, <c>model_polarity</c>, <c>template_ref</c> and <c>actions</c> (action-definition pins) pass through. Only the salted hash of
    /// <paramref name="goal"/> goes in the grant.</summary>
    public static MintedGrant MintGrant(SuiteKey principal, string holder, string? holderPqPk, JD envelope, string goal, string? salt = null)
    {
        if (string.IsNullOrEmpty(goal)) throw new ArgumentException("mintGrant: goal required");
        foreach (var k in new[] { "predicates", "caveats", "risk_policy" })
            if (envelope.GetValueOrDefault(k) == null) throw new ArgumentException($"mintGrant: envelope.{k} is required");
        var s = salt ?? RandomB64u(16);
        var commit = GoalCommit(goal, s);
        var env = new JD { ["type"] = EnvelopeCaveat, ["goal_commit"] = commit };
        foreach (var (k, v) in envelope) if (k != "goal_commit" && k != "type") env[k] = v;
        if (!env.ContainsKey("agent_binding")) env["agent_binding"] = new JD();
        return new MintedGrant(MintRoot(principal, holder, holderPqPk, new JL { env }), commit, s);
    }

    /// <summary>Child capability: caveats are the parent's followed by <paramref name="added"/> (append-only); signed by the parent's holder.</summary>
    public static JD Delegate(JD parent, string toHolder, JL? added, SuiteKey signer, string? holderPqPk = null)
    {
        var cav = new JL();
        cav.AddRange(NormL((JL)parent["caveats"]!));
        cav.AddRange(NormL(added ?? new JL()));
        var hp = holderPqPk != null ? Commitment(holderPqPk) : toHolder == (string)parent["holder"]! ? parent.GetValueOrDefault("holder_pq") as string : null;
        return Seal((string)parent["holder"]!, toHolder, cav, Pca.CapHash(parent), hp, signer);
    }

    /// <summary>Like <see cref="Delegate"/> with the holder unchanged: only narrows.</summary>
    public static JD Attenuate(JD parent, JL added, SuiteKey signer) => Delegate(parent, (string)parent["holder"]!, added, signer);

    // ---- plans ----------------------------------------------------------------------------------------------------

    /// <summary>Plan node: <c>{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}</c>.</summary>
    public static Plan CommitPlan(IEnumerable<JD> nodes)
    {
        var ids = new HashSet<string>();
        var leaves = new List<byte[]>();
        var copy = new List<JD>();
        foreach (var n in nodes)
        {
            if (n.GetValueOrDefault("id") is not string id || !ids.Add(id)) throw new ArgumentException($"commitPlan: missing or duplicate node id {n.GetValueOrDefault("id")}");
            leaves.Add(Pca.LeafHash(Pca.PlanLeaf(id, n, Pca.ConditionsDigest(n.GetValueOrDefault("pre"), n.GetValueOrDefault("post")))));
            copy.Add(n);
        }
        if (leaves.Count == 0) throw new ArgumentException("commitPlan: empty plan");
        return new Plan(Pca.B64u(Pca.Build(leaves)), copy, leaves);
    }

    // ---- PCActn ---------------------------------------------------------------------------------------------------

    static void Put(JD m, string k, object? v) { if (v != null) m[k] = v; }

    public static JD BuildPCActn(ActSpec s)
    {
        if (string.IsNullOrEmpty(s.Aud)) throw new ArgumentException("buildPCActn: aud (audience) is required");
        var node = s.Plan.Nodes.FirstOrDefault(n => Equals(n.GetValueOrDefault("id"), s.NodeId)) ?? throw new ArgumentException($"buildPCActn: unknown plan node {s.NodeId}");
        var digest = Pca.ParamsDigest(s.Params);
        if (node.GetValueOrDefault("params_digest") != null && !Equals(node["params_digest"], digest))
            throw new ArgumentException($"buildPCActn: params do not match plan node {s.NodeId}'s params_digest");
        var iat = s.Iat ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var exp = s.Exp ?? iat + (s.TtlMs ?? DefaultTtlMs);
        var body = new JD
        {
            ["ver"] = 2L,
            ["action"] = new JD { ["verb"] = node.GetValueOrDefault("verb"), ["resource"] = node.GetValueOrDefault("resource"), ["params_digest"] = digest, ["reversibility_class"] = node.GetValueOrDefault("reversibility_class") ?? Pca.DefaultRev },
            ["grant_ref"] = s.Grant["id"],
            ["cap_chain"] = s.Chain,
            ["plan"] = new JD { ["root"] = s.Plan.Root, ["inclusion_proof"] = s.Plan.ProofFor(s.NodeId), ["node_id"] = s.NodeId, ["conditions_digest"] = Pca.ConditionsDigest(node.GetValueOrDefault("pre"), node.GetValueOrDefault("post")) },
            ["attestation"] = s.Attestation ?? new JD { ["quote_digest"] = "", ["epoch"] = 0L, ["model_id"] = "unattested", ["measurement"] = "", ["operator"] = "unattested" },
            ["provenance"] = s.Provenance ?? new JD { ["causal_hash"] = "", ["taint_level"] = 0L, ["trusted_refs"] = new JL() },
            ["freshness"] = s.Freshness ?? new JD { ["beacon_ref"] = "", ["epoch"] = 0L, ["accumulator_witness"] = "" },
            ["counter"] = s.Counter,
            ["risk_claim"] = s.RiskClaim ?? new JD { ["r"] = 0L, ["inputs"] = new JD() },
            ["aud"] = s.Aud,
            ["iat"] = iat,
            ["exp"] = exp,
        };
        Put(body, "nonce", s.Nonce);
        Put(body, "caution", s.Caution);
        Put(body, "rationale_commitment", s.RationaleCommitment);
        Put(body, "progress_step", s.ProgressStep);
        Put(body, "prohibition_evidence", s.ProhibitionEvidence);
        Put(body, "tool_binding", s.ToolBinding);
        Put(body, "intent", s.Intent);
        Put(body, "intent_session", s.IntentSession);
        Put(body, "fresh_at", s.FreshAt);
        if (s.Signer.Alg != "ed25519") { body["alg"] = s.Signer.Alg; body["pq_pk"] = s.Signer.PqPk; }
        var (sig, pqSig) = s.Signer.Sign(Pca.ThresholdMessage(body));
        body["sig"] = sig;
        if (pqSig != null) body["pq_sig"] = pqSig;
        return body;
    }

    /// <summary>The canonical JSON text of a PCActn (what is sent).</summary>
    public static string Encode(JD pcactn) => Pca.Canonicalize(pcactn);

    /// <summary>The <c>PCA-Action</c> header value: the unpadded base64url of the PCActn JSON.</summary>
    public static string Header(JD pcactn) => Pca.B64u(Utf8(Encode(pcactn)));

    // ---- signed artifacts (discharge, narrow, escalation answer, ...) ---------------------------------------------

    /// <summary>Sign an artifact body under a suite: the signature covers <c>utf8(domain) || strictCanonical(body)</c> where a non-default suite
    /// adds <c>alg</c> and <c>pq_pk</c> to the SIGNED body; a hybrid also returns <c>pq_sig</c>.</summary>
    public static JD SignArtifact(string domain, JD body, SuiteKey signer)
    {
        var full = new JD(NormJ(body));
        if (signer.Alg != "ed25519") { full["alg"] = signer.Alg; full["pq_pk"] = signer.PqPk; }
        var (sig, pqSig) = signer.Sign(IntentArtifacts.ArtifactMessage(domain, full));
        full["sig"] = sig;
        if (pqSig != null) full["pq_sig"] = pqSig;
        return full;
    }

    static JD Checked(string what, JD signed, string? err) => err == null ? signed : throw new ArgumentException($"{what}: {err}");

    /// <summary>A third-party discharge for a <c>needs_discharge</c> caveat. Throws on a malformed body (a signer never emits a weaker artifact).</summary>
    public static JD SignDischarge(JD body, SuiteKey issuer)
    {
        var s = SignArtifact(CaveatLang.DischargeDomain, body, issuer);
        return Checked("signDischarge", s, CaveatLang.DischargeShapeError(s));
    }

    /// <summary>Build and sign a discharge. <paramref name="bind"/> is <c>"chain_hop"</c> or <c>"action"</c> (then <paramref name="actionDigest"/> is
    /// <see cref="CaveatLang.DischargeActionDigest"/> of the PCActn). <paramref name="issuerLabel"/> is the label the caveat names, not a key.</summary>
    public static JD Discharge(SuiteKey issuer, string caveatId, string issuerLabel, JD hop, string bind, string? actionDigest, JD? claims, long iat, long notAfter)
    {
        var b = new JD
        {
            ["v"] = 1L, ["kind"] = "pca-discharge", ["caveat_id"] = caveatId, ["issuer"] = issuerLabel, ["cap_hash"] = Pca.CapHash(hop), ["bind"] = bind,
            ["claims"] = claims ?? new JD(), ["iat"] = iat, ["not_after"] = notAfter, ["nonce"] = RandomB64u(16),
        };
        if (bind == "action") b["action_digest"] = actionDigest;
        return SignDischarge(b, issuer);
    }

    /// <summary>A holder-signed per-action self-attenuation that rides beside the PCActn (no new hop).</summary>
    public static JD SignNarrow(JD body, SuiteKey holder)
    {
        var s = SignArtifact(CaveatLang.NarrowDomain, body, holder);
        return Checked("signNarrow", s, CaveatLang.NarrowShapeError(s));
    }

    public static JD Narrow(SuiteKey holder, JD leafHop, JL caveats, string? actionDigest, long iat, long notAfter)
    {
        var b = new JD
        {
            ["v"] = 1L, ["kind"] = "pca-narrow", ["cap_hash"] = Pca.CapHash(leafHop), ["holder"] = holder.Ed!.Id, ["caveats"] = caveats,
            ["iat"] = iat, ["not_after"] = notAfter, ["nonce"] = RandomB64u(16),
        };
        if (actionDigest != null) b["action_digest"] = actionDigest;
        return SignNarrow(b, holder);
    }

    /// <summary>The principal's signed answer to an escalation. Throws on a malformed body.</summary>
    public static JD SignEscalationAnswer(JD body, SuiteKey principal)
    {
        var s = SignArtifact(Escalation.AnswerDomain, body, principal);
        return Checked("signEscalationAnswer", s, Escalation.AnswerShapeError(s));
    }

    /// <summary>Answer an escalation: bound to exactly this grant (policy), this PCActn (action) and this history head. <paramref name="renderDigest"/>
    /// (optional) is the digest of the canonical approval render the principal saw.</summary>
    public static JD EscalationAnswer(SuiteKey principal, JD grant, JD pcactn, long? lastCounter, bool allow, long iat, long expiresAt, string? renderDigest = null)
    {
        var b = new JD
        {
            ["v"] = 1L, ["kind"] = "pca-escalation-answer", ["principal"] = principal.Ed!.Id, ["policy_digest"] = Escalation.PolicyDigest(grant),
            ["action_digest"] = Escalation.ActionDigest(pcactn), ["history_head"] = Escalation.HistoryHead(lastCounter), ["decision"] = allow ? "allow" : "deny",
            ["iat"] = iat, ["expires_at"] = expiresAt, ["nonce"] = RandomB64u(16),
        };
        if (renderDigest != null) b["render_digest"] = renderDigest;
        return SignEscalationAnswer(b, principal);
    }

    // ---- Ed25519 body signatures (workflow, receipts, read grants) ------------------------------------------------

    /// <summary><c>b64u(Ed25519(domain || strictCanonical(body)))</c>.</summary>
    public static string SignBody(EdKey key, string domain, object? body) => Pca.B64u(key.Sign(Pca.Cat(Utf8(domain), Pca.Canon(body))));

    /// <summary>Sign a workflow commitment: <c>{body, sig}</c>. Throws on a malformed body, a cycle, or a body naming another principal.</summary>
    public static JD SignWorkflow(EdKey principal, JD body)
    {
        var b = NormJ(body);
        if (Workflow.DagErrorOf(b) != null) throw new ArgumentException("signWorkflow: malformed workflow");
        if (!Equals(b.GetValueOrDefault("principal"), principal.Id)) throw new ArgumentException("signWorkflow: principal is not the signer");
        return new JD { ["body"] = b, ["sig"] = SignBody(principal, Workflow.WorkflowDomain, b) };
    }

    /// <summary>Sign a step receipt (resource server). <paramref name="prev"/> is the previous receipt of the same workflow, null for the first.</summary>
    public static JD SignStepReceipt(EdKey rs, JD workflow, string step, string outcome, string paramsDigest, JD outputs, long issuedAt, JD? prev)
    {
        var seq = prev == null ? 0L : (prev["seq"] is Num sn ? long.Parse(sn.Raw, System.Globalization.CultureInfo.InvariantCulture) : Convert.ToInt64(prev["seq"], System.Globalization.CultureInfo.InvariantCulture)) + 1;
        var b = NormJ(new JD
        {
            ["v"] = 1L, ["wf"] = Workflow.WorkflowDigest(workflow), ["step"] = step, ["seq"] = seq, ["prev"] = prev == null ? null : Workflow.ReceiptRef(prev),
            ["outcome"] = outcome, ["params_digest"] = paramsDigest, ["outputs"] = outputs, ["issued_at"] = issuedAt, ["signer"] = rs.Id,
        });
        b["sig"] = SignBody(rs, Workflow.ReceiptDomain, b);
        return b;
    }

    /// <summary>A receipt output for a scalar <paramref name="value"/>; <paramref name="num"/> is carried only for integers an edge may compare.</summary>
    public static JD WfOutput(object? value, IEnumerable<string>? labels = null, string? unit = null, bool num = false)
    {
        var ls = (labels ?? Array.Empty<string>()).OrderBy(x => x, StringComparer.Ordinal).Select(x => (object?)x).ToList();
        return new JD { ["digest"] = Workflow.ValueDigest(value), ["num"] = (num && (value is long || value is int)) ? value : null, ["unit"] = unit, ["labels"] = ls };
    }

    /// <summary>Sign a read grant: <c>{body, sig}</c>.</summary>
    public static JD SignReadGrant(EdKey principal, JD body)
    {
        var b = NormJ(body);
        if (!ReadSide.ValidReadGrantBody(b) || !Equals(b.GetValueOrDefault("principal"), principal.Id)) throw new ArgumentException("signReadGrant: malformed grant");
        return new JD { ["body"] = b, ["sig"] = SignBody(principal, ReadSide.GrantDomain, b) };
    }

    // ---- passports ------------------------------------------------------------------------------------------------

    /// <summary>Content fingerprint over a passport's identity fields (its <c>id</c>).</summary>
    public static string PassportFingerprint(JD p) => Pca.HashCanonical(new JD
    {
        ["d"] = "atlas-pca/passport/v1", ["model_id"] = p.GetValueOrDefault("model_id"), ["weights_digest"] = p.GetValueOrDefault("weights_digest"),
        ["system_prompt_digest"] = p.GetValueOrDefault("system_prompt_digest"), ["tool_manifest_digest"] = p.GetValueOrDefault("tool_manifest_digest"),
        ["runtime_measurement"] = p.GetValueOrDefault("runtime_measurement"), ["operator"] = p.GetValueOrDefault("operator"), ["hardware_rooted"] = p.GetValueOrDefault("hardware_rooted"),
    });

    /// <summary>Fill <c>id</c> from the fingerprint of the identity fields.</summary>
    public static JD IssuePassport(JD identity) => new(identity) { ["id"] = PassportFingerprint(identity) };

    /// <summary>Sign a passport for <paramref name="subject"/> (the agent's Ed25519 key id). <paramref name="evidence"/> is required for a hardware-rooted passport.</summary>
    public static JD SignPassport(JD passport, SuiteKey issuer, string subject, long iat, long exp, long? nbf = null, JD? evidence = null)
    {
        if (!Equals(passport.GetValueOrDefault("id"), PassportFingerprint(passport))) throw new ArgumentException("signPassport: passport.id is not the fingerprint of its identity (use IssuePassport)");
        if (passport.GetValueOrDefault("hardware_rooted") is true && evidence == null) throw new ArgumentException("signPassport: hardware_rooted requires attestation evidence (fail closed)");
        var nb = nbf ?? iat;
        if (exp <= nb) throw new ArgumentException("signPassport: exp must be after nbf");
        var body = new JD { ["typ"] = PassportType, ["ver"] = 1L, ["passport"] = passport, ["iss"] = issuer.Ed!.Id, ["sub"] = subject, ["iat"] = iat, ["nbf"] = nb, ["exp"] = exp };
        if (evidence != null)
        {
            var ev = new JD(evidence);
            if (!ev.ContainsKey("at")) ev["at"] = iat;
            body["evidence"] = ev;
        }
        if (issuer.Alg != "ed25519") { body["alg"] = issuer.Alg; body["pq_pk"] = issuer.PqPk; }
        var n = NormJ(body);
        var (sig, pqSig) = issuer.Sign(Pca.Cat(Utf8(Passports.SigDomain), Pca.Canon(n)));
        n["sig"] = sig;
        if (pqSig != null) n["pq_sig"] = pqSig;
        return n;
    }

    // ---- fresh_at token and aggregate grant -----------------------------------------------------------------------

    /// <summary>A signed consistency token (<c>fresh_at</c>) from the resource server. <paramref name="state"/> holds revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest.</summary>
    public static JD SignFreshAt(EdKey rs, string scope, JD state, long issuedAt)
    {
        var b = new JD { ["v"] = 1L, ["scope"] = scope };
        foreach (var k in new[] { "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest" }) b[k] = state.GetValueOrDefault(k);
        b["issued_at"] = issuedAt;
        b["signer"] = rs.Id;
        var n = NormJ(b);
        n["sig"] = SignBody(rs, FreshAt.Domain, n);
        return n;
    }

    /// <summary>Sign an aggregate (differential-privacy) read grant: <c>{body, sig}</c>.</summary>
    public static JD SignAggregateGrant(EdKey principal, JD body)
    {
        var b = NormJ(body);
        if (!ReadVault.ValidAggregateGrantBody(b) || !Equals(b.GetValueOrDefault("principal"), principal.Id)) throw new ArgumentException("signAggregateGrant: malformed grant");
        return new JD { ["body"] = b, ["sig"] = SignBody(principal, ReadVault.AggregateDomain, b) };
    }
}
