// Reproduces one case of the producer conformance vectors (producer-vectors.json and producer-pq-vectors.json): the signing side of
// this SDK must emit exactly what the TypeScript reference emits. One entry point serves the tests and the conformance driver.
// Test keys come only from the fixed seeds in the vector files.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ProducerVectors
{
    /// <summary>The post-quantum families of producer-pq-vectors.json this SDK signs (FN-DSA is not one of them).</summary>
    static Dictionary<string, Pq.Prim> Families => new()
    {
        ["ml-dsa-65"] = Pq.Prim.MlDsa65, ["ml-dsa-87"] = Pq.Prim.MlDsa87, ["slh-dsa-sha2-128f"] = Pq.Prim.Slh128f, ["slh-dsa-sha2-256s"] = Pq.Prim.Slh256s,
    };

    sealed class Args
    {
        public readonly JD M, Keys, Pq;
        public Args(JD m, JD keys, JD? pq) { M = m; Keys = keys; Pq = pq ?? new JD(); }

        static ArgumentException Bad(string what) => new("produce: " + what);
        public static string S(JD m, string k) => m.GetValueOrDefault(k) as string ?? throw Bad($"{k} must be a string");
        public static string? OptS(JD m, string k) => m.GetValueOrDefault(k) switch { null => null, string s => s, _ => throw Bad($"{k} must be a string") };
        public static long N(JD m, string k) =>
            IntentJs.IsSafeInteger(m.GetValueOrDefault(k)) ? IntentJs.Lng(m[k]) : throw Bad($"{k} must be an integer");
        public static JD O(JD m, string k) => m.GetValueOrDefault(k) as JD ?? throw Bad($"{k} must be an object");
        public static JD? OptO(JD m, string k) => m.GetValueOrDefault(k) switch { null => null, JD o => o, _ => throw Bad($"{k} must be an object") };
        public static JL L(JD m, string k) => m.GetValueOrDefault(k) as JL ?? throw Bad($"{k} must be an array");
        public static List<JD> Objs(JD m, string k) => L(m, k).Select(x => x as JD ?? throw Bad($"{k} must be an array of objects")).ToList();
        public static List<string> Strs(JD m, string k) => L(m, k).Select(x => x as string ?? throw Bad($"{k} must be an array of strings")).ToList();

        public byte[] Seed(JD m, string k)
        {
            var name = S(m, k);
            return Keys.GetValueOrDefault(name) is JD e && Pca.B64uDecode(e.GetValueOrDefault("seed"), 32) is { } seed ? seed : throw Bad($"no Ed25519 key '{name}'");
        }
        public EdKey Ed(JD m, string k) => EdKey.FromSeed(Seed(m, k));
        /// <summary>A pure post-quantum suite carries no Ed25519 key: the member is null.</summary>
        public EdKey? OptEd(JD m, string k) => m.GetValueOrDefault(k) is null ? null : Ed(m, k);
        public SuiteKey Suite(JD m, string k) => SuiteKey.Ed25519(Ed(m, k));

        /// <summary>The PQ key a member names (null: none).</summary>
        public PqKey? PqKeyOf(JD m, string k)
        {
            if (OptS(m, k) is not { } name) return null;
            var e = Pq.GetValueOrDefault(name) as JD ?? throw Bad($"no post-quantum key '{name}'");
            return KeyGen(S(e, "family"), S(e, "seed"));
        }
    }

    static PqKey KeyGen(string family, string seed)
    {
        if (!Families.TryGetValue(family, out var prim)) throw new ArgumentException($"{AtlasPca.Pq.UnsupportedSuite}: {family}");
        var bytes = Pca.B64uDecode(seed, PqKey.SeedBytes(prim)) ?? throw new ArgumentException($"produce: the {family} seed must be canonical base64url of {PqKey.SeedBytes(prim)} bytes");
        return PqKey.FromSeed(prim, bytes);
    }

    static JD Sig(string s) => new() { ["sig"] = s };

    static RevocationEpochBody Epoch(JD b) => new(Args.S(b, "instance_id"), Args.S(b, "grant_ref"), Args.N(b, "epoch"), Args.N(b, "set_size"), Args.S(b, "root"),
        Args.N(b, "issued_at"), Args.N(b, "not_after"));

    /// <summary>Run one vector case: <paramref name="op"/> and its <paramref name="args"/>, with the file's Ed25519 <paramref name="keys"/>
    /// (<c>{name: {seed, public}}</c>) and, for the post-quantum file, its <paramref name="pqKeys"/>. Returns the JSON output; throws with the
    /// refusal text. An op this SDK does not produce throws <c>unsupported_op: &lt;op&gt;</c>; a suite it does not sign throws
    /// <c>unsupported_suite: &lt;alg&gt;</c>.</summary>
    public static object? Produce(string op, JD args, JD keys, JD? pqKeys = null)
    {
        try { return Run(op, new Args(args, keys, pqKeys)); }
        catch (Exception e) when (e is InvalidCastException or NullReferenceException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw new ArgumentException($"produce: malformed {op} vector: {e.Message}"); // a malformed vector is refused, never a crash
        }
    }

    static object? Run(string op, Args v)
    {
        var a = v.M;
        var b = a.GetValueOrDefault("body") as JD;
        JD Body() => b ?? throw new ArgumentException("produce: body must be an object");
        // the post-quantum file: `alg` names the suite, `pq` the signer's PQ key, `holder_pq` the holder's committed PQ key
        SuiteKey SuiteOf(string edMember) =>
            Args.OptS(a, "alg") is { } alg ? SuiteKey.Create(alg, v.OptEd(a, edMember), v.PqKeyOf(a, "pq")) : v.Suite(a, edMember);
        string? HolderPq() => v.PqKeyOf(a, "holder_pq")?.PkB64u;

        switch (op)
        {
            // ---- producer-vectors.json -----------------------------------------------------------------------------------------------
            case "ed25519_sign":
                {
                    var k = EdKey.FromSeed(Pca.B64uDecode(a.GetValueOrDefault("seed"), 32) ?? throw new ArgumentException("produce: seed must be 32 bytes"));
                    return new JD { ["public"] = k.Id, ["sig"] = Pca.B64u(k.Sign(Encoding.UTF8.GetBytes(Args.S(a, "message_utf8")))) };
                }
            case "goal_commit": return new JD { ["commit"] = Issue.GoalCommit(Args.S(a, "goal"), Args.S(a, "salt")) };
            case "params_digest": return new JD { ["digest"] = Pca.ParamsDigest(a.GetValueOrDefault("params")) };
            case "plan_commit":
                {
                    var nodes = Args.Objs(a, "nodes");
                    var p = Issue.CommitPlan(nodes);
                    var proofs = new JD();
                    foreach (var n in nodes) proofs[Args.S(n, "id")] = p.ProofFor(Args.S(n, "id"));
                    return new JD { ["root"] = p.Root, ["proofs"] = proofs };
                }
            case "mint_grant":
                {
                    var g = Issue.MintGrant(v.Suite(a, "principal"), v.Ed(a, "holder").Id, null, Args.O(a, "envelope"), Args.S(a, "goal"), Args.S(a, "salt"));
                    return new JD { ["grant"] = g.Grant, ["goal_commit"] = g.GoalCommit, ["goal_salt"] = g.GoalSalt };
                }
            case "delegate":
                {
                    var parent = Args.O(a, "parent");
                    var to = a.GetValueOrDefault("to_holder") == null ? Args.S(parent, "holder") : v.Ed(a, "to_holder").Id;
                    return Issue.Delegate(parent, to, Args.L(a, "added_caveats"), v.Suite(a, "signer"));
                }
            case "act":
                {
                    var s = new ActSpec
                    {
                        Grant = Args.O(a, "grant"), Chain = Args.L(a, "chain"), Plan = Issue.CommitPlan(Args.Objs(a, "plan")), NodeId = Args.S(a, "node_id"),
                        Params = Args.OptO(a, "params"), Counter = Args.N(a, "counter"), Signer = v.Suite(a, "signer"), Aud = Args.S(a, "aud"),
                        Iat = Args.N(a, "iat"), Exp = Args.N(a, "exp"), Nonce = Args.OptS(a, "nonce"), Caution = a.GetValueOrDefault("caution"),
                        RationaleCommitment = Args.OptS(a, "rationale_commitment"), ToolBinding = Args.OptS(a, "tool_binding"), FreshAt = Args.OptO(a, "fresh_at"),
                    };
                    var p = Issue.BuildPCActn(s);
                    return new JD { ["pcactn"] = p, ["threshold_message"] = Pca.B64u(Pca.ThresholdMessage(p)), ["header"] = Issue.Header(p) };
                }
            case "fresh_at": return Issue.SignFreshAt(v.Ed(a, "signer"), Args.S(a, "scope"), Args.O(a, "state"), Args.N(a, "issued_at"));
            case "escalation_digests":
                return new JD
                {
                    ["policy_digest"] = Escalation.PolicyDigest(Args.O(a, "grant")), ["action_digest"] = Escalation.ActionDigest(Args.O(a, "pcactn")),
                    ["history_head"] = Escalation.HistoryHead(a.GetValueOrDefault("last_counter") == null ? null : Args.N(a, "last_counter")),
                };
            case "sign_escalation_answer": return Issue.SignEscalationAnswer(Body(), v.Suite(a, "signer"));
            case "sign_discharge": return Issue.SignDischarge(Body(), v.Suite(a, "signer"));
            case "discharge_digest": return new JD { ["digest"] = CaveatLang.DischargeDigest(a.GetValueOrDefault("discharge")) };
            case "sign_narrow": return Issue.SignNarrow(Body(), v.Suite(a, "signer"));
            case "sign_passport":
                {
                    var identity = Args.O(a, "identity");
                    var pp = Issue.IssuePassport(identity);
                    var signed = Issue.SignPassport(pp, v.Suite(a, "issuer"), v.Ed(a, "subject").Id, Args.N(identity, "issued_at"), Args.N(a, "exp"));
                    return new JD { ["passport"] = pp, ["signed"] = signed };
                }
            case "sign_workflow": return Issue.SignWorkflow(v.Ed(a, "signer"), Body());
            case "sign_step_receipt":
                return Issue.SignStepReceipt(v.Ed(a, "signer"), Args.O(a, "workflow"), Args.S(a, "step"), Args.S(a, "outcome"), Args.S(a, "params_digest"),
                    Args.O(a, "outputs"), Args.N(a, "issued_at"), Args.OptO(a, "prev"));
            case "sign_read_grant": return Issue.SignReadGrant(v.Ed(a, "signer"), Body());
            case "sign_aggregate_grant": return Issue.SignAggregateGrant(v.Ed(a, "signer"), Body());
            case "sign_revocation_epoch": return RevocationFreshness.SignEpoch(v.Seed(a, "signer"), Epoch(Body()));
            case "sign_undo_token": return UndoWindows.SignToken(Args.O(a, "record"), v.Seed(a, "signer"));
            case "sign_undo_receipt": return UndoWindows.SignReceipt(Body(), v.Seed(a, "signer"));
            case "sign_contract": return Contracts.Sign(Args.O(a, "contract"), v.Ed(a, "signer"));
            case "sign_contract_reset": return Sig(ContractEnforcer.SignReset(v.Ed(a, "signer"), Args.S(a, "contract_id"), Args.N(a, "seq")));
            case "sign_constitution": return SafetyEvidence.SignConstitution(Args.O(a, "constitution"), v.Ed(a, "signer"));
            case "sign_safety_evidence":
                {
                    var k = v.Ed(a, "signer");
                    return SafetyEvidence.Sign(a.GetValueOrDefault("evidence"), k, k.Id);
                }
            case "sign_threshold_share":
                {
                    // an out-of-range t reaches the signer's own refusal (the reference's text); clamped only so the cast cannot wrap
                    var t = (int)Math.Clamp(Args.N(a, "t"), 0, 4);
                    return Signers.SignThresholdShare(Args.S(a, "role"), v.Suite(a, "signer"), B64(a, "message"), Args.L(a, "signer_set"), t);
                }
            case "sign_prepared_share": return Signers.SignPreparedShare(Args.S(a, "role"), v.Suite(a, "signer"), B64(a, "prepared"));
            case "sign_pq_binding":
                {
                    // a non-integer epoch is refused by the signer, with the reference's text
                    var e = a.GetValueOrDefault("epoch");
                    var epoch = IntentJs.IsSafeInteger(e) ? IntentJs.Lng(e) : 0;
                    return Signers.SignPqBinding(v.Ed(a, "signer"), Args.S(a, "pq_pk"), epoch, Args.OptS(a, "aud") ?? "");
                }
            case "sign_caution": return Signers.SignCaution(Body(), v.Ed(a, "signer"));
            case "sign_heartbeat": return Signers.SignHeartbeat(Body(), v.Ed(a, "signer"));
            case "prov_recorder": return Recorder(v);
            case "sign_mesh_action": return Sig(Signers.SignMeshAction(Args.Objs(a, "chain"), Args.O(a, "action"), v.Ed(a, "signer")));
            case "sign_session_root": return Signers.SignSessionRoot(Body(), v.Suite(a, "signer"));
            case "mint_session_grant":
                {
                    var g = Signers.MintSessionGrant(v.Suite(a, "principal"), v.Ed(a, "holder").Id, Args.S(a, "session"), Args.N(a, "seq"), Args.S(a, "root"),
                        Args.S(a, "map_digest"), Args.L(a, "predicates"), prev: Args.OptS(a, "prev"), mapForm: Args.OptS(a, "map_form"),
                        caveats: a.GetValueOrDefault("caveats") as JL, salt: Args.OptS(a, "salt"));
                    return new JD { ["grant"] = g.Grant, ["goal_salt"] = g.GoalSalt };
                }
            case "sign_action_schema": return Signers.SignActionSchema(Args.O(a, "doc"), Args.S(a, "kid"), v.Suite(a, "signer"));
            case "sign_intent_required": return Signers.SignIntentRequired(Body(), Args.S(a, "kid"), v.Suite(a, "signer"));
            case "sign_progress_step": return Signers.SignProgressStep(Args.O(a, "step"), v.Ed(a, "signer"));
            case "sign_labels": return Signers.SignLabels(Body(), v.Suite(a, "signer"));
            case "sign_fact": return Signers.SignFact(Body(), v.Suite(a, "signer"));
            case "sign_offer_set": return Signers.SignOfferSet(Body(), v.Suite(a, "signer"));
            case "sign_read_receipt":
                return Signers.SignReadReceipt(v.Ed(a, "signer"), Args.O(a, "grant"), Args.S(a, "verb"), Args.S(a, "resource"), Args.S(a, "purpose"),
                    Args.O(a, "fields"), Args.Strs(a, "labels"), Args.N(a, "issued_at"), Args.OptO(a, "prev"));
            case "sign_template": return PolicyAuthoring.SignTemplate(Args.O(a, "def"), v.Ed(a, "signer"));
            case "sign_tighten": return PolicyAuthoring.SignTighten(Args.O(a, "overlay"), v.Ed(a, "signer"));
            case "parse_limit": return Facade.ParseLimit(a.GetValueOrDefault("limit") as string ?? "").ToJson();
            case "compile_policy":
                return Facade.CompilePolicy(new PolicyOptions
                {
                    Permissions = a.GetValueOrDefault("permissions") as JD ?? throw new ArgumentException("compilePolicy: permissions must be an object"),
                    Limits = Limits(a), BudgetModel = Args.OptS(a, "budget_model"), Now = Args.N(a, "now"),
                }).ToJson();
            case "facade_act": return FacadeAct(v);

            // ---- producer-pq-vectors.json --------------------------------------------------------------------------------------------
            case "pq_keygen": return new JD { ["public"] = KeyGen(Args.S(a, "family"), Args.S(a, "seed")).PkB64u };
            case "suite_sign":
                {
                    var (sig, pqSig) = SuiteOf("ed").Sign(Encoding.UTF8.GetBytes(Args.S(a, "message_utf8")));
                    var r = new JD { ["sig"] = sig };
                    if (pqSig != null) r["pq_sig"] = pqSig;
                    return r;
                }
            case "mint_root_suite": return Issue.MintRoot(SuiteOf("principal"), v.Ed(a, "holder").Id, HolderPq(), Args.L(a, "caveats"));
            case "delegate_suite":
                {
                    var parent = Args.O(a, "parent");
                    var to = a.GetValueOrDefault("to_holder") == null ? Args.S(parent, "holder") : v.Ed(a, "to_holder").Id;
                    return Issue.Delegate(parent, to, a.GetValueOrDefault("added_caveats") as JL ?? new JL(), SuiteOf("signer"), HolderPq());
                }
            case "sign_pcactn_suite": return new JD { ["pcactn"] = Issue.SignPCActn(Body(), SuiteOf("signer")) };
            case "sign_artifact_suite":
                return Args.S(a, "kind") switch
                {
                    "escalation_answer" => Issue.SignEscalationAnswer(Body(), SuiteOf("signer")),
                    "revocation_epoch" => RevocationFreshness.SignEpoch(Epoch(Body()), SuiteOf("signer")),
                    var k => throw new ArgumentException($"produce: unknown artifact kind '{k}'"),
                };
        }
        throw new ArgumentException("unsupported_op: " + op);
    }

    static byte[] B64(JD a, string k) => Pca.B64uDecode(Args.S(a, k)) ?? throw new ArgumentException($"produce: {k} must be canonical base64url");

    /// <summary>The vector's limits (a non-string limit reads as empty, which parseLimit refuses, as the reference does).</summary>
    static Dictionary<string, string>? Limits(JD a) =>
        (a.GetValueOrDefault("limits") as JD)?.ToDictionary(kv => kv.Key, kv => kv.Value as string ?? "");

    /// <summary>A provenance recorder on the vector's clock (each reading takes the next tick; the last one repeats).</summary>
    static JD Recorder(Args v)
    {
        var a = v.M;
        var clock = Args.L(a, "clock");
        if (clock.Count == 0) throw new ArgumentException("produce: clock must not be empty");
        var i = 0;
        long Now()
        {
            var x = clock[Math.Min(i++, clock.Count - 1)];
            return IntentJs.IsSafeInteger(x) ? IntentJs.Lng(x) : throw new ArgumentException("produce: clock must hold integers");
        }
        var r = new ProvenanceRecorder(Args.S(a, "mediator"), Args.S(a, "kid"), v.Suite(a, "key"), Args.S(a, "session"), Now);
        var outs = new List<JD>();
        foreach (var s in Args.Objs(a, "steps"))
            outs.Add(s.GetValueOrDefault("kind") switch
            {
                "principal" => r.Principal(Args.S(s, "text")),
                "tool" => r.Tool(Args.S(s, "name"), s.GetValueOrDefault("output")),
                "retrieval" => r.Retrieval(Args.S(s, "source"), s.GetValueOrDefault("content")),
                "web" => r.Web(Args.S(s, "url"), s.GetValueOrDefault("content")),
                _ => ActionStep(r, Args.O(s, "op")),
            });
        if (outs.Count == 0) throw new ArgumentException("produce: no recorder steps");
        return new JD { ["pin"] = r.Pin.ToJson(), ["receipts"] = outs.Take(outs.Count - 1).Select(x => (object?)x).ToList(), ["bundle"] = outs[^1] };
    }

    static JD ActionStep(ProvenanceRecorder r, JD op) => r.ForAction(Args.S(op, "verb"), Args.S(op, "resource"), Args.OptO(op, "params"));

    /// <summary>The facade end to end: compile, mint, record the principal's messages, optionally hop to a sub-agent, then act.</summary>
    static JD FacadeAct(Args v)
    {
        var a = v.M;
        var now = Args.N(a, "now");
        var ag = Agent.FromPrincipal(new AgentOptions
        {
            Principal = v.Suite(a, "principal"), Holder = v.Suite(a, "holder"), Goal = Args.S(a, "goal"), GoalSalt = Args.S(a, "goal_salt"),
            Permissions = a.GetValueOrDefault("permissions") as JD ?? throw new ArgumentException("compilePolicy: permissions must be an object"),
            Limits = Limits(a), Aud = Args.S(a, "aud"), Now = now,
            Provenance = new ProvenanceOptions { Signer = v.Suite(a, "recorder_key"), Session = Args.S(a, "session"), Now = () => now },
        });
        if (a.ContainsKey("principal_messages"))
            foreach (var m in Args.Strs(a, "principal_messages")) ag.Provenance.Principal(m);
        if (Args.OptO(a, "sub_agent") is { } sa)
            ag = ag.SubAgent(v.Suite(sa, "holder"), sa.GetValueOrDefault("added_caveats") as JL);
        var act = Args.O(a, "act");
        var r = ag.Act(Args.S(act, "verb"), Args.S(act, "resource"), Args.OptO(act, "params"),
            new ActOptions { Counter = Args.N(act, "counter"), Now = Args.N(act, "now"), Nonce = Args.OptS(act, "nonce") });
        var env = (JD)((JL)ag.Grant["caveats"]!)[0]!;
        return new JD
        {
            ["grant"] = ag.Grant, ["goal_commit"] = env["goal_commit"], ["chain"] = ag.Chain.Select(x => (object?)x).ToList(), ["pcactn"] = r.PCActn,
            ["encoded"] = r.Encoded, ["provenance"] = r.Provenance,
        };
    }
}
