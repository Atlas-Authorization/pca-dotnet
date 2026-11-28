// The trusted question channel of the wallet (one instance per session) and the framework-neutral handlers of its two endpoints.
//
//  1. SELECTION belongs to the verifier: questions enter only as a site-signed intent_required (checked against the site's discovery
//     keys, the session, the current map digest and the action digest; the wallet re-derives the cell from its own outcome space and the
//     action and refuses on any disagreement), or as a structured agent clarification whose cell the wallet picks itself.
//  2. RENDERING belongs to the wallet (fixed templates); the card digest is signed into the answer.
//  3. ORDERING belongs to the wallet: friction descending, E[h|c] * mass descending, cell index ascending. A typed or device question is
//     always alone on its screen.
//  4. FRICTION scales with harm, never below the site's minimum.
//  5. CANARIES are inserted with probability rho and rendered like real questions; their answers only update the noise counts.
//  6. CAPS: at most perSession (6) questions per session and perHour (12) per hour across the principal's sessions. When the estimated
//     false-yes rate passes eta_stop the session is FROZEN: uncertain cells are refused and listed in the summary instead.
//  7. A cell is asked at most once per session (clarified cells count as visited).
//  8. Under estimated noise an irreversible cell needs two typed or device confirmations on screens at least two apart.
// What the channel returns for a real answer is the principal-signed observation. Results are JSON trees with the reference's member names.
using System.Text;
using AtlasPca.IntentPkg;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using WebauthnApi = AtlasPca.Webauthn.Webauthn;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

/// <summary>A grant view over an intent learner, with an optional ceiling predicate (true = inside every ceiling).</summary>
public sealed class LearnerView(IntentLearner learner, Func<string, int[], bool>? insideCeiling = null) : IGrantView
{
    IntentOmega.VerbSpace VsOf(string verb) =>
        learner.Omega.Verbs.Find(v => v.Verb == verb) ?? throw new WalletException($"learnerView: unknown verb {verb}");
    public double P(string verb, int[] idx) => learner.Acceptance(IntentOmega.CellRep(VsOf(verb), idx));
    public bool Vetoed(string verb, int[] idx) => learner.IsVetoed(IntentOmega.CellRep(VsOf(verb), idx));
    public bool OutsideCeiling(string verb, int[] idx) => insideCeiling != null && !insideCeiling(verb, idx);
    public IReadOnlyList<WalletCore.CellRef> Confirmed() => learner.Cells().Where(c => c.InGrant).Select(c => new WalletCore.CellRef(c.Verb, c.Cell)).ToList();
}

/// <summary>The WebAuthn trust of the device tier: relying party, origins, credential public keys (JWK) and the last accepted signature counters.</summary>
public sealed class DeviceTrust
{
    public required string RpId { get; init; }
    public required L Origins { get; init; }
    /// <summary>Credential id to its public key (a JWK dictionary).</summary>
    public required D Credentials { get; init; }
    /// <summary>Last accepted counter per credential id (absent = 0); the channel records each accepted assertion's counter, so a cloned authenticator is refused.</summary>
    public D? SignCounts { get; init; }
}

public sealed class ChannelOptions
{
    public required IntentOmega.Omega Omega { get; init; }
    public required string Session { get; init; }
    /// <summary>The current task-map digest (it changes as deltas are minted).</summary>
    public required Func<string> MapDigest { get; init; }
    public required byte[] PrincipalSecret { get; init; }
    /// <summary>The site as verified from discovery: origin, display name and its intent.schema_keys (which sign the question).</summary>
    public required string SiteOrigin { get; init; }
    public required string SiteName { get; init; }
    public required object? SiteKeys { get; init; }
    public string? StatementText { get; init; }
    public D? Units { get; init; }
    /// <summary>Value-dependent reversibility of a box (from the signed schema). Default: the verb's.</summary>
    public Func<IntentOmega.VerbSpace, List<List<int>>, string>? Reversibility { get; init; }
    /// <summary>Sensitivity of parameters by path. Default: material.</summary>
    public D? Sensitivity { get; init; }
    public IReadOnlyList<string>? IdentityPaths { get; init; }
    public required IGrantView View { get; init; }
    /// <summary>Lift an attempted action into the wallet's space (accumulator posts, provenance, world values). Default: ActionValuesOf.</summary>
    public Func<D, D>? Lift { get; init; }
    /// <summary>Lift a clarification candidate (already in outcome-space paths). Default: identity.</summary>
    public Func<D, D>? LiftCandidate { get; init; }
    public IntentOmega.HarmModel? Harm { get; init; }
    public D? Friction { get; init; }
    public int PerSession { get; init; } = 6;
    public int PerHour { get; init; } = 12;
    /// <summary>The principal's question counter across sessions (shared).</summary>
    public required WalletCore.SlidingWindowCounter Hourly { get; init; }
    /// <summary>The principal's canary counts (shared across sessions) and where to persist them.</summary>
    public required Func<D> Noise { get; init; }
    public required Action<D> OnNoise { get; init; }
    public D? Fatigue { get; init; }
    public double? Rho { get; init; }
    public required Func<double> Rand { get; init; }
    public required Func<double> Now { get; init; }
    public DeviceTrust? Device { get; init; }
    public int MaxPerScreen { get; init; } = 3;
    /// <summary>Cap on the number of cells a single question may cover (bounds the work of E[h|c]).</summary>
    public int MaxBoxCells { get; init; } = 4096;
}

/// <summary>An agent clarification's answer: HTTP-style status, the dry-run verdicts, the asked question id, a refusal code or a parse error.</summary>
public sealed record ClarifyResult(int Status, List<ClarifyVerdict> Verdicts, string? QuestionId = null, string? Refused = null, string? Error = null)
{
    public D ToJson()
    {
        var o = new D { ["status"] = WalletCore.N(Status), ["verdicts"] = Verdicts.Select(v => (object?)new D { ["index"] = WalletCore.N(v.Index), ["verdict"] = v.Verdict }).ToList() };
        if (QuestionId != null) o["questionId"] = QuestionId;
        if (Refused != null) o["refused"] = Refused;
        if (Error != null) o["error"] = Error;
        return o;
    }
}

public sealed class TrustedChannel(ChannelOptions opts)
{
    const string B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static readonly object U = JsX.Undef;

    sealed class Item
    {
        public required string Id { get; init; }
        public required string Kind { get; init; } // real | canary | confirmation
        public required string Source { get; init; }
        public required string Verb { get; init; }
        public required List<List<int>> Box { get; init; }
        public required D Coords { get; init; }
        public required D Card { get; init; }
        public D? Action { get; init; }
        public string? ActionDigest { get; init; }
        public bool Irreversible { get; init; }
        public int? Expected { get; init; }
        public double Weight { get; init; }
        public double Flat { get; init; }
        public double? ExpiresAt { get; init; }
        public int? ShownOn { get; set; }
        public D? First { get; init; }
        public int? NotBefore { get; init; }
        public bool Jit { get; init; }
        public string Tier => (string)Card["friction"]!;
    }

    readonly ChannelOptions o = opts;
    readonly Dictionary<string, Item> pending = new();
    readonly HashSet<string> asked = new();
    readonly HashSet<string> canaryUsed = new();
    readonly List<WalletCore.CellRef> knownYes = new();
    readonly Dictionary<string, L> confirmations = new();
    readonly L refusedWhileFrozen = new();
    int sessionQuestions;
    int canaries;
    int screenNo;

    static int Rank(object? t) => WalletCore.FrictionRank(t);
    static object? N(double d) => WalletCore.N(d);

    /// <summary>The current noise state (eta+ under load, frozen?).</summary>
    public D Noise() => WalletCore.NoiseState(o.Noise(), N(o.Hourly.Count(o.Now())), o.Fatigue);

    /// <summary>The admission policy the learner should use now (tau, eta+, eta-; double confirmation).</summary>
    public D Admission() => WalletCore.AdmissionPolicy(Noise(), o.Fatigue);

    /// <summary>Questions asked so far in this session (the questions accumulator of the session root).</summary>
    public int QuestionsAsked() => sessionQuestions;

    string NewId()
    {
        var sb = new StringBuilder("q_");
        for (int i = 0; i < 10; i++) sb.Append(B64U[(int)(Math.Floor(o.Rand() * 64) % 64)]);
        var s = sb.ToString();
        return pending.ContainsKey(s) ? NewId() : s;
    }

    (double Weight, double MeanHarm)? BoxStats(IntentOmega.VerbSpace vs, List<List<int>> box)
    {
        if (WalletCore.BoxSize(box) > o.MaxBoxCells) return null;
        double m = 0, mh = 0;
        foreach (var idx in WalletCore.BoxCells(box))
        {
            var s = IntentOmega.CellStats(vs, idx, o.Harm ?? IntentOmega.DefaultHarmModel);
            m += s.Mass;
            mh += s.Mass * s.Harm;
        }
        return (mh, m > 0 ? mh / m : 0);
    }

    string RevOf(IntentOmega.VerbSpace vs, List<List<int>> box) => o.Reversibility != null ? o.Reversibility(vs, box) : vs.Reversibility;

    string FrictionOf(IntentOmega.VerbSpace vs, List<List<int>> box, double meanHarm, string? siteMin, bool irreversible)
    {
        var provenance = new L();
        bool widensIdentity = false;
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            if (d.Path.StartsWith("env.prov.", StringComparison.Ordinal) && d is IntentOmega.CatDim pd)
            {
                var param = d.Path["env.prov.".Length..];
                var levels = new L();
                foreach (var i in box[k])
                {
                    var v = pd.Values[i];
                    foreach (var part in (v.Kind == "prefix" ? v.Value + "*" : v.Value).Split('|', ',')) levels.Add(part);
                }
                object? sens = o.Sensitivity != null && o.Sensitivity.TryGetValue(param, out var sv) && sv != null ? sv : "material";
                provenance.Add(new D { ["path"] = param, ["sensitivity"] = sens, ["levels"] = levels });
            }
            if (d is IntentOmega.CatDim cd && o.IdentityPaths != null && o.IdentityPaths.Contains(d.Path))
            {
                // widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones
                if (box[k].Any(i => cd.Values[i].Kind != "exact")) widensIdentity = true;
            }
        }
        var inp = new D { ["reversibility"] = RevOf(vs, box), ["expectedHarm"] = N(meanHarm), ["provenance"] = provenance, ["widensCriticalIdentity"] = widensIdentity };
        if (siteMin != null) inp["siteMin"] = siteMin;
        var tier = (string)WalletCore.FrictionFor(inp, o.Friction)["tier"]!;
        if (irreversible && Admission()["doubleConfirmIrreversible"] is true) tier = WalletCore.MaxFriction(tier, "typed");
        return tier;
    }

    (D Card, string Friction)? Render(string kind, string verb, D coords, string friction, D? action, IntentOmega.VerbSpace vs, List<List<int>> box, string? reason = null)
    {
        var b = new D { ["omega"] = o.Omega, ["verb"] = verb, ["coords"] = coords, ["site"] = new D { ["origin"] = o.SiteOrigin, ["name"] = o.SiteName } };
        if (o.StatementText != null) b["statementText"] = o.StatementText;
        b["reversibility"] = RevOf(vs, box);
        if (o.Units != null) b["units"] = o.Units;
        if (action != null) b["action"] = action;
        b["kind"] = kind;
        if (reason != null) b["reason"] = reason;
        var r = WalletCard.RenderCard(new D(b) { ["friction"] = friction });
        // A typed question needs a value to type; with none on the card, the only stronger tier is the device.
        if (r["ok"] is true && Rank(friction) == Rank("typed") && !JsX.Truthy(WalletCore.Nul(WalletCore.G(r["card"], "typed"))))
            r = WalletCard.RenderCard(new D(b) { ["friction"] = "device" });
        if (r["ok"] is not true) return null;
        var card = (D)r["card"]!;
        return (card, (string)card["friction"]!);
    }

    static D Refused(string code, string reason) => new() { ["ok"] = false, ["code"] = code, ["reason"] = reason };

    D? Gate()
    {
        if (Noise()["frozen"] is true) return Refused("frozen", "the estimated false-yes rate is above η_stop: no more questions this session");
        if (!(sessionQuestions < o.PerSession)) return Refused("cap_session", $"at most {o.PerSession} questions per session");
        if (!(double.IsFinite(o.Now()) && o.Hourly.Count(o.Now()) < o.PerHour)) return Refused("cap_hour", $"at most {o.PerHour} questions per hour");
        return null;
    }

    void Enqueue(Item it, IntentOmega.VerbSpace vs) => pending[it.Id] = it;

    Item Make(string id, string kind, string source, string verb, List<List<int>> box, D coords, D card, D? action, string? actionDigest, bool irreversible, int? expected,
        double weight, double? expiresAt, bool jit, IntentOmega.VerbSpace vs) => new()
    {
        Id = id, Kind = kind, Source = source, Verb = verb, Box = box, Coords = coords, Card = card, Action = action, ActionDigest = actionDigest, Irreversible = irreversible,
        Expected = expected, Weight = weight, Flat = WalletCore.BoxCells(box).Min(idx => WalletCore.FlatIndex(vs, idx)), ExpiresAt = expiresAt, Jit = jit,
    };

    void Count()
    {
        sessionQuestions++;
        if (!o.Hourly.TryAdd(o.Now(), JsX.MaxSafe)) throw new WalletException("unreachable");
    }

    /// <summary>Insert a canary with probability rho (rendered and ordered like a real question).</summary>
    void MaybeCanary()
    {
        var exclude = new HashSet<string>(canaryUsed);
        foreach (var p in pending.Values) foreach (var idx in WalletCore.BoxCells(p.Box)) exclude.Add(WalletCore.CellKey(p.Verb, idx));
        bool lowHarm = pending.Values.All(p => p.Kind != "real" || Rank(p.Tier) <= Rank("hold"));
        var c = WalletCore.PickCanary(new WalletCore.CanaryCtx
        {
            Omega = o.Omega,
            Confirmed = o.View.Confirmed(),
            KnownNo = (verb, idx) => o.View.OutsideCeiling(verb, idx) ? "ceiling" : o.View.Vetoed(verb, idx) ? "veto" : null,
            KnownYes = knownYes,
            Exclude = exclude,
            Rand = o.Rand,
            Rho = o.Rho,
            LowHarmSession = lowHarm,
            CanariesSoFar = canaries,
        });
        if (c == null) return;
        var vs = o.Omega.Verbs.Find(v => v.Verb == c.Verb)!;
        var box = c.Idx.Select(i => new List<int> { i }).ToList();
        var st = BoxStats(vs, box);
        if (st == null) return;
        var coords = WalletCore.CoordsOfCell(vs, c.Idx);
        var action = new D { ["verb"] = c.Verb, ["values"] = IntentOmega.OutcomeToJson(IntentOmega.CellRep(vs, c.Idx))["values"] };
        var friction = FrictionOf(vs, box, st.Value.MeanHarm, null, false);
        var r = Render("question", c.Verb, coords, friction, action, vs, box);
        if (r == null) return;
        canaries++;
        canaryUsed.Add(WalletCore.CellKey(c.Verb, c.Idx));
        Enqueue(Make(NewId(), "canary", "elicitation", c.Verb, box, coords, r.Value.Card, action, null, false, c.Expected, st.Value.Weight, null, false, vs), vs);
    }

    /// <summary>Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) with the action the agent attempted.
    /// Every check fails closed. Returns {ok: true, questionId, friction} or {ok: false, code, reason}.</summary>
    public D Receive(D ir, D action)
    {
        double now = o.Now();
        var v = WalletDelivery.VerifyIntentRequired(ir, o.SiteKeys, N(now));
        if (v != null) return Refused("bad_site_signature", v);
        if (!JsX.StrictEq(ir["session"], o.Session)) return Refused("wrong_session", "the question is for another session");
        if (!JsX.StrictEq(ir["map_digest"], o.MapDigest())) return Refused("stale_map", "the question names another map version");
        var irCell = (D)ir["cell"]!;
        var irVerb = (string)irCell["verb"]!;
        var irCoords = (D)irCell["coords"]!;
        if (!JsX.StrictEq(WalletCore.G(action, "verb"), irVerb) || WalletCore.PcaActionDigest(action) != (string)ir["action_digest"]!) return Refused("action_mismatch", "the action does not match the signed action digest");
        var lifted = o.Lift != null ? o.Lift(action) : WalletCore.ActionValuesOf(action);
        var r = WalletCore.ResolveCoords(o.Omega, irVerb, irCoords);
        if (!r.Ok) return Refused("cell_mismatch", r.Reason!);
        var vs = r.Vs!;
        var box = r.Box!;
        var at = WalletCore.CellOfAction(o.Omega, lifted);
        if (at == null || !WalletCore.CellInBox(box, at.Value.Idx)) return Refused("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names");
        var st = BoxStats(vs, box);
        if (st == null) return Refused("cell_too_large", "the question covers too many cells");
        var cells = WalletCore.BoxCells(box);
        foreach (var idx in cells)
        {
            if (o.View.OutsideCeiling(vs.Verb, idx.ToArray())) return Refused("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it");
            if (o.View.Vetoed(vs.Verb, idx.ToArray())) return Refused("not_uncertain", "the cell was vetoed");
        }
        double pa = o.View.P(vs.Verb, at.Value.Idx);
        if (!(pa > 0 && pa < 1)) return Refused("not_uncertain", pa <= 0 ? "the cell is denied" : "the cell is already in the grant");
        if (cells.Any(idx => asked.Contains(WalletCore.CellKey(vs.Verb, idx)))) return Refused("already_asked", "a cell is asked at most once per session");
        var g = Gate();
        if (g != null)
        {
            if (g["code"] is "frozen") refusedWhileFrozen.Add(new D { ["verb"] = vs.Verb, ["coords"] = irCoords });
            return g;
        }
        bool irreversible = RevOf(vs, box) == "irreversible";
        var friction = FrictionOf(vs, box, st.Value.MeanHarm, (string)ir["friction"]!, irreversible);
        var rendered = Render("question", irVerb, irCoords, friction, lifted, vs, box);
        if (rendered == null) return Refused("render_failed", "the card could not be rendered");
        var qid = (string)ir["question_id"]!;
        if (pending.ContainsKey(qid)) return Refused("already_asked", "duplicate question id");
        foreach (var idx in cells) asked.Add(WalletCore.CellKey(vs.Verb, idx));
        Count();
        Enqueue(Make(qid, "real", "elicitation", irVerb, box, irCoords, rendered.Value.Card, lifted, (string)ir["action_digest"]!, irreversible, null, st.Value.Weight, WalletCore.Dn(ir["expires_at"]), true, vs), vs);
        MaybeCanary();
        return new D { ["ok"] = true, ["questionId"] = qid, ["friction"] = rendered.Value.Friction };
    }

    /// <summary>An agent clarification: {candidates: [at most 8 structured actions], reason}, no text. Certain cells are answered at once (dry run);
    /// among the uncertain ones the wallet picks the most informative and asks it.</summary>
    public ClarifyResult Clarify(object? body)
    {
        var parsed = WalletCard.ParseClarifyRequest(body);
        if (parsed["ok"] is not true) return new ClarifyResult(400, new List<ClarifyVerdict>(), Error: (string)parsed["error"]!);
        var request = (D)parsed["request"]!;
        var candidates = (L)request["candidates"]!;
        var st = Noise();
        Func<object?, object?>? lift = null;
        if (o.LiftCandidate != null) lift = c => o.LiftCandidate((D)c!);
        var plan = WalletCard.PlanClarification(o.Omega, o.View, candidates, lift, asked,
            Math.Min(0.5 - 1e-9, WalletCore.Dn(st["etaPosBar"])), Math.Min(0.5 - 1e-9, WalletCore.Dn(st["etaNegBar"])), o.Harm ?? IntentOmega.DefaultHarmModel);
        if (plan.Ask == null) return new ClarifyResult(200, plan.Verdicts);
        var g = Gate();
        if (g != null) return new ClarifyResult((string)g["code"]! == "frozen" ? 200 : 429, plan.Verdicts, Refused: (string)g["code"]!);
        var vs = o.Omega.Verbs.Find(v => v.Verb == plan.Ask.Verb)!;
        var box = plan.Ask.Idx.Select(i => new List<int> { i }).ToList();
        (double Weight, double MeanHarm) stats = BoxStats(vs, box) ?? throw JsX.TypeError("Cannot read properties of null (reading 'meanHarm')");
        var coords = WalletCore.CoordsOfCell(vs, plan.Ask.Idx);
        var raw = (D)candidates[plan.Ask.Index]!;
        var action = o.LiftCandidate != null ? o.LiftCandidate(raw) : raw;
        bool irreversible = RevOf(vs, box) == "irreversible";
        var friction = FrictionOf(vs, box, stats.MeanHarm, null, irreversible);
        var rendered = Render("clarification", vs.Verb, coords, friction, action, vs, box, (string)request["reason"]!);
        if (rendered == null) return new ClarifyResult(200, plan.Verdicts, Refused: "render_failed");
        var id = NewId();
        asked.Add(WalletCore.CellKey(vs.Verb, plan.Ask.Idx));
        Count();
        Enqueue(Make(id, "real", "clarification", vs.Verb, box, coords, rendered.Value.Card, action, null, irreversible, null, stats.Weight, null, false, vs), vs);
        MaybeCanary();
        return new ClarifyResult(200, plan.Verdicts, QuestionId: id);
    }

    /// <summary>Pending items in display order: friction descending, E[h|c] * mass descending, cell index ascending, id ascending.</summary>
    List<Item> Ordered()
    {
        var l = pending.Values.ToList();
        l.Sort((a, b) =>
        {
            double x = Rank(b.Tier) - Rank(a.Tier);
            if (x != 0 && !double.IsNaN(x)) return Math.Sign(x);
            x = b.Weight - a.Weight;
            if (x != 0 && !double.IsNaN(x)) return Math.Sign(x);
            x = a.Flat - b.Flat;
            if (x != 0 && !double.IsNaN(x)) return Math.Sign(x);
            return Math.Sign(string.CompareOrdinal(a.Id, b.Id));
        });
        return l;
    }

    /// <summary>The next screen, or null. A typed or device question is always alone; tap and hold questions share up to MaxPerScreen.</summary>
    public D? NextScreen()
    {
        double now = o.Now();
        foreach (var it in pending.Values.ToList()) if (it.ExpiresAt != null && !(now <= it.ExpiresAt)) pending.Remove(it.Id);
        var items = Ordered().Where(it => it.ShownOn == null).ToList();
        if (items.Count == 0) return null;
        int next = screenNo + 1;
        var eligible = items.Where(it => it.NotBefore == null || next >= it.NotBefore).ToList();
        screenNo = next;
        if (eligible.Count == 0) return new D { ["screen"] = N(next), ["kind"] = "interstitial", ["questions"] = new L() };
        var first = eligible[0];
        var picked = new List<Item> { first };
        if (Rank(first.Tier) <= Rank("hold"))
            foreach (var it in eligible.Skip(1))
            {
                if (picked.Count >= o.MaxPerScreen) break;
                if (Rank(it.Tier) <= Rank("hold")) picked.Add(it);
            }
        foreach (var it in picked) it.ShownOn = next;
        return new D { ["screen"] = N(next), ["kind"] = "questions", ["questions"] = picked.Select(it => (object?)new D { ["questionId"] = it.Id, ["card"] = it.Card }).ToList() };
    }

    static D Fail(string code, string reason) => new() { ["ok"] = false, ["code"] = code, ["reason"] = reason };

    string ChallengeOf(Item it, string questionId) =>
        WalletCore.DeviceChallenge(questionId, it.Card["rendered_digest"], new Num("1"), it.Jit && it.Irreversible && !string.IsNullOrEmpty(it.ActionDigest) ? it.ActionDigest : null);

    /// <summary>The principal's response to a shown question: {answer: "no"} | {answer: "yes", holdMs?, typed?, webauthn?} | {answer: "partly", partial, ...evidence}.</summary>
    public D Answer(string? questionId, D response)
    {
        if (questionId == null || !pending.TryGetValue(questionId, out var it)) return Fail("unknown_question", "no such pending question");
        if (it.ShownOn == null) return Fail("not_shown", "the question was never shown");
        double now = o.Now();
        if (it.ExpiresAt != null && !(now <= it.ExpiresAt))
        {
            pending.Remove(questionId);
            return Fail("expired", "the question expired");
        }
        int y;
        object? partial = U;
        var ans = WalletCore.G(response, "answer");
        if (ans is string a0 && a0 == "no") y = 0;
        else if (ans is string a1 && a1 == "partly")
        {
            var e = WalletCard.PartialError(it.Card, WalletCore.G(response, "partial"));
            if (e != null) return Fail("bad_response", e);
            y = 1;
            partial = WalletCore.G(response, "partial");
        }
        else y = 1;
        var ux = new D { ["tier"] = it.Tier, ["rendered_digest"] = it.Card["rendered_digest"], ["canary"] = it.Kind == "canary" };
        if (y == 1)
        {
            var ev = TierEvidence(it, ans is string a2 && a2 == "no" ? new D() : response, questionId);
            if (ev["ok"] is not true) return ev;
            foreach (var (k, v) in (D)ev["ux"]!) ux[k] = v;
        }
        bool plainYes = y == 1 && ReferenceEquals(partial, U);
        if (it.Kind != "canary" && it.Jit && it.Irreversible && plainYes && !string.IsNullOrEmpty(it.ActionDigest) && Rank(it.Tier) >= Rank("typed"))
        {
            ux["action_digest"] = it.ActionDigest;
            ux["consent_for_action"] = true;
        }
        var body = new D { ["map_digest"] = o.MapDigest(), ["session"] = o.Session, ["question_id"] = questionId, ["verb"] = it.Verb, ["cell"] = it.Coords, ["y"] = N(y) };
        if (!ReferenceEquals(partial, U) && JsX.Truthy(partial)) body["partial"] = partial;
        body["source"] = it.Source;
        body["observed_at"] = N(now);
        body["ux"] = ux;
        var answer = WalletCore.SignIntentAnswer(body, o.PrincipalSecret);
        pending.Remove(questionId);
        if (it.Kind == "canary")
        {
            o.OnNoise(WalletCore.RecordCanary(o.Noise(), N(it.Expected!.Value), N(y)));
            return new D { ["ok"] = true, ["kind"] = "canary", ["answer"] = answer };
        }
        if (y == 0) return new D { ["ok"] = true, ["kind"] = "veto", ["answer"] = answer };
        if (plainYes && Rank(it.Tier) >= Rank("typed") && it.Box.All(ids => ids.Count == 1))
            knownYes.Add(new WalletCore.CellRef(it.Verb, it.Box.Select(ids => ids[0]).ToArray())); // a verified high-friction yes: a source of known-yes canaries
        if (plainYes && it.Irreversible && Admission()["doubleConfirmIrreversible"] is true)
        {
            var key = it.Verb + "|" + JsJson.Stringify(it.Coords);
            var recs = new L();
            if (confirmations.TryGetValue(key, out var prev)) recs.AddRange(prev);
            recs.Add(new D { ["screen"] = N(it.ShownOn.Value), ["tier"] = it.Tier });
            confirmations[key] = recs;
            if (it.Kind == "confirmation" && it.First != null && WalletCore.DoubleConfirmed(recs))
                return new D { ["ok"] = true, ["kind"] = "confirmed", ["answers"] = new L { it.First, answer } };
            if (it.Kind == "confirmation") return new D { ["ok"] = true, ["kind"] = "pending_confirmation", ["answer"] = answer };
            // schedule the second, independent confirmation: at least one other screen in between
            var second = new Item
            {
                Id = NewId(), Kind = "confirmation", Source = it.Source, Verb = it.Verb, Box = it.Box, Coords = it.Coords, Card = it.Card, Action = it.Action, ActionDigest = it.ActionDigest,
                Irreversible = it.Irreversible, Expected = it.Expected, Weight = it.Weight, Flat = it.Flat, ExpiresAt = it.ExpiresAt, First = answer, NotBefore = it.ShownOn.Value + 2, Jit = it.Jit,
            };
            pending[second.Id] = second;
            return new D { ["ok"] = true, ["kind"] = "pending_confirmation", ["answer"] = answer };
        }
        return new D { ["ok"] = true, ["kind"] = "answer", ["answer"] = answer };
    }

    /// <summary>The evidence a yes carries for its friction tier: {ok: true, ux} or the refusal {ok: false, code, reason}.</summary>
    D TierEvidence(Item it, D r, string questionId)
    {
        switch (it.Tier)
        {
            case "tap":
                return new D { ["ok"] = true, ["ux"] = new D() };
            case "hold":
                {
                    var h = WalletCore.G(r, "holdMs");
                    if (!(WalletCore.IsIntegral(h) && WalletCore.Dn(h) >= WalletCore.MinHoldMs)) return Fail("tier_evidence", $"hold for at least {WalletCore.MinHoldMs} ms");
                    return new D { ["ok"] = true, ["ux"] = new D { ["hold_ms"] = h } };
                }
            case "typed":
                {
                    var t = WalletCore.G(it.Card, "typed");
                    if (!JsX.Truthy(WalletCore.Nul(t)) || it.Action == null || WalletCore.G(r, "typed") is not string typedIn) return Fail("tier_evidence", "type the value shown on the card");
                    var want = WalletCard.ExpectedTyped(it.Card, it.Action);
                    var unit = o.Units != null ? WalletCore.G(o.Units, JsX.Str(WalletCore.G(t, "path"))) : U;
                    var got = WalletCard.NormalizeTyped(typedIn, WalletCore.G(t, "mode"), ReferenceEquals(unit, U) ? null : unit);
                    if (want == null || got == null || got != want) return Fail("typed_mismatch", "the typed value does not match the card");
                    return new D { ["ok"] = true, ["ux"] = new D { ["typed_digest"] = WalletCore.TypedDigest(questionId, got) } };
                }
            case "device":
                {
                    var wa = WalletCore.G(r, "webauthn");
                    var dev = o.Device;
                    if (!JsX.Truthy(WalletCore.Nul(wa)) || dev == null) return Fail("tier_evidence", "a security-key assertion is required");
                    var credId = JsX.At(wa, "credential_id");
                    var pk = dev.Credentials.TryGetValue(JsX.Str(credId), out var p) && JsX.Truthy(p) ? p : null;
                    var ad = Pca.B64uDecode(JsX.At(wa, "authenticator_data"));
                    var cd = Pca.B64uDecode(JsX.At(wa, "client_data_json"));
                    var sg = Pca.B64uDecode(JsX.At(wa, "signature"));
                    if (pk == null || ad == null || cd == null || sg == null) return Fail("tier_evidence", "unknown credential or malformed assertion");
                    var challenge = ChallengeOf(it, questionId);
                    object? stored = dev.SignCounts != null && dev.SignCounts.TryGetValue(JsX.Str(credId), out var sc) && sc != null ? sc : new Num("0");
                    var res = WebauthnApi.VerifyAssertion(
                        new D { ["authenticatorData"] = ad, ["clientDataJSON"] = cd, ["signature"] = sg, ["publicKey"] = pk },
                        new D { ["expectedChallenge"] = challenge, ["rpId"] = dev.RpId, ["origins"] = dev.Origins, ["requireUV"] = true, ["storedSignCount"] = stored });
                    if (res["ok"] is not true) return Fail("tier_evidence", "security key: " + JsX.Str(res["reason"]));
                    if (dev.SignCounts != null) dev.SignCounts[JsX.Str(credId)] = res["signCount"] is long n ? new Num(n.ToString(System.Globalization.CultureInfo.InvariantCulture)) : res["signCount"];
                    return new D { ["ok"] = true, ["ux"] = new D { ["webauthn"] = new D((D)wa!) } };
                }
            default:
                throw new WalletException("unreachable friction tier");
        }
    }

    /// <summary>The WebAuthn challenge the wallet UI passes to the credential API for a shown device-tier question, or null.</summary>
    public string? DeviceChallengeFor(string? questionId)
    {
        if (questionId == null || !pending.TryGetValue(questionId, out var it) || it.ShownOn == null || it.Tier != "device") return null;
        return ChallengeOf(it, questionId);
    }

    /// <summary>The end-of-session summary shown instead of questions once the session froze: {frozen, refused, asked, canaries}.</summary>
    public D Summary() => new() { ["frozen"] = Noise()["frozen"], ["refused"] = new L(refusedWhileFrozen), ["asked"] = N(sessionQuestions), ["canaries"] = N(canaries) };

    /// <summary>A stable digest of the channel's pending state (for tests and audit logs).</summary>
    public string StateDigest()
    {
        var keys = asked.ToList();
        keys.Sort(StringComparer.Ordinal);
        return Pca.HashCanonical(new D
        {
            ["d"] = "atlas-pca/wallet-channel-state/v1",
            ["p"] = Ordered().Select(i => (object?)new D { ["id"] = i.Id, ["k"] = i.Kind, ["d"] = i.Card["rendered_digest"] }).ToList(),
            ["a"] = keys.Select(k => (object?)k).ToList(),
            ["n"] = N(sessionQuestions),
        });
    }
}

/// <summary>Framework-neutral handlers for the two wallet endpoints named in the session root: POST .../questions
/// {intent_required, action} and POST .../clarify {candidates, reason}. Neither response carries p or any map content: the agent (or site)
/// learns a question id, a dry-run verdict or a refusal code, exactly what an attempt would teach it.</summary>
public static class WalletHandlers
{
    static readonly Dictionary<string, int> StatusOfRefusal = new()
    {
        ["bad_site_signature"] = 401, ["wrong_session"] = 409, ["stale_map"] = 409, ["action_mismatch"] = 422, ["cell_mismatch"] = 422, ["not_uncertain"] = 409,
        ["already_asked"] = 409, ["frozen"] = 429, ["cap_session"] = 429, ["cap_hour"] = 429, ["cell_too_large"] = 422, ["bad_request"] = 400, ["render_failed"] = 422,
    };

    static D Resp(int status, D body) => new() { ["status"] = WalletCore.N(status), ["body"] = body };
    static D Err(string error, string? detail = null)
    {
        var b = new D { ["error"] = error };
        if (detail != null) b["detail"] = detail;
        return b;
    }

    static D? ActionOf(object? v)
    {
        if (!WalletCore.IsObj(v) || WalletCore.G(v, "verb") is not string verb || WalletCore.G(v, "resource") is not string resource
            || WalletCore.G(v, "reversibility_class") is not string rc || !WalletCore.IsObj(WalletCore.G(v, "params"))) return null;
        foreach (var k in JsX.Keys(v)) if (k is not ("verb" or "resource" or "params" or "reversibility_class")) return null;
        return new D { ["verb"] = verb, ["resource"] = resource, ["params"] = WalletCore.G(v, "params"), ["reversibility_class"] = rc };
    }

    /// <summary>The question endpoint: a site delivers (or an agent relays, unchanged) a site-signed intent_required. Returns {status, body}.</summary>
    public static D Question(Func<string, TrustedChannel?> resolve, string sessionId, object? body)
    {
        var ch = resolve(sessionId);
        if (ch == null) return Resp(404, Err("unknown_session"));
        if (!WalletCore.IsObj(body)) return Resp(400, Err("bad_request"));
        foreach (var k in JsX.Keys(body)) if (k != "intent_required" && k != "action") return Resp(400, Err("bad_request", $"unknown member \"{k}\""));
        var action = ActionOf(WalletCore.G(body, "action"));
        if (action == null || !WalletCore.IsObj(WalletCore.G(body, "intent_required"))) return Resp(400, Err("bad_request"));
        var r = ch.Receive((D)WalletCore.G(body, "intent_required")!, action);
        if (r["ok"] is true) return Resp(202, new D { ["question_id"] = r["questionId"], ["friction"] = r["friction"] });
        var code = (string)r["code"]!;
        return Resp(StatusOfRefusal.GetValueOrDefault(code, 400), new D { ["error"] = code });
    }

    /// <summary>The clarification endpoint. Returns {status, body}.</summary>
    public static D Clarify(Func<string, TrustedChannel?> resolve, string sessionId, object? body)
    {
        var ch = resolve(sessionId);
        if (ch == null) return Resp(404, Err("unknown_session"));
        var r = ch.Clarify(body);
        if (r.Error != null) return Resp(400, Err("bad_request", r.Error));
        var b = new D { ["verdicts"] = r.ToJson()["verdicts"] };
        if (r.QuestionId != null) b["question_id"] = r.QuestionId;
        if (r.Refused != null) b["refused"] = r.Refused;
        return Resp(r.Status, b);
    }
}
