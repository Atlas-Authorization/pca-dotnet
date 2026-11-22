using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.IntentPkg;
using AtlasPca.Wallet;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the wallet side of the Intent Layer v2 (signed answers, friction tiers, cell coordinates, noise numerics,
/// canaries, approval fatigue, risk-priced escalation) against the TypeScript reference (test-data/ref-wallet.json.gz). Doubles from
/// transcendental functions compare to 1e-12 relative. A reference throw requires the native to throw.</summary>
public class RefWalletTests
{
    const string M = "ref-wallet";
    static D Om => (D)((D)Base.Of(M, "omegas").First()["out"]!);
    static Omega OmOf(object? o) => OmegaFromJson(o is string id ? Om[id] : Sub(o));
    static VerbSpace Vs(object? id, object? verb) => VerbSpaceOf(OmegaFromJson(Om[(string)id!]), (string)verb!)!;

    static byte[] Seed(object? k) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + (string)((D)k!)["$seed"]!));

    /// <summary>The $omega placeholder of a case argument (the $seed placeholders are resolved by <see cref="Seed"/>).</summary>
    static object? Sub(object? x) => x switch
    {
        L l => l.Select(Sub).ToList(),
        D m when m.Count == 1 && m.ContainsKey("$omega") => Om[(string)m["$omega"]!],
        D m => m.ToDictionary(e => e.Key, e => Sub(e.Value)),
        _ => x,
    };

    static object? N(double d) => IntentOmega.N(d);
    static int I(object? o) => (int)Dbl(o);
    static int[] Idx(object? o) => ((L)o!).Select(I).ToArray();
    static L Ints(IEnumerable<int> xs) => xs.Select(x => (object?)N(x)).ToList();
    static L Strs(IEnumerable<string> xs) => xs.Select(x => (object?)x).ToList();
    static D Dd(object? o) => (D)o!;
    static D? DOrNull(L a, int i) => a.Count > i && a[i] is D d ? d : null;

    /// <summary>JSON equality with numbers within 1e-12 relative. Only the diagnostic statistics (lnGamma, betacf, betaInc, betaQuantile, the binary entropy, the information gain, the clarification plan and the population noise)
    /// use it; every value that decides something (the exact Clopper-Pearson bounds, the noise estimate, the load-adjusted eta and the admission policy) is compared exactly.</summary>
    static bool Close(D c, object? have) => CloseV(c["out"], Base.Json(have));
    static bool CloseV(object? a, object? b)
    {
        if (a is Num x && b is Num y)
        {
            double p = IntentJs.NumOf(x)!.Value, q = IntentJs.NumOf(y)!.Value;
            return p == q || Math.Abs(p - q) <= 1e-12 * Math.Max(Math.Abs(p), Math.Abs(q)) || Math.Abs(p - q) <= 1e-15;
        }
        if (a is D da && b is D db) return da.Count == db.Count && da.All(e => db.TryGetValue(e.Key, out var v) && CloseV(e.Value, v));
        if (a is L la && b is L lb) return la.Count == lb.Count && la.Zip(lb).All(t => CloseV(t.First, t.Second));
        return Base.Show(a) == Base.Show(b);
    }


    // ---- friction / wire ----
    [Fact] public void IsFrictionTierFn() => Base.Check(M, "isFrictionTier", a => WalletCore.IsFrictionTier(a[0]));
    [Fact] public void FrictionRankFn() => Base.Check(M, "frictionRank", a => WalletCore.FrictionRank(a[0]));
    [Fact] public void MaxFrictionFn() => Base.Check(M, "maxFriction", a => WalletCore.MaxFriction(a.ToArray()));
    [Fact] public void SatisfiesTierFn() => Base.Check(M, "satisfiesTier", a => WalletCore.SatisfiesTier(a[0], a[1]));
    [Fact] public void IsProvenanceLevelFn() => Base.Check(M, "isProvenanceLevel", a => WalletCore.IsProvenanceLevel(a[0]));
    [Fact] public void WorstProvenanceFn() => Base.Check(M, "worstProvenance", a => WalletCore.WorstProvenance(a[0]));
    [Fact] public void FrictionForFn() => Base.Check(M, "frictionFor", a => WalletCore.FrictionFor(Dd(a[0]), DOrNull(a, 1)));
    [Fact] public void PcaActionDigestFn() => Base.Check(M, "pcaActionDigest", a => WalletCore.PcaActionDigest(a[0]));
    [Fact] public void ActionValuesOfFn() => Base.Check(M, "actionValuesOf", a => WalletCore.ActionValuesOf(a[0]));
    [Fact] public void IsB64u32Fn() => Base.Check(M, "isB64u32", a => WalletCore.IsB64u32(a[0]));
    [Fact] public void IsObjFn() => Base.Check(M, "isObj", a => WalletCore.IsObj(a[0]));
    [Fact] public void CoordsErrorFn() => Base.Check(M, "coordsError", a => WalletCore.CoordsError(a[0]));
    [Fact] public void AnswerShapeErrorFn() => Base.Check(M, "answerShapeError", a => WalletCore.AnswerShapeError(a[0]));
    [Fact] public void SignIntentAnswerFn() => Base.Check(M, "signIntentAnswer", a => WalletCore.SignIntentAnswer(Dd(a[0]), Seed(a[1])));

    [Fact]
    public void VerifyIntentAnswerFn() => Base.Check(M, "verifyIntentAnswer", a =>
    {
        var r = WalletCore.VerifyIntentAnswer(a[0], a.Count > 1 && a[1] is L p ? p.Select(x => (string)x!).ToList() : null);
        return r["ok"] is false && ((string)r["reason"]!).StartsWith("malformed answer:", StringComparison.Ordinal) ? new D { ["ok"] = false, ["reason"] = "malformed answer" } : r;
    });

    [Fact] public void AnswerRefFn() => Base.Check(M, "answerRef", a => WalletCore.AnswerRef(a[0]));
    [Fact] public void TypedDigestFn() => Base.Check(M, "typedDigest", a => WalletCore.TypedDigest(a[0], a[1]));
    [Fact] public void DeviceChallengeFn() => Base.Check(M, "deviceChallenge", a =>
    {
        var m = Dd(a[0]);
        return WalletCore.DeviceChallenge(m["questionId"], m["renderedDigest"], m["y"], m.GetValueOrDefault("actionDigest"));
    });

    // ---- stats ----
    [Fact] public void LnGammaFn() => Base.Check(M, "lnGamma", a => N(WalletCore.LnGamma(Dbl(a[0]))), Close);
    [Fact] public void BetacfFn() => Base.Check(M, "betacf", a => N(WalletCore.Betacf(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);
    [Fact] public void BetaIncFn() => Base.Check(M, "betaInc", a => N(WalletCore.BetaInc(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);
    [Fact] public void BetaQuantileFn() => Base.Check(M, "betaQuantile", a => N(WalletCore.BetaQuantile(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);
    [Fact] public void ClopperPearsonUpperFn() => Base.Check(M, "clopperPearsonUpper", a => N(WalletCore.ClopperPearsonUpper(a[0], a[1], a[2])));
    [Fact] public void BinEntFn() => Base.Check(M, "binEnt", a => N(WalletCore.BinEnt(Dbl(a[0]))), Close);

    // ---- canaries, noise, fatigue ----
    [Fact] public void RecordCanaryFn() => Base.Check(M, "recordCanary", a => WalletCore.RecordCanary(Dd(a[0]), a[1], a[2]));
    [Fact] public void EstimateNoiseFn() => Base.Check(M, "estimateNoise", a => WalletCore.EstimateNoise(Dd(a[0]), a.Count > 1 ? Dbl(a[1]) : 0.05));
    [Fact] public void CellKeyFn() => Base.Check(M, "cellKey", a => WalletCore.CellKey(a[0], (L)a[1]!));

    static WalletCore.CellRef Ref(object? o) => new((string)Dd(o)["verb"]!, Idx(Dd(o)["idx"]));
    static L RefsOut(IEnumerable<WalletCore.CellRef> rs) => rs.Select(r => (object?)new D { ["verb"] = r.Verb, ["idx"] = Ints(r.Idx) }).ToList();

    [Fact] public void BoundaryNeighboursFn() => Base.Check(M, "boundaryNeighbours", a =>
        RefsOut(WalletCore.BoundaryNeighbours(OmOf(a[0]), ((L)a[1]!).Select(Ref).ToList())));

    [Fact]
    public void PickCanaryFn() => Base.Check(M, "pickCanary", a =>
    {
        var ctx = Dd(Sub(a[0]));
        var rands = ((L)ctx["rands"]!).Select(Dbl).ToList();
        int i = 0;
        var knownNo = Dd(ctx["knownNo"]);
        var c = new WalletCore.CanaryCtx
        {
            Omega = OmegaFromJson(ctx["omega"]),
            Confirmed = ((L)ctx["confirmed"]!).Select(Ref).ToList(),
            KnownNo = (v, idx) => knownNo.TryGetValue(WalletCore.CellKey(v, idx), out var w) ? w as string : null,
            KnownYes = ((L)ctx["knownYes"]!).Select(Ref).ToList(),
            Exclude = ((L)ctx["exclude"]!).Select(x => (string)x!).ToHashSet(),
            Rand = () => i < rands.Count ? rands[i++] : throw new InvalidOperationException("rand exhausted"),
            Rho = ctx.TryGetValue("rho", out var rho) ? Dbl(rho) : null,
            LowHarmSession = ctx["lowHarmSession"] is true,
            CanariesSoFar = Dbl(ctx["canariesSoFar"]),
        };
        return WalletCore.PickCanary(c) is { } r ? new D { ["verb"] = r.Verb, ["idx"] = Ints(r.Idx), ["expected"] = N(r.Expected), ["source"] = r.Source } : null;
    });

    [Fact] public void EtaUnderLoadFn() => Base.Check(M, "etaUnderLoad", a => N(WalletCore.EtaUnderLoad(a[0], a[1], a[2])));
    [Fact] public void NoiseStateFn() => Base.Check(M, "noiseState", a => WalletCore.NoiseState(Dd(a[0]), a[1], DOrNull(a, 2)));
    [Fact] public void AdmissionPolicyFn() => Base.Check(M, "admissionPolicy", a => WalletCore.AdmissionPolicy(Dd(a[0]), DOrNull(a, 1)));
    [Fact] public void DoubleConfirmedFn() => Base.Check(M, "doubleConfirmed", a => WalletCore.DoubleConfirmed((L)a[0]!));

    [Fact]
    public void SlidingWindowFn() => Base.Check(M, "slidingWindow", a =>
    {
        var c = a[0] == null ? new WalletCore.SlidingWindowCounter() : new WalletCore.SlidingWindowCounter(Dbl(a[0]));
        var o = new L();
        foreach (var op in (L)a[1]!)
        {
            var ol = (L)op!;
            try { o.Add(new D { ["v"] = (string)ol[0]! == "count" ? N(c.Count(Dbl(ol[1]))) : c.TryAdd(Dbl(ol[1]), Dbl(ol[2])) }); }
            catch (Exception) { o.Add(new D { ["err"] = true }); }
        }
        return o;
    });

    // ---- risk-priced escalation ----
    [Fact] public void SignPricingConfigFn() => Base.Check(M, "signPricingConfig", a => WalletPricing.SignPricingConfig(Dd(a[0]), Seed(a[1])));
    [Fact] public void PricingConfigErrorFn() => Base.Check(M, "pricingConfigError", a => WalletPricing.PricingConfigError(a[0]));
    [Fact] public void FreshCalibrationFn() => Base.Check(M, "freshCalibration", a => WalletPricing.FreshCalibration());
    [Fact] public void DecideEscalationFn() => Base.Check(M, "decideEscalation", a => WalletPricing.DecideEscalation(Dd(a[0]), a[1], a[2]));
    [Fact] public void SignAnswerFn() => Base.Check(M, "signAnswer", a => WalletPricing.SignAnswer(Dd(a[0]), Seed(a[1])));
    [Fact] public void UpdateCalibrationFn() => Base.Check(M, "updateCalibration", a => WalletPricing.UpdateCalibration(Dd(a[0]), Dd(a[1]), (L)a[2]!, Dd(a[3])));
    [Fact] public void SignAutonomyRaiseFn() => Base.Check(M, "signAutonomyRaise", a => WalletPricing.SignAutonomyRaise(Dd(a[0]), Seed(a[1])));
    [Fact] public void ApplyAutonomyRaiseFn() => Base.Check(M, "applyAutonomyRaise", a => WalletPricing.ApplyAutonomyRaise(Dd(a[0]), Dd(a[1]), Seed(a[2])));

    // ---- cell coordinates ----
    [Fact] public void CoordKeyOfFn() => Base.Check(M, "coordKeyOf", a => WalletCore.CoordKeyOf((string)a[0]!));

    static IReadOnlyList<IReadOnlyList<int>> Box(object? o) => ((L)o!).Select(x => (IReadOnlyList<int>)Idx(x)).ToList();

    [Fact]
    public void ResolveCoordsFn() => Base.Check(M, "resolveCoords", a =>
    {
        var r = WalletCore.ResolveCoords(OmOf(a[0]), a[1], a[2]);
        return r.Ok ? new D { ["ok"] = true, ["verb"] = r.Vs!.Verb, ["box"] = r.Box!.Select(b => (object?)Ints(b)).ToList() } : new D { ["ok"] = false, ["reason"] = r.Reason };
    });

    [Fact] public void CoordsOfBoxFn() => Base.Check(M, "coordsOfBox", a => WalletCore.CoordsOfBox(Vs(a[0], a[1]), Box(a[2])));
    [Fact] public void CoordsOfCellFn() => Base.Check(M, "coordsOfCell", a => WalletCore.CoordsOfCell(Vs(a[0], a[1]), Idx(a[2])));
    [Fact] public void CellInBoxFn() => Base.Check(M, "cellInBox", a => WalletCore.CellInBox(Box(a[0]), Idx(a[1])));
    [Fact] public void BoxCellsFn() => Base.Check(M, "boxCells", a => WalletCore.BoxCells(Box(a[0])).Select(c => (object?)Ints(c)).ToList());
    [Fact] public void BoxSizeFn() => Base.Check(M, "boxSize", a => N(WalletCore.BoxSize(Box(a[0]))));
    [Fact] public void CellOfActionFn() => Base.Check(M, "cellOfAction", a =>
        WalletCore.CellOfAction(OmegaFromJson(Om[(string)a[0]!]), a[1]) is { } r ? new D { ["verb"] = r.Vs.Verb, ["idx"] = Ints(r.Idx) } : null);
    [Fact] public void FlatIndexFn() => Base.Check(M, "flatIndex", a => N(WalletCore.FlatIndex(Vs(a[0], a[1]), Idx(a[2]))));

    // ---- the outcome space as the wallet reaches it ----
    static Dim DimOf(object? id, object? verb, object? k) => Vs(id, verb).Dims[I(k)];
    [Fact] public void OmegaVerbCellCountFn() => Base.Check(M, "omega.verbCellCount", a => N(VerbCellCount(Vs(a[0], a[1]))));
    [Fact] public void OmegaCellCountFn() => Base.Check(M, "omega.cellCount", a => N(CellCount(DimOf(a[0], a[1], a[2]))));
    [Fact]
    public void OmegaNumCellsFn() => Base.Check(M, "omega.numCells", a =>
        NumCells((NumDim)DimOf(a[0], a[1], a[2])).Select(c => (object?)new D { ["lo"] = N(c.Lo), ["hi"] = N(c.Hi) }).ToList());
    [Fact] public void OmegaLabelOfFn() => Base.Check(M, "omega.labelOf", a => IntentRender.LabelOf((string)a[0]!));
    [Fact] public void OmegaDecodeCellFn() => Base.Check(M, "omega.decodeCell", a => Ints(DecodeCell(Vs(a[0], a[1]), Dbl(a[2]))));
    [Fact] public void OmegaCellStatsFn() => Base.Check(M, "omega.cellStats", a => StatsToJson(CellStats(Vs(a[0], a[1]), Idx(a[2]))), Close);
    [Fact] public void OmegaCellRepFn() => Base.Check(M, "omega.cellRep", a => OutcomeToJson(CellRep(Vs(a[0], a[1]), Idx(a[2]))));
    [Fact] public void OmegaCellOfFn() => Base.Check(M, "omega.cellOf", a => CellOf(Vs(a[0], a[1]), OutcomeFromJson(a[2])) is { } r ? Ints(r) : null);

    // ---- the card and clarification ----
    static D CardIn(object? x)
    {
        var m = Dd(x);
        var o = new D { ["omega"] = OmegaFromJson(Om[(string)m["omegaId"]!]) };
        foreach (var (k, v) in m) if (k != "omegaId") o[k] = v;
        return o;
    }

    [Fact] public void CleanTextFn() => Base.Check(M, "cleanText", a => WalletCard.CleanText(a[0], I(a[1])));
    [Fact] public void Last4Fn() => Base.Check(M, "last4", a => WalletCard.Last4(a[0]));
    [Fact] public void FormatNumberFn() => Base.Check(M, "formatNumber", a => WalletCard.FormatNumber(Dbl(a[0]), a.Count > 1 ? a[1] : null));
    [Fact] public void RenderCardFn() => Base.Check(M, "renderCard", a => WalletCard.RenderCard(CardIn(a[0])));
    [Fact] public void CardDigestFn() => Base.Check(M, "cardDigest", a => WalletCard.CardDigest(Dd(a[0])));
    [Fact] public void CardDigestMatchesFn() => Base.Check(M, "cardDigestMatches", a => WalletCard.CardDigestMatches(Dd(a[0])));
    [Fact] public void CardTextFn() => Base.Check(M, "cardText", a => WalletCard.CardText(Dd(a[0])));
    [Fact] public void PartialErrorFn() => Base.Check(M, "partialError", a => WalletCard.PartialError(Dd(a[0]), a[1]));
    [Fact] public void NormalizeTypedFn() => Base.Check(M, "normalizeTyped", a => WalletCard.NormalizeTyped(a[0], a[1], a.Count > 2 ? a[2] : null));
    [Fact] public void ExpectedTypedFn() => Base.Check(M, "expectedTyped", a => WalletCard.ExpectedTyped(Dd(a[0]), a[1]));
    [Fact] public void ParseClarifyRequestFn() => Base.Check(M, "parseClarifyRequest", a => WalletCard.ParseClarifyRequest(a[0]));
    [Fact] public void InformationGainFn() => Base.Check(M, "informationGain", a => N(WalletCard.InformationGain(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);

    /// <summary>A grant view over a case table: p by cell key (default 0), the vetoed and ceiling key lists, the confirmed cells.</summary>
    sealed class TableView(D v) : IGrantView
    {
        public double P(string verb, int[] idx) => v["p"] is D p && p.TryGetValue(WalletCore.CellKey(verb, idx), out var x) && x != null ? Dbl(x) : 0;
        public bool Vetoed(string verb, int[] idx) => Has(v, "vetoed", verb, idx);
        public bool OutsideCeiling(string verb, int[] idx) => Has(v, "ceiling", verb, idx);
        public IReadOnlyList<WalletCore.CellRef> Confirmed() => v.GetValueOrDefault("confirmed") is L l ? l.Select(Ref).ToList() : new List<WalletCore.CellRef>();
        static bool Has(D v, string list, string verb, int[] idx) { var key = WalletCore.CellKey(verb, idx); return v[list] is L l && l.Any(k => k is string s && s == key); }
    }

    [Fact]
    public void PlanClarificationFn() => Base.Check(M, "planClarification", a =>
    {
        var x = Dd(a[0]);
        var plan = WalletCard.PlanClarification(OmOf(x["omega"]), new TableView(Dd(x["view"])), (L)x["candidates"]!, null,
            ((L)x["asked"]!).Select(k => (string)k!).ToHashSet(), Dbl(x["etaPos"]), Dbl(x["etaNeg"]));
        return plan.ToJson();
    }, Close);

    // ---- population priors ----
    static Func<double> Seq(L xs) { int i = 0; return () => i < xs.Count ? Dbl(xs[i++]) : throw new InvalidOperationException("rand exhausted"); }

    [Fact] public void GaussianSigmaFn() => Base.Check(M, "gaussianSigma", a => N(WalletPopulation.GaussianSigma(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);
    [Fact] public void GaussianFn() => Base.Check(M, "gaussian", a => N(WalletPopulation.Gaussian(Seq((L)a[0]!))), Close);
    [Fact] public void RrKeepProbabilityFn() => Base.Check(M, "rrKeepProbability", a => N(WalletPopulation.RrKeepProbability(Dbl(a[0]))), Close);
    [Fact] public void RandomizedResponseFn() => Base.Check(M, "randomizedResponse", a => N(WalletPopulation.RandomizedResponse(I(a[0]), Dbl(a[1]), () => Dbl(a[2]))));
    [Fact] public void DebiasRandomizedResponseFn() => Base.Check(M, "debiasRandomizedResponse", a => N(WalletPopulation.DebiasRandomizedResponse(Dbl(a[0]), Dbl(a[1]), Dbl(a[2]))), Close);
    [Fact] public void PopulationCellKeyFn() => Base.Check(M, "populationCellKey", a => WalletPopulation.PopulationCellKey((string)a[0]!, Vs(a[1], a[2]), Idx(a[3])));

    [Fact]
    public void AggregateFn() => Base.Check(M, "aggregate", a =>
    {
        var opts = Dd(a[2]);
        var agg = new PopulationAggregator((string)a[0]!, a[1], opts.TryGetValue("maxCellsPerPrincipal", out var mc) ? (double?)Dbl(mc) : null, Seq((L)a[5]!));
        var votes = ((L)a[3]!).Select(v => (object?)agg.Contribute(Dd(v))).ToList();
        var rel = Dd(a[4]);
        object? release;
        try
        {
            release = agg.Release(Dbl(rel["epsilon"]), Dbl(rel["delta"]), rel.TryGetValue("qMin", out var q) ? (double?)Dbl(q) : null, rel.TryGetValue("minCount", out var m) ? (double?)Dbl(m) : null);
        }
        catch (Exception) { release = new D { ["err"] = true }; }
        return new D { ["votes"] = votes, ["release"] = release };
    }, Close);

    [Fact]
    public void PopulationPriorFn() => Base.Check(M, "populationPrior", a =>
    {
        var pm = WalletPopulation.PopulationPrior(Dd(a[0]), Dbl(a[1]));
        var inSet = ((L)a[4]!).Select(I).ToHashSet();
        return new D { ["beta"] = N(pm.Beta), ["weight"] = N(pm.Weight(Vs(a[2], a[3]), c => inSet.Contains(c))) };
    }, Close);

    // ---- delivery ----
    [Fact] public void SiteQuestionNoticeFn() => Base.Check(M, "siteQuestionNotice", a => WalletDelivery.SiteQuestionNotice(Dd(a[0]), a[1], a[2], a[3], a.Count > 4 ? a[4] : null));
    [Fact] public void ClarificationNoticeFn() => Base.Check(M, "clarificationNotice", a => WalletDelivery.ClarificationNotice(a[0], a[1], a.Count > 2 ? a[2] : null));
    [Fact] public void QuestionTextFn() => Base.Check(M, "questionText", a => WalletDelivery.QuestionText(Dd(a[0]), (string)a[1]!));

    static L Deliver(IQuestionChannel ch, L notices) => notices.Select(n => (object?)ch.NotifyAsync(Dd(n)).GetAwaiter().GetResult()).ToList();

    [Fact]
    public void WebhookChannelFn() => Base.Check(M, "webhookChannel", a =>
    {
        var cfg = Dd(a[0]);
        var script = (L)a[1]!;
        var calls = new L();
        int i = 0;
        WebhookFetch tr = (url, method, headers, body) =>
        {
            calls.Add(new D { ["url"] = url, ["method"] = method, ["headers"] = new D(headers), ["body"] = body });
            var step = i < script.Count ? Dd(script[i++]) : new D { ["ok"] = true, ["status"] = N(200) };
            if (step.GetValueOrDefault("throw") is string t) throw new InvalidOperationException(t);
            return Task.FromResult(new TransportResult(step["ok"] is true, I(step["status"])));
        };
        var cfgHeaders = cfg.GetValueOrDefault("headers") is D h ? h.ToDictionary(e => e.Key, e => (string)e.Value!) : null;
        var ch = WalletDelivery.QuestionWebhookChannel(cfg.GetValueOrDefault("url") as string, cfgHeaders, tr);
        var deliveries = Deliver(ch, (L)a[2]!);
        return new D { ["kind"] = ch.Kind, ["enabled"] = ch.Enabled, ["deliveries"] = deliveries, ["calls"] = calls };
    });

    [Fact]
    public void TextChannelFn() => Base.Check(M, "textChannel", a =>
    {
        var script = a[2] as L;
        var sent = new L();
        int i = 0;
        TextSender? send = script == null ? null : body =>
        {
            sent.Add(body);
            var st = i < script.Count ? script[i] : null;
            i++;
            if (st is D sd && sd.GetValueOrDefault("throw") is string t) throw new InvalidOperationException(t);
            return Task.CompletedTask;
        };
        var ch = WalletDelivery.QuestionTextChannel((string)a[0]!, send, (string)a[1]!);
        var deliveries = Deliver(ch, (L)a[3]!);
        return new D { ["kind"] = ch.Kind, ["enabled"] = ch.Enabled, ["deliveries"] = deliveries, ["sent"] = sent };
    });

    [Fact]
    public void DispatcherFn() => Base.Check(M, "dispatcher", a =>
    {
        var chans = new List<IQuestionChannel>();
        foreach (var co in (L)a[0]!)
        {
            var c = Dd(co);
            var type = (string)c["type"]!;
            chans.Add(type == "webhook"
                ? WalletDelivery.QuestionWebhookChannel(c.GetValueOrDefault("url") as string, null, (u, m, h, b) => Task.FromResult(new TransportResult(true, 200)))
                : WalletDelivery.QuestionTextChannel(type, c.GetValueOrDefault("enabled") is true ? (TextSender)(b => Task.CompletedTask) : null, "S"));
        }
        var deliveries = WalletDelivery.NotifyAllAsync(chans, Dd(a[1])).GetAwaiter().GetResult();
        return new D { ["n"] = N(chans.Count), ["deliveries"] = deliveries.Select(d => (object?)d).ToList() };
    });

    // ---- the question channel (scenarios) ----
    static byte[] SeedOf(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    [Fact] public void ChannelFn() => Base.Check(M, "channel", a => RunScenario(Dd(Sub(a[0]))), Close);

    static D RunScenario(D spec)
    {
        var hourly = spec.GetValueOrDefault("windowMs") is { } wm ? new WalletCore.SlidingWindowCounter(Dbl(wm)) : new WalletCore.SlidingWindowCounter();
        foreach (var ts in (L)spec["hourlyPre"]!) hourly.TryAdd(Dbl(ts), 9007199254740991.0);
        double t = Dbl(spec["t0"]);
        var counts = Dd(spec["noise"]);
        var map = (string)spec["mapDigest"]!;
        var site = Dd(spec["site"]);
        var caps = spec.GetValueOrDefault("caps") as D;
        var dm = spec.GetValueOrDefault("device") as D;
        var dev = dm == null ? null : new DeviceTrust
        {
            RpId = (string)dm["rpId"]!, Origins = (L)dm["origins"]!, Credentials = Dd(dm["credentials"]), SignCounts = dm.GetValueOrDefault("signCounts") is D sc ? new D(sc) : null,
        };
        Func<D, D>? lift = null;
        if (spec.GetValueOrDefault("lift") is D lm)
        {
            var add = Dd(lm["add"]);
            lift = act =>
            {
                var v = WalletCore.ActionValuesOf(act);
                var vals = new D(Dd(v["values"]));
                foreach (var (k, x) in add) vals[k] = x;
                return new D { ["verb"] = v["verb"], ["values"] = vals };
            };
        }
        Func<D, D>? liftCand = null;
        if (spec.GetValueOrDefault("liftCand") is D lc)
            liftCand = c =>
            {
                var vals = new D(Dd(c["values"]));
                foreach (var (k, x) in lc) vals[k] = x;
                return new D { ["verb"] = c["verb"], ["values"] = vals };
            };
        var opts = new ChannelOptions
        {
            Omega = OmegaFromJson(spec["omega"]), Session = (string)spec["session"]!, MapDigest = () => map, PrincipalSecret = SeedOf((string)spec["principal"]!),
            SiteOrigin = (string)site["origin"]!, SiteName = (string)site["name"]!, SiteKeys = site["keys"],
            StatementText = spec.GetValueOrDefault("statementText") as string, Units = spec.GetValueOrDefault("units") as D, Sensitivity = spec.GetValueOrDefault("sensitivity") as D,
            IdentityPaths = (spec.GetValueOrDefault("identityPaths") as L)?.Select(x => (string)x!).ToList(), View = new TableView(Dd(spec["view"])),
            Lift = lift, LiftCandidate = liftCand, Hourly = hourly, Noise = () => counts, OnNoise = n => counts = n, Rand = Seq((L)spec["rands"]!), Now = () => t,
            PerSession = caps != null && caps.TryGetValue("perSession", out var ps) ? I(ps) : 6, PerHour = caps != null && caps.TryGetValue("perHour", out var ph) ? I(ph) : 12,
            Rho = spec.GetValueOrDefault("rho") is { } rho ? (double?)Dbl(rho) : null, Fatigue = spec.GetValueOrDefault("fatigue") as D, Device = dev,
            MaxPerScreen = spec.GetValueOrDefault("maxPerScreen") is { } mps ? I(mps) : 3, MaxBoxCells = spec.GetValueOrDefault("maxBoxCells") is { } mbc ? I(mbc) : 4096,
        };
        var ch = new TrustedChannel(opts);
        var seen = new List<string>();
        var steps = new L();
        Func<string, TrustedChannel?> resolver = sid => sid == opts.Session ? ch : null;
        foreach (var so in (L)spec["steps"]!)
        {
            var st = Dd(so);
            var op = (string)st["op"]!;
            object? r;
            try
            {
                string? qid = st.GetValueOrDefault("q") is { } qi ? (I(qi) < seen.Count ? seen[I(qi)] : null) : st.GetValueOrDefault("qid") as string;
                switch (op)
                {
                    case "time": t = Dbl(st["t"]); r = new D { ["t"] = st["t"] }; break;
                    case "receive": r = ch.Receive(Dd(st["ir"]), Dd(st["action"])); break;
                    case "next":
                        {
                            var scr = ch.NextScreen();
                            if (scr != null) foreach (var q in (L)scr["questions"]!) seen.Add((string)Dd(q)["questionId"]!);
                            r = scr;
                            break;
                        }
                    case "answer": r = ch.Answer(qid, Dd(st["response"])); break;
                    case "clarify": r = ch.Clarify(st.GetValueOrDefault("body")).ToJson(); break;
                    case "hQuestion": r = WalletHandlers.Question(resolver, st.GetValueOrDefault("sid") as string ?? opts.Session, st.GetValueOrDefault("body")); break;
                    case "hClarify": r = WalletHandlers.Clarify(resolver, st.GetValueOrDefault("sid") as string ?? opts.Session, st.GetValueOrDefault("body")); break;
                    case "summary": r = ch.Summary(); break;
                    case "state": r = new D { ["digest"] = ch.StateDigest(), ["asked"] = N(ch.QuestionsAsked()) }; break;
                    case "noise": r = new D { ["noise"] = ch.Noise(), ["admission"] = ch.Admission() }; break;
                    case "challenge": r = ch.DeviceChallengeFor(qid); break;
                    default: throw new InvalidOperationException("bad op " + op);
                }
            }
            catch (Exception) { r = new D { ["$err"] = true }; }
            steps.Add(new D { ["op"] = op, ["r"] = r });
        }
        return new D { ["steps"] = steps, ["noise"] = counts, ["signCounts"] = dev?.SignCounts };
    }

    [Fact]
    public void ConstantsFn()
    {
        var want = Dd(Base.Of(M, "constants").First()["out"]);
        var have = new D
        {
            ["FRICTION_ORDER"] = Strs(WalletCore.FrictionOrder), ["INTENT_ANSWER_SIG_DOMAIN"] = WalletCore.IntentAnswerSigDomain,
            ["INTENT_ANSWER_REF_DOMAIN"] = WalletCore.IntentAnswerRefDomain, ["INTENT_TYPED_DOMAIN"] = WalletCore.IntentTypedDomain,
            ["INTENT_DEVICE_CHALLENGE_DOMAIN"] = WalletCore.IntentDeviceChallengeDomain, ["MIN_HOLD_MS"] = N(WalletCore.MinHoldMs),
            ["PROVENANCE_ORDER"] = Strs(WalletCore.ProvenanceOrder), ["DEFAULT_FRICTION_THRESHOLDS"] = WalletCore.DefaultFrictionThresholds(),
            ["EMPTY_NOISE"] = WalletCore.EmptyNoise(), ["NOISE_PRIOR"] = WalletCore.NoisePrior(), ["DEFAULT_FATIGUE"] = WalletCore.DefaultFatigue(),
            ["PPM"] = N(WalletPricing.Ppm), ["MAX_MULTIPLIER_PPM"] = N(WalletPricing.MaxMultiplierPpm),
            ["CARD_DOMAIN"] = WalletCard.CardDomain, ["CLARIFY_REASONS"] = Strs(WalletCard.ClarifyReasons), ["REASON_LABELS"] = WalletCard.ReasonLabels(),
            ["MAX_CANDIDATES"] = N(WalletCard.MaxCandidates),
            ["POPULATION_VOTE_DOMAIN"] = WalletPopulation.PopulationVoteDomain, ["BETA_MAX"] = N(WalletPopulation.BetaMax),
        };
        foreach (var (k, v) in have) Assert.True(Base.Eq(want[k], v), k);
    }

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "omegas", "constants", "isFrictionTier", "frictionRank", "isProvenanceLevel", "worstProvenance", "satisfiesTier", "maxFriction", "frictionFor", "pcaActionDigest",
        "actionValuesOf", "isB64u32", "isObj", "coordsError", "answerShapeError", "signIntentAnswer", "verifyIntentAnswer", "answerRef", "typedDigest", "deviceChallenge",
        "lnGamma", "betaInc", "betacf", "betaQuantile", "clopperPearsonUpper", "binEnt", "recordCanary", "estimateNoise", "cellKey", "boundaryNeighbours", "pickCanary",
        "etaUnderLoad", "noiseState", "admissionPolicy", "doubleConfirmed", "slidingWindow", "signPricingConfig", "pricingConfigError", "freshCalibration",
        "decideEscalation", "signAnswer", "updateCalibration", "signAutonomyRaise", "applyAutonomyRaise", "omega.verbCellCount", "omega.cellCount", "omega.numCells",
        "omega.labelOf", "omega.decodeCell", "omega.cellStats", "omega.cellRep", "omega.cellOf", "coordKeyOf", "resolveCoords", "coordsOfBox", "coordsOfCell",
        "cellInBox", "boxCells", "boxSize", "cellOfAction", "flatIndex",
        "cleanText", "last4", "formatNumber", "renderCard", "cardDigest", "cardDigestMatches", "cardText", "partialError", "normalizeTyped", "expectedTyped",
        "parseClarifyRequest", "informationGain", "planClarification",
        "siteQuestionNotice", "clarificationNotice", "questionText", "webhookChannel", "textChannel", "dispatcher", "channel",
        "gaussianSigma", "gaussian", "rrKeepProbability", "randomizedResponse", "debiasRandomizedResponse", "populationCellKey", "aggregate", "populationPrior",
    }); Assert.Equal(7360, Base.Total(M)); }
}
