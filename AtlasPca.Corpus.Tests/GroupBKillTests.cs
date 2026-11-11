using System.Reflection;
using System.Text;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for K4, Decision, Assurance, A2a, Escalation, Blueprint, Agent and Keys. Every limit and message is the
/// reference's: pca-wallet/src/escalation-pricing.ts, pca-payments/src/network-token.ts, pca-erc7715/src/index.ts, pca/src/decision.ts,
/// pca/src/envelope-rules.ts, pca/src/assurance.ts, pca/src/pca-need.ts, pca-a2a/src/a2a-auth.ts, pca-a2a/src/a2a-receipt.ts,
/// pca/src/escalation.ts, pca-grants/src/blueprint.ts. Where a test says "not the reference" it pins a stricter .NET rule on purpose.</summary>
public class GroupBKillTests
{
    static EdKey Op => EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray());
    static EdKey Other => EdKey.FromSeed(Enumerable.Repeat((byte)8, 32).ToArray());

    static Num N(long v) => IntentJs.OfLong(v);

    sealed class Hostile : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a, string? b) => Armed ? throw new InvalidOperationException("hostile") : a == b;
        public int GetHashCode(string s) => Armed ? throw new InvalidOperationException("hostile") : 0;
    }

    // an empty dictionary answers a lookup without asking its comparer, so it holds one member before it turns hostile
    static JD HostileDict()
    {
        var h = new Hostile();
        var d = new JD(h) { ["x"] = null };
        h.Armed = true;
        return d;
    }

    // ------------------------------------------------------------------------------------------------ K4: pricing

    static string K4Sig(EdKey k, string kind, JD body) =>
        Pca.B64u(k.Sign(Encoding.UTF8.GetBytes(Pca.HashCanonical(new JD { ["kind"] = kind, ["body"] = body }))));

    static JD Cfg(Action<JD>? tweak = null)
    {
        var b = new JD
        {
            ["v"] = N(1), ["principal"] = Op.Id, ["currency"] = "USD", ["interruptionCost"] = N(5), ["maxInterruptionCost"] = N(10),
            ["hardCeilingLoss"] = N(1_000_000), ["tightenStepPpm"] = N(1000), ["epoch"] = N(1),
        };
        tweak?.Invoke(b);
        b["sig"] = K4Sig(Op, "pca.escalation_pricing", b);
        return b;
    }

    static JD Cal(long m) => new() { ["multiplierPpm"] = N(m) };

    [Fact]
    public void K4_AKeyOrSignatureThatDoesNotDecodeIsMalformedAndAWrongOneIsInvalid()
    {
        Assert.Null(K4.PricingConfigError(Cfg()));
        var badKey = Cfg(); badKey["principal"] = "!!!";
        Assert.Equal("config_malformed", K4.PricingConfigError(badKey));
        var badSig = Cfg(); badSig["sig"] = "!!!";
        Assert.Equal("config_malformed", K4.PricingConfigError(badSig));
        var otherKey = Cfg(); otherKey["principal"] = Other.Id;
        Assert.Equal("config_signature_invalid", K4.PricingConfigError(otherKey));
        Assert.Equal("config_malformed", K4.PricingConfigError(HostileDict()));
    }

    [Fact]
    public void K4_EveryIdentityMemberIsCheckedBeforeTheAmounts()
    {
        // no amounts at all: reading past the identity check would answer config_amounts_invalid
        JD Id(object? principal, object? currency, object? sig) => new() { ["v"] = N(1), ["principal"] = principal, ["currency"] = currency, ["sig"] = sig };
        Assert.Equal("config_amounts_invalid", K4.PricingConfigError(Id("p", "USD", "s")));
        Assert.Equal("config_malformed", K4.PricingConfigError(Id(N(1), "USD", "s")));
        Assert.Equal("config_malformed", K4.PricingConfigError(Id("p", N(1), "s")));
        Assert.Equal("config_malformed", K4.PricingConfigError(Id("p", "USD", N(1))));
    }

    [Fact]
    public void K4_CostMayEqualMaxAndTheStepBoundsAreInclusive()
    {
        Assert.Equal("config_step_invalid", K4.PricingConfigError(Cfg(b => { b["interruptionCost"] = N(10); b["tightenStepPpm"] = N(-1); })));
        Assert.Equal("config_cost_above_max", K4.PricingConfigError(Cfg(b => b["interruptionCost"] = N(11))));
        Assert.Null(K4.PricingConfigError(Cfg(b => b["interruptionCost"] = N(10))));

        Assert.Equal("config_step_invalid", K4.PricingConfigError(Cfg(b => b.Remove("tightenStepPpm"))));
        Assert.Equal("config_step_invalid", K4.PricingConfigError(Cfg(b => b["tightenStepPpm"] = "x")));
        Assert.Equal("config_step_invalid", K4.PricingConfigError(Cfg(b => b["tightenStepPpm"] = N(K4.MaxMultiplierPpm + 1))));
        Assert.Null(K4.PricingConfigError(Cfg(b => b["tightenStepPpm"] = N(0))));
        Assert.Null(K4.PricingConfigError(Cfg(b => b["tightenStepPpm"] = N(K4.MaxMultiplierPpm))));
    }

    [Fact]
    public void K4_AMissingProbabilityAsks()
    {
        var ask = new PricingVerdict(true, "risk_input_invalid");
        Assert.Equal(ask, K4.Decide(Cfg(), Cal(K4.Ppm), new JD { ["currency"] = "USD", ["loss"] = N(1) }));
        Assert.Equal(ask, K4.Decide(Cfg(), Cal(K4.Ppm), new JD { ["currency"] = "USD", ["loss"] = N(1), ["pBadUpperPpm"] = N(-1) }));
        Assert.Equal(ask, K4.Decide(Cfg(), Cal(K4.Ppm), new JD { ["currency"] = "USD", ["loss"] = N(1), ["pBadUpperPpm"] = N(K4.Ppm + 1) }));
        Assert.Equal(new PricingVerdict(false, "expected_loss_within_interruption_cost"), K4.Decide(Cfg(), Cal(K4.Ppm), new JD { ["currency"] = "USD", ["loss"] = N(1), ["pBadUpperPpm"] = N(K4.Ppm) }));
    }

    static JD Answer(string nonce, string answer = "deny", string digest = "d")
    {
        var b = new JD { ["v"] = N(1), ["principal"] = Op.Id, ["nonce"] = nonce, ["action_digest"] = digest, ["answer"] = answer };
        b["sig"] = K4Sig(Op, "pca.escalation_answer", b);
        return b;
    }

    static JD SafeRisk => new() { ["currency"] = "USD", ["loss"] = N(1), ["pBadUpperPpm"] = N(1) };

    static CalibrationState Fold(IReadOnlyDictionary<string, object?> risks, params object?[] answers) =>
        K4.UpdateCalibration(Cfg(), K4.Ppm, Array.Empty<string>(), answers, risks);

    [Fact]
    public void K4_ANonceOfEightCharactersCountsAndOneOfSevenDoesNot()
    {
        var risks = new JD { ["d"] = SafeRisk };
        var ok = Fold(risks, Answer("12345678"));
        Assert.Equal(K4.Ppm + 1000, ok.MultiplierPpm);
        Assert.Equal(new[] { "12345678" }, ok.Seen);
        var shortNonce = Fold(risks, Answer("1234567"));
        Assert.Equal(K4.Ppm, shortNonce.MultiplierPpm);
        Assert.Empty(shortNonce.Seen);
    }

    [Fact]
    public void K4_AnAnswerThatThrowsIsSkippedAndANullRiskTightensNothing()
    {
        var hostile = Fold(new JD { ["d"] = SafeRisk }, HostileDict());
        Assert.Equal(K4.Ppm, hostile.MultiplierPpm);
        Assert.Empty(hostile.Seen);
        var unsigned = Answer("12345678"); unsigned.Remove("sig");
        Assert.Empty(Fold(new JD { ["d"] = SafeRisk }, unsigned).Seen);

        var nullRisk = Fold(new JD { ["d"] = null }, Answer("12345678"));
        Assert.Equal(K4.Ppm, nullRisk.MultiplierPpm);
        Assert.Equal(new[] { "12345678" }, nullRisk.Seen);
        var unknown = Fold(new JD(), Answer("12345678"));
        Assert.Equal(K4.Ppm, unknown.MultiplierPpm);
        Assert.Equal(new[] { "12345678" }, unknown.Seen);
    }

    // ------------------------------------------------------------------------------------------------ K4: network token

    [Fact]
    public void K4_PanLengthBoundsAreInclusiveAndTheLuhnSumIsTheReal()
    {
        // 9 + (5 * 2 - 9) = 10: one doubled digit above 4, so halving it or adding 9 breaks the sum
        static string Pan(int zeros) => new string('0', zeros) + "59";
        Assert.False(K4.LooksLikePan(Pan(10))); // 12 digits
        Assert.True(K4.LooksLikePan(Pan(11)));  // 13
        Assert.True(K4.LooksLikePan(Pan(17)));  // 19
        Assert.False(K4.LooksLikePan(Pan(18))); // 20
        Assert.False(K4.LooksLikePan(new string('0', 11) + "58"));
        Assert.True(K4.LooksLikePan("4242424242424242"));
        Assert.False(K4.LooksLikePan("4242424242424241"));
    }

    [Fact]
    public void K4_OneRunIsEnoughAndNoRunIsNot()
    {
        Assert.True(K4.LooksLikePan("4242424242424242x1"));
        Assert.False(K4.LooksLikePan("abcdefgh"));
        Assert.True(K4.LooksLikePan("4242-4242 4242-4242"));
    }

    // network-token.ts: JavaScript \s includes U+FEFF, .NET \s does not (was a false negative here)
    [Fact]
    public void K4_AByteOrderMarkDoesNotHideAPan() => Assert.True(K4.LooksLikePan("4242﻿424242424242"));

    static readonly JD BGrant = new() { ["id"] = "g" };
    const string BNonce = "nonce-nonce-nonce";

    static JD Binding(object? holder, object? proof) => new()
    {
        ["kind"] = K4.BindingKind, ["provider"] = "p", ["token_ref"] = "tok_abcdefgh", ["grant_digest"] = Pca.HashCanonical(BGrant), ["issuer_nonce"] = BNonce, ["holder"] = holder, ["binding_proof"] = proof,
    };

    [Fact]
    public void K4_BindingProofAndHolderMustDecode()
    {
        var zeros = Pca.B64u(new byte[64]);
        Assert.Equal("binding_malformed", K4.VerifyBinding(Binding("!!!", zeros), BGrant, "!!!", BNonce, null));
        Assert.Equal("binding_malformed", K4.VerifyBinding(Binding(Op.Id, "!!!"), BGrant, Op.Id, BNonce, null));
        Assert.Equal("binding_malformed", K4.VerifyBinding(Binding(Op.Id, null), BGrant, Op.Id, BNonce, null));
        Assert.Equal("binding_proof_invalid", K4.VerifyBinding(Binding(Op.Id, zeros), BGrant, Op.Id, BNonce, null));
        Assert.Equal("binding_malformed", K4.VerifyBinding(HostileDict(), BGrant, Op.Id, BNonce, null));

        var body = new JD { ["kind"] = K4.BindingKind, ["v"] = N(1), ["provider"] = "p", ["token_ref"] = "tok_abcdefgh", ["grant_digest"] = Pca.HashCanonical(BGrant), ["issuer_nonce"] = BNonce, ["holder"] = Op.Id };
        var proof = Pca.B64u(Op.Sign(Encoding.UTF8.GetBytes(Pca.HashCanonical(body))));
        Assert.Null(K4.VerifyBinding(Binding(Op.Id, proof), BGrant, Op.Id, BNonce, null));
    }

    // ------------------------------------------------------------------------------------------------ K4: ERC-7715

    const string Mgr = "0x1111111111111111111111111111111111111111";
    const string OtherMgr = "0x2222222222222222222222222222222222222222";
    const string To = "0x3333333333333333333333333333333333333333";
    const string From = "0x4444444444444444444444444444aaaaaaaaaaaa";

    static JD Env => new() { ["grantDigest"] = "gd", ["expiresAtSec"] = N(200) };

    static JD SentReq(string? token = null)
    {
        var data = new JD { ["allowance"] = "0x10" };
        if (token != null) data["tokenAddress"] = token;
        return new() { ["chainId"] = "0x1", ["to"] = To, ["permission"] = new JD { ["type"] = "native-token-allowance", ["isAdjustmentAllowed"] = true, ["data"] = data } };
    }

    static JD Got(string? token = null)
    {
        var g = SentReq(token);
        g["context"] = "0xab";
        g["delegationManager"] = Mgr;
        g["rules"] = new JL { new JD { ["type"] = "expiry", ["data"] = new JD { ["timestamp"] = N(100) } } };
        return g;
    }

    static string? Vg(JD sent, object? got, params string[] managers) => K4.VerifyGranted(Env, sent, got, managers.Length == 0 ? new[] { Mgr } : managers, null);

    static JD PermOf(JD got) => (JD)got["permission"]!;

    [Fact]
    public void Erc7715_OneAllowedManagerIsEnoughAndNoneIsRefused()
    {
        Assert.Null(Vg(SentReq(), Got()));
        Assert.Null(Vg(SentReq(), Got(), OtherMgr, Mgr));
        Assert.Equal("delegation_manager_not_allowed", Vg(SentReq(), Got(), OtherMgr));
        Assert.Equal("delegation_manager_not_allowed", K4.VerifyGranted(Env, SentReq(), Got(), Array.Empty<string>(), null));
    }

    [Fact]
    public void Erc7715_AnAllowlistedManagerMustStillBeAnAddress()
    {
        foreach (var bad in new[] { "not-an-address", "0x" + new string('1', 39), "0x" + new string('1', 41), new string('1', 42), Mgr + "\n" })
        {
            var got = Got();
            got["delegationManager"] = bad;
            Assert.Equal("delegation_manager_not_allowed", Vg(SentReq(), got, bad));
        }
    }

    [Fact]
    public void Erc7715_FromIsComparedOnlyWhenSent()
    {
        var sent = SentReq(); sent["from"] = From;
        var same = Got(); same["from"] = From.ToUpperInvariant().Replace("0X", "0x");
        Assert.Null(Vg(sent, same));
        var other = Got(); other["from"] = To;
        Assert.Equal("from_mismatch", Vg(sent, other));
        Assert.Equal("from_mismatch", Vg(sent, Got()));
        var notString = Got(); notString["from"] = N(1);
        Assert.Equal("from_mismatch", Vg(sent, notString));
        Assert.Null(Vg(SentReq(), other));
    }

    // index.ts: lower(sent.x) of a non-string throws. These used to compare a missing value equal to a missing value and pass.
    [Fact]
    public void Erc7715_AMalformedRequestIsRefusedNotMatched()
    {
        var nullFrom = SentReq(); nullFrom["from"] = null;
        Assert.Equal("response_malformed", Vg(nullFrom, Got()));

        var noChain = SentReq(); noChain.Remove("chainId");
        var gotNoChain = Got(); gotNoChain.Remove("chainId");
        Assert.Equal("response_malformed", Vg(noChain, gotNoChain));

        var noTo = SentReq(); noTo.Remove("to");
        var gotNoTo = Got(); gotNoTo.Remove("to");
        Assert.Equal("response_malformed", Vg(noTo, gotNoTo));
    }

    [Fact]
    public void Erc7715_AMissingWalletValueNeverEqualsAnyRequestValue()
    {
        var emptyChain = SentReq(); emptyChain["chainId"] = "";
        var gotNoChain = Got(); gotNoChain.Remove("chainId");
        Assert.Equal("chain_mismatch", Vg(emptyChain, gotNoChain));
        var nul = SentReq(); nul["to"] = "\0";
        var gotNoTo = Got(); gotNoTo.Remove("to");
        Assert.Equal("recipient_mismatch", Vg(nul, gotNoTo));
    }

    [Fact]
    public void Erc7715_ComparisonFoldsToLowerCaseNotUpperCase()
    {
        // JavaScript toLowerCase: U+212A (Kelvin) folds to k; micro U+00B5 and Greek mu U+03BC stay different (they only meet in upper case)
        JD Sent(string c) { var s = SentReq(); s["chainId"] = c; return s; }
        JD Chain(string c) { var g = Got(); g["chainId"] = c; return g; }
        Assert.Null(Vg(Sent("0xab"), Chain("0XAB")));
        Assert.Null(Vg(Sent("k"), Chain("K")));
        Assert.Equal("chain_mismatch", Vg(Sent("µ"), Chain("μ")));
        Assert.Equal("token_mismatch", Vg(SentReq("µ"), Got("μ")));
        Assert.Null(Vg(SentReq("ABC"), Got("abc")));
    }

    [Fact]
    public void Erc7715_TheTokenIsItsJavaScriptText()
    {
        // String(d.tokenAddress ?? ''): an explicit empty token is no token
        Assert.Null(Vg(SentReq(), Got("")));
        Assert.Null(Vg(SentReq(""), Got()));
        // FAIL-OPEN fixed: a non-string token used to read as "" and pass a native-token request
        var numeric = Got();
        ((JD)PermOf(numeric)["data"]!)["tokenAddress"] = N(1);
        Assert.Equal("token_mismatch", Vg(SentReq(), numeric));
        Assert.Null(Vg(SentReq("1"), numeric));
    }

    [Fact]
    public void Erc7715_DataAndExpiryThatCannotBeReadAreMalformed()
    {
        // d.tokenAddress of undefined / null throws in the reference; of a string it is undefined
        var noData = Got(); PermOf(noData).Remove("data");
        Assert.Equal("response_malformed", Vg(SentReq(), noData));
        var nullData = Got(); PermOf(nullData)["data"] = null;
        Assert.Equal("response_malformed", Vg(SentReq(), nullData));
        var strData = Got(); PermOf(strData)["data"] = "x";
        Assert.Equal("amount_malformed", Vg(SentReq(), strData));

        // rule.data.timestamp, the same
        JD Rule(params (string, object?)[] m)
        {
            var g = Got();
            var r = new JD { ["type"] = "expiry" };
            foreach (var (k, v) in m) r[k] = v;
            g["rules"] = new JL { r };
            return g;
        }
        Assert.Equal("response_malformed", Vg(SentReq(), Rule()));
        Assert.Equal("response_malformed", Vg(SentReq(), Rule(("data", null))));
        Assert.Equal("expiry_malformed", Vg(SentReq(), Rule(("data", "x"))));
        Assert.Equal("expiry_malformed", Vg(SentReq(), Rule(("data", new JD()))));
        Assert.Equal("expiry_malformed", Vg(SentReq(), Rule(("data", new JD { ["timestamp"] = "x" }))));
        Assert.Null(Vg(SentReq(), Rule(("data", new JD { ["timestamp"] = N(200) }))));
        Assert.Equal("expiry_extended", Vg(SentReq(), Rule(("data", new JD { ["timestamp"] = N(201) }))));

        Assert.Equal("response_malformed", K4.VerifyGranted(new JD(), new JD(), HostileDict(), Array.Empty<string>(), null));
    }

    // ------------------------------------------------------------------------------------------------ Decision

    [Fact]
    public void Decision_MeetIsTheLowerAndAnUnknownIsDeny()
    {
        foreach (var (a, b, want) in new (string?, string?, string)[]
        {
            ("allow", "allow", "allow"), ("allow", "escalate", "escalate"), ("escalate", "allow", "escalate"), ("escalate", "escalate", "escalate"),
            ("allow", "deny", "deny"), ("deny", "allow", "deny"), ("deny", "escalate", "deny"), ("escalate", "deny", "deny"), ("deny", "deny", "deny"),
            (null, "allow", "deny"), ("allow", null, "deny"), ("x", "x", "deny"),
        })
            Assert.Equal(want, PcaDecision.Meet(a, b));
    }

    [Fact]
    public void Decision_SixtyFourUnitEntriesAreAllowed()
    {
        JD Units(int n)
        {
            var m = new JD();
            for (int i = 0; i < n; i++) m["action.params.p" + i] = new JD { ["kind"] = "k" };
            return m;
        }
        Assert.Null(PcaDecision.UnitTagsError(Units(64)));
        Assert.Equal("units has more than 64 entries", PcaDecision.UnitTagsError(Units(65)));
    }

    [Fact]
    public void Decision_ModelDerivedPaths()
    {
        Assert.False(PcaDecision.IsModelDerivedPath(N(5)));
        Assert.False(PcaDecision.IsModelDerivedPath(null));
        Assert.False(PcaDecision.IsModelDerivedPath("env"));
        Assert.False(PcaDecision.IsModelDerivedPath("foo.class"));
        Assert.True(PcaDecision.IsModelDerivedPath("env.class"));
        Assert.False(PcaDecision.IsModelDerivedPath("env.world"));
        Assert.True(PcaDecision.IsModelDerivedPath("env.world", new[] { "b" }));
        Assert.False(PcaDecision.IsModelDerivedPath("env.world.a", new[] { "b" }));
        Assert.True(PcaDecision.IsModelDerivedPath("env.world.a", new[] { "a" }));
    }

    static object Nest(int depth, string key)
    {
        object c = new JD { ["field"] = "env.class.x" };
        for (int i = 0; i < depth; i++) c = new JD { [key] = new JL { c } };
        return c;
    }

    [Theory]
    [InlineData("all_of")]
    [InlineData("any_of")]
    [InlineData("not")]
    public void Decision_TheWalkStopsPastDepthSixtyFour(string key)
    {
        static object W(object c) => new JL { new JD { ["where"] = new JL { c } } };
        object Wrapped(int d)
        {
            if (key != "not") return Nest(d, key);
            object c = new JD { ["field"] = "env.class.x" };
            for (int i = 0; i < d; i++) c = new JD { ["not"] = c };
            return c;
        }
        Assert.Equal(new[] { "env.class.x" }, PcaDecision.ModelPathsRead(new[] { W(Wrapped(64)) }));
        Assert.Empty(PcaDecision.ModelPathsRead(new[] { W(Wrapped(65)) }));
    }

    [Fact]
    public void Decision_AThrowingInputIsDeniedWithItsMessage()
    {
        var t = PcaDecision.DecideTighten(HostileDict());
        Assert.Equal("deny", t.Outcome);
        Assert.Equal("evaluation error (fail closed): hostile", t.Reason);
        var u = PcaDecision.DecideUnits(HostileDict());
        Assert.False(u.Ok);
        Assert.Equal("evaluation error (fail closed): hostile", u.Reason);
    }

    sealed class Text { public override string ToString() => "txt"; }
    sealed class NullText { public override string? ToString() => null; }

    [Fact]
    public void Decision_JsValueStringIsJavaScriptString()
    {
        Assert.Equal("null", PcaDecision.JsValueString(null));
        Assert.Equal("s", PcaDecision.JsValueString("s"));
        Assert.Equal("true", PcaDecision.JsValueString(true));
        Assert.Equal("false", PcaDecision.JsValueString(false));
        Assert.Equal(",true,a", PcaDecision.JsValueString(new JL { null, true, "a" }));
        Assert.Equal("1,,2", PcaDecision.JsValueString(new JL { new JL { N(1), null }, N(2) }));
        Assert.Equal("", PcaDecision.JsValueString(new JL()));
        Assert.Equal("[object Object]", PcaDecision.JsValueString(new JD()));
        Assert.Equal("5", PcaDecision.JsValueString(N(5)));
        Assert.Equal("1.5", PcaDecision.JsValueString(new Num("1.5")));
        Assert.Equal("7", PcaDecision.JsValueString(7L));
        Assert.Equal("1e+21", PcaDecision.JsValueString(1e21));
        Assert.Equal("NaN", PcaDecision.JsValueString(double.NaN));
        Assert.Equal("Infinity", PcaDecision.JsValueString(double.PositiveInfinity));
        Assert.Equal("-Infinity", PcaDecision.JsValueString(double.NegativeInfinity));
        Assert.Equal("txt", PcaDecision.JsValueString(new Text()));
        Assert.Equal("", PcaDecision.JsValueString(new NullText()));
    }

    static JD UnitsInput(JD units, JD schemaUnits, JD verbParams, JL? predicates = null)
    {
        var i = new JD { ["units"] = units, ["verb"] = "pay", ["schema_units"] = schemaUnits, ["verb_params"] = verbParams };
        if (predicates != null) i["predicates"] = predicates;
        return i;
    }

    [Fact]
    public void Decision_ATagWithoutAKindPrintsAQuestionMark()
    {
        const string P = "action.params.a";
        var tagged = new JD { [P] = new JD { ["kind"] = "usd" } };
        var prm = new JD { [P] = new JD { ["unit"] = "u" } };
        const string Want = "'action.params.a' is declared as ? by the action schema but the policy term is tagged usd (unit confusion)";
        Assert.Equal(Want, PcaDecision.DecideUnits(UnitsInput(tagged, new JD { ["u"] = new JD { ["kind"] = null } }, prm)).Reason);
        Assert.Equal(Want, PcaDecision.DecideUnits(UnitsInput(tagged, new JD { ["u"] = new JD() }, prm)).Reason);
        Assert.Equal("'action.params.a' is declared as x/null/e2 by the action schema but the policy term is tagged usd (unit confusion)",
            PcaDecision.DecideUnits(UnitsInput(tagged, new JD { ["u"] = new JD { ["kind"] = "x", ["currency"] = null, ["exponent"] = N(2) } }, prm)).Reason);
    }

    static bool StrictEq(object? a, object? b) =>
        (bool)typeof(PcaDecision).GetMethod("StrictEq", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new[] { a, b })!;

    // a policy tag holds only validated strings and integers, so booleans and null on its side need the direct seam
    [Fact]
    public void Decision_StrictEqIsTripleEquals()
    {
        Assert.True(StrictEq(true, true));
        Assert.True(StrictEq(false, false));
        Assert.False(StrictEq(true, false));
        Assert.False(StrictEq(true, "true"));
        Assert.True(StrictEq(null, null));
        Assert.False(StrictEq(null, "x"));
        Assert.True(StrictEq("a", "a"));
        Assert.False(StrictEq("a", "b"));
        Assert.True(StrictEq(N(1), new Num("1")));
        Assert.False(StrictEq(N(1), N(2)));
        Assert.False(StrictEq(new JD(), new JD()));
        Assert.False(StrictEq(new JL(), new JL()));
    }

    [Fact]
    public void Decision_UntaggedReadsReportTheFirstInSortOrderAndOnlyParamPathsCount()
    {
        var schema = new JD { ["u"] = new JD { ["kind"] = "usd" } };
        var two = new JD { ["action.params.a"] = new JD { ["unit"] = "u" }, ["action.params.b"] = new JD { ["unit"] = "u" } };
        var reads = new JL { new JL { new JD { ["verb"] = "pay", ["where"] = new JL { new JD { ["field"] = "action.params.b" }, new JD { ["field"] = "action.params.a" } } } } };
        Assert.Equal("a policy term reads 'action.params.a' (usd) without a unit tag", PcaDecision.DecideUnits(UnitsInput(new JD(), schema, two, reads)).Reason);

        var declared = new JD { ["params.x"] = new JD { ["unit"] = "u" } };
        var notParam = new JL { new JL { new JD { ["verb"] = "pay", ["where"] = new JL { new JD { ["field"] = "params.x" } } } } };
        var r = PcaDecision.DecideUnits(UnitsInput(new JD(), schema, declared, notParam));
        Assert.True(r.Ok);
        Assert.Null(r.Reason);
    }

    // ------------------------------------------------------------------------------------------------ Assurance

    static object Hook(string level) => AssuranceLabels.Set(new object(), new AssuranceLabel(level));

    static AssuranceReport Passing(string name, AssuranceSources s)
    {
        s.Checks = new[] { new KeyValuePair<string, string>(name, "pass") };
        return Assurance.BuildReport(s);
    }

    static AssuranceReport Rep(string name, CheckAssurance e)
    {
        var r = new AssuranceReport();
        r.Set(name, e);
        return r;
    }

    static CheckAssurance Pass(string? level) => new("pass") { Level = level };

    [Fact]
    public void Assurance_LabellingNothingNamesTheArgument() =>
        Assert.Equal("target", Assert.Throws<ArgumentNullException>(() => AssuranceLabels.Set<object>(null!, new AssuranceLabel("x"))).ParamName);

    [Fact]
    public void Assurance_FromJsonReadsEveryMember()
    {
        var r = AssuranceReport.FromJson(new JD
        {
            ["a"] = new JD
            {
                ["outcome"] = "pass", ["level"] = "L", ["vendor"] = "V", ["awaiting_audit"] = true, ["ceremony"] = "C", ["suites"] = new JL { "s", N(1), null },
                ["t"] = N(3), ["reason"] = "R", ["degraded"] = true,
            },
            ["b"] = new JD { ["preview"] = true },
            ["c"] = N(1),
        });
        var a = r.Get("a")!;
        Assert.Equal("pass", a.Outcome);
        Assert.Equal("L", a.Level);
        Assert.Equal("V", a.Vendor);
        Assert.True(a.AwaitingAudit);
        Assert.Equal("C", a.Ceremony);
        Assert.Equal(new[] { "s", "", "" }, a.Suites!);
        Assert.Equal(3.0, a.T);
        Assert.Equal("R", a.Reason);
        Assert.True(a.Degraded);
        Assert.True(r.Get("b")!.AwaitingAudit);
        Assert.Equal("", r.Get("b")!.Outcome);
        Assert.Null(r.Get("b")!.Suites);
        Assert.Equal("", r.Get("c")!.Outcome);
        Assert.False(r.Get("c")!.AwaitingAudit);
    }

    [Fact]
    public void Assurance_RequirementFromJson()
    {
        var q = AssuranceRequirement.FromJson(new JD { ["threshold"] = new JL { "a", N(1) }, ["allowPreview"] = true });
        Assert.Equal(new[] { "a", "" }, q.Threshold!);
        Assert.True(q.AllowAwaitingAudit);
        Assert.True(AssuranceRequirement.FromJson(new JD { ["allowAwaitingAudit"] = true }).AllowAwaitingAudit);
        Assert.False(AssuranceRequirement.FromJson(null).AllowAwaitingAudit);
    }

    [Theory]
    [InlineData("frost", true)]
    [InlineData("frost_dkg", true)]
    [InlineData("mpc", true)]
    [InlineData("multisig", false)]
    public void Assurance_TheSchemesAwaitingAudit(string level, bool want)
    {
        var r = Passing("threshold", new AssuranceSources { Hooks = new AssuranceHooks(Threshold: Hook(level)) });
        Assert.Equal(want, r.Get("threshold")!.AwaitingAudit);
    }

    [Fact]
    public void Assurance_SignatureLevels()
    {
        Assert.Equal("unknown", Assurance.SignatureLevel(N(5)));
        Assert.Equal("ed25519", Assurance.SignatureLevel(null));
        Assert.Equal("hybrid", Assurance.SignatureLevel("hybrid-ed25519-ml-dsa-65"));
        Assert.Equal("pq", Assurance.SignatureLevel("ml-dsa-65"));
        Assert.Equal("unknown", Assurance.SignatureLevel("nope"));
    }

    static CheckAssurance Chain(bool unbound, params object?[] algs)
    {
        var chain = new JL(algs.Select(a => (object?)(a == null ? new JD() : new JD { ["alg"] = a })));
        return Passing("cap_chain", new AssuranceSources { Pcactn = new JD { ["cap_chain"] = chain }, AllowUnboundPq = unbound }).Get("cap_chain")!;
    }

    [Fact]
    public void Assurance_ChainLevelIsTheWeakest()
    {
        Assert.Equal("unknown", Chain(false, null, "nope").Level);
        Assert.Equal("ed25519", Chain(false, "hybrid-ed25519-ml-dsa-65", null).Level);
        Assert.Equal("hybrid", Chain(false, "ml-dsa-65", "hybrid-ed25519-ml-dsa-65").Level);
        Assert.Equal("pq", Chain(false, "ml-dsa-65").Level);
        Assert.Equal("unknown", Chain(false).Level);
    }

    [Fact]
    public void Assurance_ChainIsUnboundWhenAnySuiteIsNotEd25519()
    {
        Assert.Equal("unbound_pq", Chain(true, "ml-dsa-65", null).Level);
        Assert.Equal("ed25519", Chain(true, null, "ed25519").Level);
        Assert.Equal("unknown", Chain(true).Level);
        Assert.Equal(new[] { "ml-dsa-65", "ed25519" }, Chain(true, "ml-dsa-65", null).Suites!);
    }

    [Fact]
    public void Assurance_MultiRootWithoutHardwareIsTheWeakestRoot()
    {
        var soft = new AttestationRoot(Hook("software"), true);
        var none = new AttestationRoot(null, true);
        Assert.Equal("software", Assurance.MultiRootLevel(new[] { soft }, 1));
        Assert.Equal("unknown", Assurance.MultiRootLevel(new[] { none }, 1));
        Assert.Equal("unknown", Assurance.MultiRootLevel(new[] { soft, none }, 2));
        Assert.Equal("software", Assurance.MultiRootLevel(Array.Empty<AttestationRoot>(), 0));
        Assert.Equal("hardware", Assurance.MultiRootLevel(new[] { new AttestationRoot(Hook("hardware"), true), soft }, 2));
    }

    // assurance.ts: `e.reason ?? ...`, `e.level ?? 'unknown'`, `label?.level ?? 'unknown'` are nullish tests: an empty string stays empty
    [Fact]
    public void Assurance_ReasonsDefaultOnlyWhenAbsent()
    {
        var empty = new AssuranceRequirement();
        Assert.Equal("assurance: unsupported: b (not implemented); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("unsupported")), empty));
        Assert.Equal("assurance: unsupported: b (why); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("unsupported") { Reason = "why" }), empty));
        Assert.Equal("assurance: unsupported: b (); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("unsupported") { Reason = "" }), empty));

        Assert.Equal("assurance: b rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("pass") { Degraded = true }), empty));
        Assert.Equal("assurance: b rests on a degraded compatibility mode (why); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("pass") { Degraded = true, Reason = "why" }), empty));
        Assert.Equal("assurance: b rests on a degraded compatibility mode (); a high-assurance policy never accepts it", Assurance.Unmet(Rep("b", new CheckAssurance("pass") { Degraded = true, Reason = "" }), empty));

        var att = new AssuranceRequirement(Attestation: "hardware");
        Assert.Equal("assurance: hardware attestation required but the evidence is unknown", Assurance.Unmet(Rep("attestation", Pass(null)), att));
        Assert.Equal("assurance: hardware attestation required but the evidence is software", Assurance.Unmet(Rep("attestation", Pass("software")), att));
        Assert.Equal("assurance: hardware attestation required but the evidence is ", Assurance.Unmet(Rep("attestation", Pass("")), att));
        Assert.Null(Assurance.Unmet(Rep("attestation", Pass("hardware")), att));

        Assert.Equal("", Passing("attestation", new AssuranceSources { AttestationHook = Hook("") }).Get("attestation")!.Level);
        Assert.Equal("unknown", Passing("attestation", new AssuranceSources { AttestationHook = new object() }).Get("attestation")!.Level);
    }

    [Fact]
    public void Assurance_AttestedVmHardwareNeedsABoundKey()
    {
        var q = new AssuranceRequirement(Zk: "attested_vm_hardware");
        const string Unbound = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence";
        Assert.Equal(Unbound, Assurance.Unmet(Rep("zk_compliance", Pass("attested_vm")), q));
        Assert.Equal(Unbound, Assurance.Unmet(Rep("zk_compliance", Pass("unknown")), q));
        Assert.Equal(Unbound, Assurance.Unmet(Rep("zk_compliance", Pass(null)), q));
        Assert.Equal("assurance: zk compliance (attested_vm_hardware) required but the evidence is ", Assurance.Unmet(Rep("zk_compliance", Pass("")), q));
        Assert.Null(Assurance.Unmet(Rep("zk_compliance", Pass("attested_vm_hw")), q));
        Assert.Null(Assurance.Unmet(Rep("zk_compliance", Pass("groth16")), q));
    }

    [Fact]
    public void Assurance_ThresholdSchemesAndAwaitingAudit()
    {
        var q = new AssuranceRequirement(Threshold: new[] { "multisig", "frost" });
        Assert.Equal("assurance: threshold (multisig | frost) required but there is no threshold evidence", Assurance.Unmet(new AssuranceReport(), q));
        Assert.Equal("assurance: threshold (multisig | frost) required but no threshold verifier enforced it", Assurance.Unmet(Rep("threshold", Pass(null)), q));
        Assert.Equal("assurance: threshold (multisig | frost) required but the scheme is mpc", Assurance.Unmet(Rep("threshold", Pass("mpc")), q));
        Assert.Null(Assurance.Unmet(Rep("threshold", new CheckAssurance("pass") { Level = "frost", AwaitingAudit = true }), q));
        Assert.Equal("assurance: threshold rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme to accept it",
            Assurance.Unmet(Rep("threshold", new CheckAssurance("pass") { Level = "frost", AwaitingAudit = true }), new AssuranceRequirement()));
    }

    // ------------------------------------------------------------------------------------------------ A2a: needs

    static JD Need(string kind = "scope", params (string, object?)[] extra)
    {
        var n = new JD { ["v"] = N(1), ["kind"] = kind, ["verb"] = "v", ["resource"] = "r" };
        foreach (var (k, x) in extra) n[k] = x;
        return n;
    }

    static JL Strs(int n) => new(Enumerable.Range(0, n).Select(i => (object?)("s" + i)));

    [Fact]
    public void A2a_EveryKindAndFieldBound()
    {
        Assert.Null(A2a.NeedError(Need("scope")));
        Assert.Null(A2a.NeedError(Need("grant")));
        Assert.Null(A2a.NeedError(Need("discharge")));
        Assert.Null(A2a.NeedError(Need("escalate", ("tier", N(2)))));
        Assert.Equal("bad_kind", A2a.NeedError(Need("nope")));

        var at = Need(); at["verb"] = new string('v', 128);
        Assert.Null(A2a.NeedError(at));
        var over = Need(); over["verb"] = new string('v', 129);
        Assert.Equal("bad_field", A2a.NeedError(over));
    }

    [Fact]
    public void A2a_ScopesAreBoundedAndEveryOneIsChecked()
    {
        Assert.Null(A2a.NeedError(Need("scope", ("scopes", Strs(16)))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("scopes", Strs(17)))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("scopes", new JL { "ok", "b c" }))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("scopes", new JL { "ok", "a﻿b" }))));
        Assert.Null(A2a.NeedError(Need("scope", ("scopes", new JL { "a\u0085b" })))); // JavaScript \s does not hold U+0085
    }

    [Theory]
    [InlineData("grant_ref")]
    [InlineData("policy_digest")]
    public void A2a_ReferenceFieldsAreBothChecked(string key)
    {
        Assert.Null(A2a.NeedError(Need("scope", (key, new string('a', 128)))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", (key, new string('a', 129)))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", (key, ""))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", (key, N(1)))));
    }

    [Fact]
    public void A2a_LimitsAreBoundedNonNegativeAndEveryOneIsChecked()
    {
        JD Lim(int n)
        {
            var m = new JD();
            for (int i = 0; i < n; i++) m["k" + i] = N(0);
            return m;
        }
        Assert.Null(A2a.NeedError(Need("scope", ("limits", Lim(16))))); // and zero is allowed
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("limits", Lim(17)))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("limits", new JD { ["a"] = N(1), ["b"] = N(-1) }))));
    }

    [Fact]
    public void A2a_DischargesAreBoundedAndEveryOneIsChecked()
    {
        static JD D() => new() { ["issuer"] = "i", ["claim"] = "c" };
        Assert.Null(A2a.NeedError(Need("scope", ("discharges", new JL(Enumerable.Range(0, 16).Select(_ => (object?)D()))))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("discharges", new JL(Enumerable.Range(0, 17).Select(_ => (object?)D()))))));
        Assert.Equal("bad_field", A2a.NeedError(Need("scope", ("discharges", new JL { D(), new JD { ["issuer"] = "i" } }))));
    }

    [Fact]
    public void A2a_DecodeBounds()
    {
        Assert.Equal("bad_json", A2a.DecodeNeed(new string('A', 2048)).Code); // 2048 passes the length test; NUL bytes are not JSON
        Assert.Equal("too_long", A2a.DecodeNeed(new string('A', 2049)).Code);
    }

    [Fact]
    public void A2a_TheResumeGateTakesNoEncodedNeedAsNoNeed()
    {
        Assert.Equal("no_valid_need", A2a.ResumeGate("TASK_STATE_AUTH_REQUIRED", null, "d", new JD()));
        var need = Need();
        var enc = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(need)));
        Assert.Null(A2a.ResumeGate("TASK_STATE_AUTH_REQUIRED", enc, A2a.NeedDigest(need), new JD { ["verb"] = "v", ["resource"] = "r" }));
    }

    [Fact]
    public void A2a_APushSaltOfSixteenIsEnough()
    {
        var ids = new[] { "c" };
        Assert.NotNull(A2a.PushToken("t", ids, new string('s', 16)));
        Assert.Null(A2a.PushToken("t", ids, new string('s', 15)));
    }

    // ------------------------------------------------------------------------------------------------ A2a: receipts

    static readonly string[] ChainIds = { "c" };
    static string Chain0 => PcaGrant.ChainDigest(ChainIds);
    static string Digest32 => Pca.B64u(new byte[32]);
    static readonly string[] ReceiptBody = { "v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer" };

    // signed by Op over whatever the tweak leaves, so only the shape checks can refuse it
    static JD Receipt(Action<JD>? tweak = null)
    {
        var r = new JD { ["v"] = N(1), ["task_id"] = "t", ["state"] = "TASK_STATE_WORKING", ["seq"] = N(0), ["prev"] = null, ["chain"] = Chain0, ["issued_at"] = N(1), ["signer"] = Op.Id };
        tweak?.Invoke(r);
        var body = new JD();
        foreach (var k in ReceiptBody) body[k] = r.GetValueOrDefault(k);
        r["sig"] = Issue.SignBody(Op, A2a.ReceiptDomain, body);
        return r;
    }

    static bool Rv(Action<JD>? tweak = null) => A2a.VerifyReceipt(Receipt(tweak), Op.Id);

    [Theory]
    [InlineData("TASK_STATE_SUBMITTED")]
    [InlineData("TASK_STATE_WORKING")]
    [InlineData("TASK_STATE_INPUT_REQUIRED")]
    [InlineData("TASK_STATE_AUTH_REQUIRED")]
    [InlineData("TASK_STATE_COMPLETED")]
    [InlineData("TASK_STATE_FAILED")]
    [InlineData("TASK_STATE_CANCELED")]
    [InlineData("TASK_STATE_REJECTED")]
    public void A2a_EveryStateIsAReceiptState(string state) => Assert.True(Rv(r => r["state"] = state));

    [Fact]
    public void A2a_EveryReceiptMemberIsChecked()
    {
        Assert.True(Rv());
        Assert.False(A2a.VerifyReceipt(N(1), Op.Id));
        Assert.False(Rv(r => r["v"] = N(2)));
        Assert.False(Rv(r => r["v"] = "1"));
        Assert.False(Rv(r => r["signer"] = Other.Id));
        Assert.False(Rv(r => r["task_id"] = ""));
        Assert.True(Rv(r => r["task_id"] = new string('t', 4096)));
        Assert.False(Rv(r => r["task_id"] = new string('t', 4097)));
        Assert.False(Rv(r => r["state"] = "nope"));
        Assert.False(Rv(r => r["state"] = N(1)));
        Assert.False(Rv(r => r["seq"] = "x"));
        Assert.False(Rv(r => r["seq"] = N(-1)));
        Assert.False(Rv(r => r["issued_at"] = "x"));
        Assert.False(Rv(r => r["chain"] = "short"));
        Assert.False(Rv(r => r["chain"] = N(1)));
    }

    [Fact]
    public void A2a_PrevMustMatchTheSequence()
    {
        Assert.False(Rv(r => r["prev"] = Digest32));                           // seq 0 with a prev
        Assert.False(Rv(r => r["seq"] = N(1)));                                // seq 1 without one
        Assert.False(Rv(r => { r["seq"] = N(1); r["prev"] = "bad"; }));        // not a digest
        Assert.True(Rv(r => { r["seq"] = N(1); r["prev"] = Digest32; }));
    }

    // FAIL-OPEN fixed. a2a-receipt.ts: r.prev === null, so an ABSENT prev is refused; it used to read as null here and the signature over prev:null still held
    [Fact]
    public void A2a_AnAbsentPrevIsNotANullPrev()
    {
        var r = Receipt();
        Assert.True(A2a.VerifyReceipt(r, Op.Id));
        r.Remove("prev");
        Assert.False(A2a.VerifyReceipt(r, Op.Id));
    }

    static A2aReceiptChain Rc(params JD[] rs) => A2a.CheckReceiptChain(rs.Cast<object?>().ToList(), Op.Id, "t", ChainIds);

    [Fact]
    public void A2a_ChainLinksNeedBothTheSequenceAndTheDigest()
    {
        var r0 = Receipt();
        Assert.Equal(new A2aReceiptChain(true, null, -1, false, "TASK_STATE_WORKING"), Rc(r0, Receipt(r => { r["seq"] = N(1); r["prev"] = A2a.ReceiptDigest(r0); })));
        Assert.Equal(new A2aReceiptChain(false, "broken_link", 1), Rc(r0, Receipt(r => { r["seq"] = N(2); r["prev"] = A2a.ReceiptDigest(r0); })));
        Assert.Equal(new A2aReceiptChain(false, "broken_link", 1), Rc(r0, Receipt(r => { r["seq"] = N(1); r["prev"] = Digest32; })));
        Assert.Equal(new A2aReceiptChain(true, null, -1, true, "TASK_STATE_COMPLETED"), Rc(Receipt(r => r["state"] = "TASK_STATE_COMPLETED")));
    }

    // ------------------------------------------------------------------------------------------------ Escalation

    static readonly JD EGrant = new() { ["id"] = "g" };

    static JD Pcactn(params (string, object?)[] action)
    {
        var a = new JD();
        foreach (var (k, v) in action) a[k] = v;
        return new JD { ["action"] = a };
    }

    static JD Req(string? aud = "a", long? ttl = null, string? render = null, JD? pcactn = null, IEnumerable<string>? reasons = null) =>
        Escalation.BuildRequest(aud, EGrant, pcactn ?? Pcactn(("verb", "pay"), ("resource", "res")), null, reasons ?? Array.Empty<string>(), 1000, ttl, render);

    [Fact]
    public void Escalation_RequestMembers()
    {
        var r = Req();
        Assert.Equal("a", r["aud"]);
        Assert.Equal("", Req(aud: null)["aud"]);
        Assert.Equal("pay", r["verb"]);
        Assert.Equal("res", r["resource"]);
        Assert.False(r.ContainsKey("render_digest"));
        Assert.False(r.ContainsKey(""));
        Assert.Equal("h", Req(render: "h")["render_digest"]);
    }

    // escalation.ts: String(a.pcactn?.action?.verb). JSON text was printed here before: "[]" for a list, "{}" for an object, "undefined" for null
    [Fact]
    public void Escalation_VerbAndResourceAreJavaScriptStrings()
    {
        Assert.Equal("undefined", Req(pcactn: Pcactn())["verb"]);
        Assert.Equal("undefined", Req(pcactn: new JD())["resource"]);
        Assert.Equal("null", Req(pcactn: Pcactn(("verb", null)))["verb"]);
        Assert.Equal("true", Req(pcactn: Pcactn(("verb", true)))["verb"]);
        Assert.Equal("false", Req(pcactn: Pcactn(("resource", false)))["resource"]);
        Assert.Equal("5", Req(pcactn: Pcactn(("verb", N(5))))["verb"]);
        Assert.Equal("1,2", Req(pcactn: Pcactn(("verb", new JL { N(1), N(2) })))["verb"]);
        Assert.Equal("[object Object]", Req(pcactn: Pcactn(("verb", new JD())))["verb"]);
    }

    [Fact]
    public void Escalation_ReasonsAreTheFirstSixteenCutAt512()
    {
        var reasons = Enumerable.Range(0, 17).Select(i => "r" + i).ToList();
        var got = (JL)Req(reasons: reasons)["reasons"]!;
        Assert.Equal(reasons.Take(16).Cast<object?>(), got);
        var cut = (JL)Req(reasons: new[] { new string('x', 513) })["reasons"]!;
        Assert.Equal(new string('x', 512), cut[0]);
    }

    // now + (ttl ?? one hour), escalation.ts:71
    [Fact]
    public void Escalation_RequestExpiry()
    {
        long Exp(long? ttl) => IntentJs.Lng(Req(ttl: ttl)["expires_at"]);
        Assert.Equal(1005, Exp(5));
        Assert.Equal(1000, Exp(0));
        Assert.Equal(999, Exp(-1));
        Assert.Equal(1000 + 3_600_000, Exp(null));
    }

    // a stricter rule than String(r).slice(0, n): a pair is never split, a lone surrogate cannot go on the wire
    [Fact]
    public void Escalation_TruncationNeverSplitsAPair()
    {
        Assert.Equal("abc", Escalation.TruncUtf16("abc", 3));
        Assert.Equal("ab\uD83D", Escalation.TruncUtf16("ab\uD83D", 3));
        Assert.Equal("ab", Escalation.TruncUtf16("abc", 2));
        Assert.Equal("a", Escalation.TruncUtf16("a😀b", 2));
        Assert.Equal("ab", Escalation.TruncUtf16("abc😀", 2));
    }

    [Fact]
    public void Escalation_TheClockBoundIsInclusiveAndAThrowFailsClosed()
    {
        var bind = new EscalationBinding("a", "b", "c");
        Assert.Equal("malformed escalation answer: not an object", Escalation.Verify(null, null, bind, Pca.MaxSafeInt).Reason);
        Assert.Equal("malformed escalation answer: not an object", Escalation.Verify(null, null, bind, -Pca.MaxSafeInt).Reason);
        Assert.Equal("the verifier clock is not a safe integer (fail closed)", Escalation.Verify(null, null, bind, Pca.MaxSafeInt + 1).Reason);
        var thrown = Escalation.Verify(null, null, bind, long.MinValue); // Math.Abs overflows
        Assert.False(thrown.Ok);
        Assert.StartsWith("escalation answer error (fail closed): ", thrown.Reason);
    }

    // ------------------------------------------------------------------------------------------------ Blueprint

    const string BpKey = "blueprint-key";

    static JD Bp(Action<JD>? tweak = null, EdKey? signer = null)
    {
        var k = signer ?? Op;
        var b = new JD { ["v"] = N(1), ["id"] = "bp", ["key"] = BpKey, ["ceiling"] = new JL(), ["epoch"] = N(1), ["status"] = "active", ["issued_at"] = N(1), ["operator"] = k.Id };
        tweak?.Invoke(b);
        b["sig"] = Issue.SignBody(k, Blueprint.Domain, b);
        return b;
    }

    static JL Ceiling(int n) => new(Enumerable.Range(0, n).Select(_ => (object?)new JD { ["type"] = "x" }));

    [Fact]
    public void Blueprint_EveryMemberIsChecked()
    {
        Assert.True(Blueprint.Verify(Bp()));
        Assert.False(Blueprint.Verify("x"));
        Assert.False(Blueprint.Verify(Bp(b => b["v"] = N(2))));
        Assert.False(Blueprint.Verify(Bp(b => b["v"] = "1")));
        Assert.False(Blueprint.Verify(Bp(b => b["id"] = "")));
        Assert.True(Blueprint.Verify(Bp(b => b["id"] = new string('i', 128))));
        Assert.False(Blueprint.Verify(Bp(b => b["id"] = new string('i', 129))));
        Assert.False(Blueprint.Verify(Bp(b => b["key"] = "")));
        Assert.False(Blueprint.Verify(Bp(b => b["operator"] = "")));
        Assert.False(Blueprint.Verify(Bp(b => b["epoch"] = "x")));
        Assert.False(Blueprint.Verify(Bp(b => b["issued_at"] = "x")));
        Assert.False(Blueprint.Verify(Bp(b => b["status"] = "x")));
        Assert.True(Blueprint.Verify(Bp(b => b["status"] = "disabled")));
        Assert.False(Blueprint.Verify(Bp(b => b["max_depth"] = N(0))));
        Assert.False(Blueprint.Verify(Bp(b => b["max_depth"] = "x")));
        Assert.True(Blueprint.Verify(Bp(b => b["max_depth"] = N(1))));
        Assert.False(Blueprint.Verify(Bp(b => b["expires_at"] = "x")));
        Assert.True(Blueprint.Verify(Bp(b => b["expires_at"] = N(5))));
        Assert.True(Blueprint.Verify(Bp(b => b["ceiling"] = Ceiling(32))));
        Assert.False(Blueprint.Verify(Bp(b => b["ceiling"] = Ceiling(33))));
    }

    [Fact]
    public void Blueprint_RegistryRefusalsAreNotOk()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        Assert.Equal(new BlueprintAccept(false, false, "bad_record"), reg.Accept("x"));
        Assert.Equal(new BlueprintAccept(false, false, "unknown_operator"), reg.Accept(Bp(signer: Other)));

        var two = new BlueprintRegistry(new[] { Op.Id, Other.Id }, new MemoryBlueprintStore());
        Assert.Equal(new BlueprintAccept(true, true, null), two.Accept(Bp(b => b["epoch"] = N(2))));
        Assert.Equal(new BlueprintAccept(false, false, "operator_changed"), two.Accept(Bp(b => b["epoch"] = N(3), Other)));
        Assert.Equal(new BlueprintAccept(false, false, "stale_epoch"), two.Accept(Bp()));
        Assert.Equal(new BlueprintAccept(false, false, "epoch_fork"), two.Accept(Bp(b => { b["epoch"] = N(2); b["status"] = "disabled"; })));
        Assert.Equal(new BlueprintAccept(true, false, null), two.Accept(Bp(b => b["epoch"] = N(2))));
        Assert.Equal(new BlueprintAccept(true, true, null), two.Accept(Bp(b => b["epoch"] = N(3))));
    }

    static JL Hops(object? issuer, object? holder) => new() { new JD { ["issuer"] = issuer, ["holder"] = holder } };

    [Fact]
    public void Blueprint_BothHopMembersAreInput()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        foreach (var hops in new[] { Hops("", "h"), Hops("i", ""), Hops(N(1), "h"), Hops("i", null) })
        {
            var d = Blueprint.Check(hops, reg, N(1), "any");
            Assert.Equal("deny", d.Decision);
            Assert.Equal("bad_input", d.Code);
        }
        Assert.Equal("allow", Blueprint.Check(Hops("i", "h"), reg, N(1), "any").Decision);
    }

    [Fact]
    public void Blueprint_ExpiryAppliesFromItsInstantOnly()
    {
        var reg = new BlueprintRegistry(new[] { Op.Id }, new MemoryBlueprintStore());
        Assert.True(reg.Accept(Bp(b => b["expires_at"] = N(100))).Ok);
        var chain = new JL { new JD { ["issuer"] = "root", ["holder"] = BpKey }, new JD { ["issuer"] = BpKey, ["holder"] = "inst" } };
        var before = Blueprint.Check(chain, reg, N(99), "require");
        Assert.Equal("allow", before.Decision);
        Assert.Equal(new[] { "bp" }, before.Governed!);
        var at = Blueprint.Check(chain, reg, N(100), "require");
        Assert.Equal("deny", at.Decision);
        Assert.Equal("blueprint_expired", at.Code);
        Assert.Equal("bp", at.Blueprint);
    }

    // ------------------------------------------------------------------------------------------------ Agent

    static SuiteKey Me => SuiteKey.Ed25519(Op);

    static JD MintedFor() => Issue.MintGrant(SuiteKey.Ed25519(Other), Op.Id, null, new JD
    {
        ["predicates"] = new JL { new JD { ["verb"] = "*" } }, ["caveats"] = new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    }, "goal", Pca.B64u(new byte[16])).Grant;

    static Agent NewAgent(long counter = 0) => new(Me, "aud", MintedFor(), null, counter) { Clock = () => 1000 };

    [Fact]
    public void Agent_AudIsRequired()
    {
        const string Msg = "Agent: aud (the resource server / instance id) is required";
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => new Agent(Me, "", new JD())).Message);
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => new Agent(Me, null!, new JD())).Message);
    }

    [Fact]
    public void Agent_ANonceFromTheSlotsWinsThenRandomUnlessDisabled()
    {
        var slot = new JD { ["nonce"] = "slot-nonce" };
        Assert.Equal("slot-nonce", NewAgent().Act("v", "r", null, slot)["nonce"]);
        var quiet = NewAgent(); quiet.Nonces = false;
        Assert.Equal("slot-nonce", quiet.Act("v", "r", null, slot)["nonce"]);
        var off = NewAgent(); off.Nonces = false;
        Assert.False(off.Act("v", "r").ContainsKey("nonce"));
        var random = (string)NewAgent().Act("v", "r")["nonce"]!;
        Assert.Equal(16, Pca.B64uDecode(random)!.Length);
    }

    [Fact]
    public void Agent_EverySlotReachesItsMember()
    {
        var slots = new JD
        {
            ["caution"] = new Num("0.5"), ["rationale_commitment"] = "rc", ["tool_binding"] = "tb", ["prohibition_evidence"] = new JD { ["m"] = "pe" },
            ["progress_step"] = new JD { ["m"] = "ps" }, ["intent"] = new JD { ["m"] = "in" }, ["intent_session"] = new JD { ["m"] = "is" }, ["fresh_at"] = new JD { ["m"] = "fa" },
            ["provenance"] = new JD { ["m"] = "pv" }, ["attestation"] = new JD { ["m"] = "at" }, ["freshness"] = new JD { ["m"] = "fr" }, ["risk_claim"] = new JD { ["m"] = "rk" },
        };
        var p = NewAgent().Act("v", "r", null, slots);
        foreach (var (k, v) in slots)
            Assert.Same(v, p[k]);
    }

    [Fact]
    public void Agent_ActNodeNeedsAPlan() =>
        Assert.Equal("CommitPlan() first", Assert.Throws<InvalidOperationException>(() => NewAgent().ActNode("n1")).Message);

    [Fact]
    public void Agent_TheAdHocNodeIsNamedAfterTheNextCounter()
    {
        var a = NewAgent(5);
        Assert.Equal("n6", ((JD)a.Act("v", "r")["plan"]!)["node_id"]);
        Assert.Equal(6, a.Counter);
        Assert.Equal("n7", ((JD)a.Act("v", "r")["plan"]!)["node_id"]);
    }

    [Fact]
    public void Agent_ADelegateNeedsAnEd25519Identity()
    {
        var pure = SuiteKey.Create("ml-dsa-65", null, Ml65());
        Assert.Equal("a delegate holder needs an Ed25519 identity", Assert.Throws<ArgumentException>(() => NewAgent().Delegate(pure)).Message);
    }

    // ------------------------------------------------------------------------------------------------ Keys

    static PqKey Ml65() => PqKey.Load(Pq.Prim.MlDsa65, new byte[Pq.Lens(Pq.Prim.MlDsa65).Pk], new byte[1]);

    [Fact]
    public void Keys_ASeedIs32Bytes()
    {
        const string Msg = "an Ed25519 seed is 32 bytes";
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => EdKey.FromSeed(null!)).Message);
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => EdKey.FromSeed(new byte[31])).Message);
        Assert.Equal(Msg, Assert.Throws<ArgumentException>(() => EdKey.FromSeed(new byte[33])).Message);
    }

    [Fact]
    public void Keys_GenerateUsesTheNamedSlhParameterSet()
    {
        Assert.Equal(Pq.Lens(Pq.Prim.Slh256s).Pk, PqKey.Generate(Pq.Prim.Slh256s).Pk.Length);
        Assert.Equal(Pq.Lens(Pq.Prim.Slh128f).Pk, PqKey.Generate(Pq.Prim.Slh128f).Pk.Length);
    }

    [Theory]
    [InlineData(Pq.Prim.None)]
    [InlineData(Pq.Prim.Less)]
    public void Keys_APrimitiveThatCannotSignIsRefused(Pq.Prim p)
    {
        var msg = $"cannot sign with {p} in this SDK";
        Assert.Equal(msg, Assert.Throws<ArgumentException>(() => PqKey.Generate(p)).Message);
        Assert.Equal(msg, Assert.Throws<ArgumentException>(() => PqKey.Load(p, new byte[Pq.Lens(p).Pk], new byte[1])).Message);
    }

    [Fact]
    public void Keys_LoadChecksThePublicKeyLength() =>
        Assert.Equal("wrong public key length for MlDsa65", Assert.Throws<ArgumentException>(() => PqKey.Load(Pq.Prim.MlDsa65, new byte[1], new byte[1])).Message);

    // Keys.cs promises deterministic signing; the wire does not need it, so this pins the SDK's own contract, not a shared vector
    [Theory]
    [InlineData(Pq.Prim.MlDsa65)]
    [InlineData(Pq.Prim.Slh128f)]
    public void Keys_SigningIsDeterministic(Pq.Prim p)
    {
        var k = PqKey.Generate(p);
        var m = Encoding.UTF8.GetBytes("message");
        var s = k.Sign(m);
        Assert.Equal(s, k.Sign(m));
        Assert.True(Pq.Verify(p, k.Pk, m, s));
    }

    [Fact]
    public void Keys_SuiteFactoryRefusals()
    {
        Assert.Equal("'ed25519' requires an Ed25519 key", Assert.Throws<ArgumentException>(() => SuiteKey.Create("ed25519", null, null)).Message);
        Assert.Equal("'hybrid-ed25519-ml-dsa-65' requires an Ed25519 key", Assert.Throws<ArgumentException>(() => SuiteKey.Create("hybrid-ed25519-ml-dsa-65", null, Ml65())).Message);
        Assert.Equal("ml-dsa-65", SuiteKey.Create("ml-dsa-65", null, Ml65()).Alg); // pure post-quantum needs no Ed25519 key
        Assert.Equal("'ml-dsa-65' requires a MlDsa65 key", Assert.Throws<ArgumentException>(() => SuiteKey.Create("ml-dsa-65", null, null)).Message);
        var ml87 = PqKey.Load(Pq.Prim.MlDsa87, new byte[Pq.Lens(Pq.Prim.MlDsa87).Pk], new byte[1]);
        Assert.Equal("'ml-dsa-65' needs a MlDsa65 key, got MlDsa87", Assert.Throws<ArgumentException>(() => SuiteKey.Create("ml-dsa-65", null, ml87)).Message);
    }

    // the LESS suites exist only when the native library loads, so a test suite of that primitive is registered for this one call (tests run serially, AssemblyInfo.cs)
    [Fact]
    public void Keys_LessCannotBeSigned()
    {
        Pq.SuitesHook = s => s["test-less"] = new Pq.Suite(1329, true, false, Pq.Prim.Less);
        try
        {
            Assert.Equal("LESS cannot be signed in this SDK", Assert.Throws<ArgumentException>(() => SuiteKey.Create("test-less", null, null)).Message);
        }
        finally { Pq.SuitesHook = null; }
    }

    [Fact]
    public void Keys_ThePqPinNeedsBothKeys()
    {
        var ml = Ml65();
        var pin = SuiteKey.Create("hybrid-ed25519-ml-dsa-65", Op, ml).PqPin();
        Assert.Single(pin);
        Assert.Equal(ml.PkB64u, pin[Op.Id]);
        Assert.Empty(SuiteKey.Ed25519(Op).PqPin());
        Assert.Empty(SuiteKey.Create("ml-dsa-65", null, ml).PqPin());
    }
}
