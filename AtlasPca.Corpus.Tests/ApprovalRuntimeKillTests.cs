using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Pinned to packages/pca/src/approval-render.ts, packages/pca-actions/src/approval-render.ts + approval-profiles.ts and
// packages/pca-sandbox/src/runtime-claim.ts. The .NET claim bounds (128-char strings, non-negative iat/exp/now) are stricter than the
// reference on purpose.
public class ApprovalRuntimeKillTests
{
    const long MaxSafe = 9007199254740991;

    static object? N(long v) => IntentJs.OfLong(v);
    static string Digest(byte b) => Pca.B64u(Enumerable.Repeat(b, 32).ToArray());

    static void Kit(string code, string message, Action f)
    {
        var e = Assert.Throws<ActionKitError>(f);
        Assert.Equal(code, e.Code);
        Assert.Equal(message, e.Message);
    }

    static void Unlinkable(string message, Action f) => Kit("psd2_unlinkable", message, f);

    static void Arg(string message, Action f)
    {
        var e = Assert.Throws<ArgumentException>(f);
        Assert.Equal(message, e.Message);
    }

    // ---- render values ------------------------------------------------------------------------------------------------

    static D F(string id, string cls, object? value) => new() { ["id"] = id, ["class"] = cls, ["value"] = value };
    static D MoneyUnit(string ccy = "USD", long exp = 2) => new() { ["kind"] = "money", ["ccy"] = ccy, ["exp"] = N(exp) };
    static D Amt(object? value, object? unit)
    {
        var f = F("amount", "money.amount", value);
        f["unit"] = unit;
        return f;
    }
    static D Payee(object? value) => F("payee", "party.payee", value);
    static D Rn(L fields, object? unreviewed = null) => new()
    {
        ["v"] = N(1), ["kind"] = "pca-approval-render", ["verb"] = "acme.pay.send", ["def_digest"] = Digest(9), ["unreviewed"] = unreviewed ?? false, ["fields"] = fields,
    };
    static D Pay(long minor = 1250, string payee = "alice", string ccy = "USD", long exp = 2) => Rn(new L { Amt(N(minor), MoneyUnit(ccy, exp)), Payee(payee) });
    static string Link(long minor = 1250, string payee = "alice", string ccy = "USD", long exp = 2) =>
        K05.Show(new D { ["amount_minor"] = N(minor), ["currency"] = ccy, ["exp"] = N(exp), ["payee"] = payee });

    // ---- the render's shape --------------------------------------------------------------------------------------------

    [Fact]
    public void AMoneyUnitIsExactlyKindCcyExp()
    {
        Assert.Null(Approval.RenderShapeError(Pay()));
        const string Bad = "a money unit needs ccy and exp";
        var noCcy = MoneyUnit();
        noCcy.Remove("ccy");
        var noExp = MoneyUnit();
        noExp.Remove("exp");
        var extra = MoneyUnit();
        extra["x"] = N(1);
        foreach (var u in new[] { noCcy, noExp, extra })
            Assert.Equal(Bad, Approval.RenderShapeError(Rn(new L { Amt(N(1), u), Payee("a") })));
    }

    [Fact]
    public void AnOtherUnitIsExactlyAKnownKind()
    {
        foreach (var k in new[] { "count", "bytes", "duration", "ratio" })
        {
            Assert.Null(Approval.RenderShapeError(Rn(new L { Amt(N(1), new D { ["kind"] = k }) })));
            Assert.Equal("unknown unit", Approval.RenderShapeError(Rn(new L { Amt(N(1), new D { ["kind"] = k, ["x"] = N(1) }) })));
        }
        Assert.Equal("unknown unit", Approval.RenderShapeError(Rn(new L { Amt(N(1), new D { ["kind"] = "other" }) })));
        Assert.Equal("unknown unit", Approval.RenderShapeError(Rn(new L { Amt(N(1), new D()) })));
    }

    // ---- H(R), the challenge, the words ---------------------------------------------------------------------------------

    [Fact]
    public void AShapelessRenderHasNoDigest()
    {
        Arg("approvalRenderDigest: render must be an object", () => Approval.RenderDigest(5));
        var extra = Pay();
        extra["x"] = N(1);
        Arg("approvalRenderDigest: unknown member 'render.x'", () => Approval.RenderDigest(extra));
    }

    [Fact]
    public void TheChallengeNeedsBothDigests()
    {
        const string Bad = "approvalChallenge: both digests must be canonical 32-byte values";
        var ok = Digest(1);
        foreach (var bad in new object?[] { null, 5, "", "AAAA", Pca.B64u(new byte[31]) })
        {
            Arg(Bad, () => Approval.Challenge(bad, ok));
            Arg(Bad, () => Approval.Challenge(ok, bad));
            Arg(Bad, () => Approval.Challenge(bad, bad));
        }
        var a = Enumerable.Repeat((byte)1, 32).ToArray();
        var r = Enumerable.Repeat((byte)2, 32).ToArray();
        var want = Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca/approval-challenge/v1\0").Concat(a).Concat(r).ToArray()));
        Assert.Equal(want, Approval.Challenge(Digest(1), Digest(2)));
    }

    [Fact]
    public void TheWordsNeedACanonicalDigest()
    {
        const string Bad = "bindingWords: render digest must be a canonical 32-byte value";
        foreach (var bad in new object?[] { null, 5, "", "AAAA", Pca.B64u(new byte[31]) })
            Arg(Bad, () => Approval.BindingWords(bad));
        var bytes = new byte[32];
        bytes[1] = 1;
        bytes[2] = 2;
        bytes[3] = 3;
        bytes[4] = 4;
        bytes[5] = 255;
        Assert.Equal("able-acid-aged-also-area-nice", Approval.BindingWords(Pca.B64u(bytes)));
    }

    // ---- renderApproval -------------------------------------------------------------------------------------------------

    static D Def(D prms) => new()
    {
        ["kind"] = Actions.ActionDefKind, ["verb"] = "acme.pay.send", ["title"] = "t", ["effects"] = new L { "send" },
        ["resource"] = new D { ["type"] = "thing", ["id"] = new D(), ["scope"] = "one" }, ["params"] = prms,
    };
    static D Typed(string type) => new() { ["type"] = type };
    static string BadValue(string id, string type) => $"'{id}' is not a {type} in the canonical domain (no floats, no null, no lone surrogates)";

    [Fact]
    public void ParamsMustBeAnObject()
    {
        Kit("render_bad_params", "params must be an object", () => Approval.Render(Def(new D()), 5));
        Kit("render_bad_params", "params must be an object", () => Approval.Render(Def(new D()), null));
    }

    [Fact]
    public void ADottedKeyIsRefusedAtEveryLevel()
    {
        var d = Def(new D { ["to.iban"] = Typed("string") });
        Kit("render_bad_params", "the parameter key 'to.iban' contains a dot", () => Approval.Render(d, new D { ["to.iban"] = "x" }));
        Kit("render_bad_params", "the parameter key 'a.b' contains a dot", () => Approval.Render(d, new D { ["to"] = new D { ["a.b"] = "x" } }));
    }

    [Fact]
    public void NestedKeysJoinWithADotAndAnEmptyPrefixAddsNone()
    {
        var nested = Approval.Render(Def(new D { ["to.iban"] = Typed("string") }), new D { ["to"] = new D { ["iban"] = "x" } });
        Assert.Equal(K05.Show(new L { F("to.iban", "param", "x") }), K05.Show(nested["fields"]));
        // the reference's walk: prefix === '' ? k : prefix + '.' + k, so a member of the "" key is the bare name
        var bare = Approval.Render(Def(new D { ["x"] = Typed("integer") }), new D { [""] = new D { ["x"] = N(5) } });
        Assert.Equal(K05.Show(new L { F("x", "param", N(5)) }), K05.Show(bare["fields"]));
    }

    [Fact]
    public void AnUndeclaredParameterIsRefused() =>
        Kit("render_undeclared_param", "'x' is not a parameter of acme.pay.send", () => Approval.Render(Def(new D()), new D { ["x"] = "v" }));

    [Fact]
    public void ARequiredParameterFollowsTheReferencesTruthiness()
    {
        foreach (var marker in new object?[] { true, null, N(1), "yes", new L(), new D() })
        {
            var p = Typed("string");
            p["required"] = marker;
            Kit("render_missing_param", "required parameter 'x' of acme.pay.send is missing", () => Approval.Render(Def(new D { ["x"] = p }), new D()));
        }
        var dflt = Typed("string");
        Kit("render_missing_param", "required parameter 'x' of acme.pay.send is missing", () => Approval.Render(Def(new D { ["x"] = dflt }), new D()));
        foreach (var marker in new object?[] { false, N(0), "" })
        {
            var p = Typed("string");
            p["required"] = marker;
            Assert.Empty((L)Approval.Render(Def(new D { ["x"] = p }), new D())["fields"]!);
        }
    }

    [Fact]
    public void AnUnknownTypeIsNeverACanonicalValue()
    {
        Kit("render_bad_value", BadValue("x", "uuid"), () => Approval.Render(Def(new D { ["x"] = Typed("uuid") }), new D { ["x"] = "v" }));
        Kit("render_bad_value", BadValue("x", "integer"), () => Approval.Render(Def(new D { ["x"] = Typed("integer") }), new D { ["x"] = "v" }));
    }

    [Fact]
    public void ANullRoleReadsAsParam()
    {
        var role = Typed("integer");
        role["role"] = null;
        Assert.Equal(K05.Show(new L { F("x", "param", N(5)) }), K05.Show(Approval.Render(Def(new D { ["x"] = role }), new D { ["x"] = N(5) })["fields"]));
        var named = Typed("integer");
        named["role"] = "custom.role";
        Assert.Equal(K05.Show(new L { F("x", "custom.role", N(5)) }), K05.Show(Approval.Render(Def(new D { ["x"] = named }), new D { ["x"] = N(5) })["fields"]));
    }

    [Fact]
    public void AnUnresolvedCurrencyIsRefused()
    {
        D Prms() => new()
        {
            ["amount"] = new D { ["type"] = "integer", ["unit"] = new D { ["kind"] = "money", ["ccy"] = new D { ["from"] = "cur" }, ["exp"] = N(2) } },
            ["cur"] = new D { ["type"] = "string", ["required"] = false },
        };
        const string Bad = "the currency of 'amount' is not a string";
        Kit("render_unresolved_currency", Bad, () => Approval.Render(Def(Prms()), new D { ["amount"] = N(5) }));
        Kit("render_unresolved_currency", Bad, () => Approval.Render(Def(Prms()), new D { ["amount"] = N(5), ["cur"] = "" }));
        var r = Approval.Render(Def(Prms()), new D { ["amount"] = N(5), ["cur"] = "EUR" });
        var f = (D)((L)r["fields"]!)[0]!;
        Assert.Equal(K05.Show(MoneyUnit("EUR", 2)), K05.Show(f["unit"]));
    }

    // ---- PSD2 linking ---------------------------------------------------------------------------------------------------

    [Fact]
    public void TheLinkingViewIsExactlyAmountCurrencyExpPayee()
    {
        Assert.Equal(Link(), K05.Show(Approval.Psd2Linking(Pay())));
        Assert.Equal(Link(0, "b", "EUR", 3), K05.Show(Approval.Psd2Linking(Pay(0, "b", "EUR", 3))));
        Assert.Equal(Link(MaxSafe), K05.Show(Approval.Psd2Linking(Pay(MaxSafe))));
    }

    [Fact]
    public void AnAbsentUnitMemberStaysAbsentAndAPresentOneIsCopied()
    {
        D Linked(D unit) => Approval.Psd2Linking(Rn(new L { Amt(N(5), unit), Payee("p") }));
        Assert.Equal(K05.Show(new D { ["amount_minor"] = N(5), ["payee"] = "p" }), K05.Show(Linked(new D { ["kind"] = "money" })));
        Assert.Equal(K05.Show(new D { ["amount_minor"] = N(5), ["currency"] = "USD", ["payee"] = "p" }), K05.Show(Linked(new D { ["kind"] = "money", ["ccy"] = "USD" })));
        Assert.Equal(K05.Show(new D { ["amount_minor"] = N(5), ["exp"] = N(2), ["payee"] = "p" }), K05.Show(Linked(new D { ["kind"] = "money", ["exp"] = N(2) })));
        Assert.Equal(K05.Show(new D { ["amount_minor"] = N(5), ["currency"] = null, ["exp"] = null, ["payee"] = "p" }), K05.Show(Linked(new D { ["kind"] = "money", ["ccy"] = null, ["exp"] = null })));
    }

    [Fact]
    public void AnyTruthyUnreviewedMarkerRefuses()
    {
        const string Bad = "an unreviewed definition cannot be a payment approval";
        foreach (var marker in new object?[] { true, "x", N(1), new L(), new D() })
        {
            var r = Pay();
            r["unreviewed"] = marker;
            Unlinkable(Bad, () => Approval.Psd2Linking(r));
        }
        foreach (var marker in new object?[] { false, "", N(0), null })
        {
            var r = Pay();
            r["unreviewed"] = marker;
            Assert.Equal(Link(), K05.Show(Approval.Psd2Linking(r)));
        }
        var absent = Pay();
        absent.Remove("unreviewed");
        Assert.Equal(Link(), K05.Show(Approval.Psd2Linking(absent)));
    }

    [Fact]
    public void ANullFieldThrowsAndANonObjectFieldHasNoClass()
    {
        Arg("Cannot read properties of null (reading 'class')", () => Approval.Psd2Linking(Rn(new L { null, Amt(N(5), MoneyUnit()), Payee("alice") })));
        var r = Rn(new L { N(7), "text", new L(), Amt(N(1250), MoneyUnit()), Payee("alice") });
        Assert.Equal(Link(), K05.Show(Approval.Psd2Linking(r)));
    }

    [Fact]
    public void ThereIsExactlyOneAmount()
    {
        const string Bad = "a payment approval needs exactly one money.amount parameter";
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { Payee("a") })));
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { Amt(N(1), MoneyUnit()), Amt(N(2), MoneyUnit()), Payee("a") })));
        // other classes are not amounts
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { F("x", "", N(1)), F("y", "money.amount2", N(1)), Payee("a") })));
    }

    [Fact]
    public void TheAmountNeedsAMoneyUnit()
    {
        const string Bad = "the money.amount parameter has no money unit";
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { F("amount", "money.amount", N(1)), Payee("a") })));
        foreach (var unit in new object?[] { null, "money", N(1), new D(), new D { ["kind"] = "count" }, new D { ["kind"] = "" } })
            Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { Amt(N(1), unit), Payee("a") })));
    }

    [Fact]
    public void TheAmountIsANonNegativeSafeInteger()
    {
        const string Bad = "the amount must be a non-negative integer in minor units";
        foreach (var v in new object?[] { N(-1), new Num("1.5"), new Num("-0"), N(MaxSafe + 1), "5", true, null, new L(), new D() })
            Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { Amt(v, MoneyUnit()), Payee("a") })));
    }

    [Fact]
    public void ThereIsExactlyOneNonEmptyStringPayee()
    {
        const string Bad = "a payment approval needs exactly one non-empty party.payee parameter";
        var amount = Amt(N(1), MoneyUnit());
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { amount })));
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { amount, Payee("a"), Payee("b") })));
        foreach (var v in new object?[] { "", N(5), null, true, new L() })
            Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { amount, Payee(v) })));
        Unlinkable(Bad, () => Approval.Psd2Linking(Rn(new L { amount, F("x", "", "a"), F("y", "party.payee2", "a") })));
    }

    // ---- minorToDecimal -------------------------------------------------------------------------------------------------

    [Fact]
    public void MinorUnitsPrintAsTheMajorDecimal()
    {
        Assert.Equal("12.50", Approval.MinorToDecimal(1250, 2));
        Assert.Equal("0.05", Approval.MinorToDecimal(5, 2));
        Assert.Equal("0.00", Approval.MinorToDecimal(0, 2));
        Assert.Equal("1250", Approval.MinorToDecimal(1250, 0));
        Assert.Equal("0", Approval.MinorToDecimal(0, 0));
        Assert.Equal("0.000000000000000001", Approval.MinorToDecimal(1, 18));
        Assert.Equal("9007199254740991", Approval.MinorToDecimal(MaxSafe, 0));
    }

    [Fact]
    public void MinorUnitsOutsideTheDomainAreRefused()
    {
        const string Bad = "minor units must be a non-negative safe integer";
        Unlinkable(Bad, () => Approval.MinorToDecimal(-1, 0));
        Unlinkable(Bad, () => Approval.MinorToDecimal(MaxSafe + 1, 0));
        Unlinkable(Bad, () => Approval.MinorToDecimal(1, -1));
        Unlinkable(Bad, () => Approval.MinorToDecimal(1, 19));
    }

    // ---- the batch ------------------------------------------------------------------------------------------------------

    static D Item(byte action, D render) => new() { ["action_digest"] = Digest(action), ["render"] = render };

    [Fact]
    public void ABatchCommitsToTotalsPayeesAndItems()
    {
        var r1 = Pay(100, "zed");
        var r2 = Pay(5, "amy", "EUR", 3);
        var r3 = Pay(250, "zed");
        var result = Approval.Batch(new L { Item(1, r1), Item(2, r2), Item(3, r3) });

        D Leaf(byte a, D r) => new() { ["d"] = "atlas-pca/approval-batch-item/v1", ["a"] = Digest(a), ["r"] = Approval.RenderDigest(r) };
        D PayeeLeaf(string p) => new() { ["d"] = "atlas-pca/approval-payee/v1", ["payee"] = p };
        var itemsRoot = Pca.MerkleRoot(new L { Leaf(1, r1), Leaf(2, r2), Leaf(3, r3) });
        var batch = new D
        {
            ["v"] = N(1), ["kind"] = "pca-approval-batch", ["n"] = N(3),
            ["totals"] = new L
            {
                new D { ["ccy"] = "EUR", ["exp"] = N(3), ["minor"] = N(5) },
                new D { ["ccy"] = "USD", ["exp"] = N(2), ["minor"] = N(350) },
            },
            ["payees_root"] = Pca.MerkleRoot(new L { PayeeLeaf("amy"), PayeeLeaf("zed") }),
            ["items_root"] = itemsRoot,
        };
        var rd = Pca.HashCanonical(new D { ["d"] = "atlas-pca/approval-batch/v1", ["batch"] = batch });
        var want = new D
        {
            ["batch"] = batch, ["action_digest"] = itemsRoot, ["render_digest"] = rd,
            ["challenge"] = Approval.Challenge(itemsRoot, rd), ["words"] = Approval.BindingWords(rd),
        };
        Assert.Equal(K05.Show(want), K05.Show(result));
    }

    [Fact]
    public void AnEmptyBatchIsRefused() =>
        Unlinkable("a batch needs at least one payment", () => Approval.Batch(new L()));

    [Fact]
    public void OneCurrencyHasOneExponent() =>
        Unlinkable("currency USD appears with two exponents", () => Approval.Batch(new L { Item(1, Pay(1, "a", "USD", 2)), Item(2, Pay(1, "a", "USD", 3)) }));

    [Fact]
    public void TheTotalStaysSafe()
    {
        var at = Approval.Batch(new L { Item(1, Pay(MaxSafe)), Item(2, Pay(0)) });
        Assert.Equal(K05.Show(new L { new D { ["ccy"] = "USD", ["exp"] = N(2), ["minor"] = N(MaxSafe) } }), K05.Show(((D)at["batch"]!)["totals"]));
        Unlinkable("the batch total exceeds the safe integer range", () => Approval.Batch(new L { Item(1, Pay(MaxSafe)), Item(2, Pay(1)) }));
    }

    [Fact]
    public void EveryItemIsLinkedBeforeAnyRenderIsDigested()
    {
        var shapeless = Pay();
        shapeless["x"] = N(1);
        var unreviewed = Pay();
        unreviewed["unreviewed"] = true;
        // the reference walks psd2Linking over all items first: the later unlinkable item decides
        Unlinkable("an unreviewed definition cannot be a payment approval", () => Approval.Batch(new L { Item(1, shapeless), Item(2, unreviewed) }));
        Arg("approvalRenderDigest: unknown member 'render.x'", () => Approval.Batch(new L { Item(1, shapeless) }));
    }

    // ---- runtime-class claims -------------------------------------------------------------------------------------------

    static readonly byte[] AttSeed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    static EdKey Att => EdKey.FromSeed(AttSeed);
    const string Pd = "passport-digest", Ev = "evidence-digest";

    static D Signed(Action<D>? edit = null, string cls = "os_confined")
    {
        var c = new D
        {
            ["v"] = N(1), ["class"] = cls, ["passport_digest"] = Pd, ["evidence_digest"] = Ev, ["iat"] = N(100), ["exp"] = N(200), ["attestor"] = Att.Id,
        };
        edit?.Invoke(c);
        c["sig"] = Issue.SignBody(Att, RuntimeClaim.Domain, c);
        return c;
    }

    static string Verified(object? claim, string pd = Pd, string ev = Ev, object? now = null, string? pin = null) =>
        RuntimeClaim.VerifiedClass(claim, new[] { pin ?? Att.Id }, pd, new[] { ev }, now ?? N(150));

    [Fact]
    public void EveryClassVerifies()
    {
        foreach (var cls in new[] { "none", "os_confined", "egress_default_deny", "wasi_no_ambient" })
            Assert.Equal(cls, Verified(Signed(cls: cls)));
    }

    [Fact]
    public void AnUnknownClassIsNone()
    {
        Assert.Equal("none", Verified(Signed(cls: "sgx")));
        Assert.Equal("none", Verified(Signed(cls: "")));
        Assert.Equal("none", Verified(Signed(c => c["class"] = N(1))));
        Assert.Equal("none", Verified(Signed(c => c["class"] = null)));
    }

    [Fact]
    public void TheMembersAreExactlyTheEight()
    {
        Assert.Equal("none", Verified(5));
        Assert.Equal("none", Verified(null));
        Assert.Equal("none", Verified(new L()));
        Assert.Equal("none", Verified(Signed(c => c["extra"] = N(1))));
        foreach (var k in new[] { "v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig" })
        {
            var missing = Signed();
            missing.Remove(k);
            Assert.Equal("none", Verified(missing));
            // eight members, one of them foreign
            var swapped = Signed();
            swapped.Remove(k);
            swapped["x"] = N(1);
            Assert.Equal("none", Verified(swapped));
        }
    }

    [Fact]
    public void TheVersionIsOne()
    {
        foreach (var v in new object?[] { N(2), N(0), N(-1), new Num("1.5"), "1", true, null })
            Assert.Equal("none", Verified(Signed(c => c["v"] = v)));
    }

    [Fact]
    public void ADigestIsNonEmptyAndAtMost128Chars()
    {
        var at = new string('p', 128);
        var over = new string('p', 129);
        Assert.Equal("os_confined", Verified(Signed(c => c["passport_digest"] = at), pd: at));
        Assert.Equal("none", Verified(Signed(c => c["passport_digest"] = over), pd: over));
        Assert.Equal("none", Verified(Signed(c => c["passport_digest"] = ""), pd: ""));
        Assert.Equal("os_confined", Verified(Signed(c => c["evidence_digest"] = at), ev: at));
        Assert.Equal("none", Verified(Signed(c => c["evidence_digest"] = over), ev: over));
        Assert.Equal("none", Verified(Signed(c => c["evidence_digest"] = ""), ev: ""));
        Assert.Equal("none", Verified(Signed(c => c["passport_digest"] = N(1))));
        Assert.Equal("none", Verified(Signed(c => c["evidence_digest"] = N(1))));
    }

    [Fact]
    public void AnAttestorThatIsNotABoundedStringIsNone()
    {
        Assert.Equal("none", Verified(Signed(c => c["attestor"] = ""), pin: ""));
        var over = new string('a', 129);
        Assert.Equal("none", Verified(Signed(c => c["attestor"] = over), pin: over));
        Assert.Equal("none", Verified(Signed(c => c["attestor"] = N(1))));
    }

    [Fact]
    public void TheClockValuesAreNaturals()
    {
        // stricter than the reference, which takes any integer
        Assert.Equal("none", Verified(Signed(c => c["iat"] = N(-1))));
        Assert.Equal("none", Verified(Signed(c => c["iat"] = "100")));
        Assert.Equal("none", Verified(Signed(c => c["exp"] = N(-1))));
        Assert.Equal("none", Verified(Signed(c => c["exp"] = "200")));
        Assert.Equal("none", Verified(Signed(c => c["exp"] = new Num("200.5"))));
        // an unreadable clock would read 0, inside this window
        var fromZero = Signed(c => c["iat"] = N(0));
        Assert.Equal("os_confined", Verified(fromZero, now: N(0)));
        Assert.Equal("none", Verified(fromZero, now: "x"));
        Assert.Equal("none", Verified(fromZero, now: new Num("1.5")));
    }

    [Fact]
    public void TheWindowIncludesIatAndExcludesExp()
    {
        Assert.Equal("none", Verified(Signed(), now: N(99)));
        Assert.Equal("os_confined", Verified(Signed(), now: N(100)));
        Assert.Equal("os_confined", Verified(Signed(), now: N(199)));
        Assert.Equal("none", Verified(Signed(), now: N(200)));
    }

    [Fact]
    public void TheClaimIsBoundToTrustAndSignature()
    {
        Assert.Equal("none", Verified(Signed(), pd: "other"));
        Assert.Equal("none", Verified(Signed(), ev: "other"));
        Assert.Equal("none", Verified(Signed(), pin: EdKey.Generate().Id));
        var tampered = Signed();
        tampered["class"] = "wasi_no_ambient";
        Assert.Equal("none", Verified(tampered));
        var unsigned = Signed();
        unsigned["sig"] = Pca.B64u(new byte[64]);
        Assert.Equal("none", Verified(unsigned));
    }

    [Fact]
    public void AThrowInsideIsNone()
    {
        // a null list makes the membership check throw: only the catch can answer
        Assert.Equal("none", RuntimeClaim.VerifiedClass(Signed(), null!, Pd, new[] { Ev }, N(150)));
        Assert.Equal("none", RuntimeClaim.VerifiedClass(Signed(), new[] { Att.Id }, Pd, null!, N(150)));
    }
}
