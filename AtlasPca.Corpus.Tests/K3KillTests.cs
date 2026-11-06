using System.Globalization;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Kills of the Stryker survivors in K3.cs. Every message, code and boundary is the TypeScript reference's
/// (packages/pca-grants/src/bundle.ts, list-authorized.ts, grant-resource.ts, sig.ts). The artifacts are really signed, so a check that
/// a mutant drops is seen by the signature then passing. The fail-closed catches are driven by a dictionary whose lookups throw.</summary>
public class K3KillTests
{
    static readonly EdKey Key = EdKey.FromSeed(Enumerable.Repeat((byte)0x31, 32).ToArray());
    static readonly EdKey Pr = EdKey.FromSeed(Enumerable.Repeat((byte)0x32, 32).ToArray());
    static readonly EdKey Ag = EdKey.FromSeed(Enumerable.Repeat((byte)0x33, 32).ToArray());

    static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));
    static string Sign(EdKey k, string domain, object? body) => Pca.B64u(k.Sign(IntentJs.Message(domain, body)));
    static string Chars(int n) => new('a', n);
    static JL Copies(object? x, int n) => Enumerable.Repeat(x, n).ToList();

    /// <summary>A key comparer that throws for the keys <see cref="Trip"/> names: a lookup on a dictionary built with it throws, enumeration works.</summary>
    sealed class Boom : IEqualityComparer<string>
    {
        public Func<string, bool>? Trip;
        public bool Equals(string? a, string? b) => a == b;
        public int GetHashCode(string s)
        {
            if (Trip?.Invoke(s) == true) throw new InvalidOperationException("boom");
            return s.GetHashCode();
        }
    }

    static JD Armed(JD src, Func<string, bool> trip)
    {
        var c = new Boom();
        var d = new JD(c);
        foreach (var (k, v) in src) d[k] = v;
        c.Trip = trip;
        return d;
    }

    static JD Throwing(JD src) => Armed(src, _ => true);

    // ---------------------------------------------------------------- policy bundles

    static JD Body(Action<JD>? tweak = null)
    {
        var b = new JD
        {
            ["v"] = N(1), ["kind"] = "pca-policy-bundle", ["revision"] = N(1), ["grants"] = new JL(), ["template_digests"] = new JL(),
            ["min_verifier_version"] = "0.5.0", ["issued_at"] = N(1),
        };
        tweak?.Invoke(b);
        return b;
    }

    static JD Signed(JD body, params EdKey[] keys)
    {
        var sigs = new JL();
        foreach (var k in keys) sigs.Add(new JD { ["signer"] = k.Id, ["sig"] = Sign(k, K3.BundleDomain, body) });
        return new JD(body) { ["sigs"] = sigs };
    }

    static string? ShapeOf(Action<JD> tweak) => K3.BundleShapeError(Body(tweak));

    [Fact]
    public void BundleKindAndVersionAreBothRequired()
    {
        Assert.Null(K3.BundleShapeError(Body()));
        Assert.Equal("not a policy bundle", K3.BundleShapeError("x"));
        Assert.Equal("not a policy bundle", ShapeOf(b => b["v"] = N(2)));
        Assert.Equal("not a policy bundle", ShapeOf(b => b["kind"] = "other"));
    }

    [Fact]
    public void BundleRevisionAndTime()
    {
        const string bad = "bad revision or time";
        Assert.Equal(bad, ShapeOf(b => b["revision"] = N(0)));
        Assert.Equal(bad, ShapeOf(b => b["revision"] = "1"));
        Assert.Equal(bad, ShapeOf(b => b["issued_at"] = "1"));
    }

    [Fact]
    public void BundlePrevIsAbsentAtRevisionOneAndAtMost128Characters()
    {
        const string bad = "prev must be absent at revision 1 and present after";
        Assert.Equal(bad, ShapeOf(b => b["prev"] = "p"));
        Assert.Equal(bad, ShapeOf(b => b["revision"] = N(2)));
        Assert.Equal(bad, ShapeOf(b => { b["revision"] = N(2); b["prev"] = ""; }));
        Assert.Null(ShapeOf(b => { b["revision"] = N(2); b["prev"] = Chars(128); }));
        Assert.Equal(bad, ShapeOf(b => { b["revision"] = N(2); b["prev"] = Chars(129); }));
    }

    [Fact]
    public void BundleListsHoldAtMost4096ShortStrings()
    {
        foreach (var (k, bad) in new[] { ("grants", "bad grants"), ("template_digests", "bad template_digests") })
        {
            Assert.Null(ShapeOf(b => b[k] = Copies("g", 4096)));
            Assert.Equal(bad, ShapeOf(b => b[k] = Copies("g", 4097)));
            Assert.Equal(bad, ShapeOf(b => b[k] = "g"));
            Assert.Equal(bad, ShapeOf(b => b[k] = new JL { "g", "" }));
        }
    }

    [Theory]
    [InlineData("schema_digest")]
    [InlineData("constitution_digest")]
    [InlineData("flow_rules_digest")]
    public void BundleOptionalDigests(string k)
    {
        Assert.Null(ShapeOf(b => b[k] = Chars(128)));
        Assert.Equal("bad " + k, ShapeOf(b => b[k] = Chars(129)));
        Assert.Equal("bad " + k, ShapeOf(b => b[k] = N(1)));
    }

    // bundle.ts:72. The port had no shadow check: a signed bundle with a malformed `shadow` member was accepted.
    [Fact]
    public void BundleShadowIsANonEmptyListOfAtMost16DistinctDigests()
    {
        const string bad = "bad shadow";
        JL Distinct(int n) => Enumerable.Range(0, n).Select(i => (object?)("d" + i)).ToList();
        Assert.Null(ShapeOf(b => b["shadow"] = Distinct(1)));
        Assert.Null(ShapeOf(b => b["shadow"] = Distinct(16)));
        Assert.Null(ShapeOf(b => b["shadow"] = new JL { Chars(128) }));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = Distinct(17)));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = new JL()));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = "d"));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = null));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = new JL { "d", "" }));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = new JL { Chars(129) }));
        Assert.Equal(bad, ShapeOf(b => b["shadow"] = new JL { "d", "d" }));
        var refused = K3.VerifyBundle(Signed(Body(b => b["shadow"] = new JL()), Key), new[] { Key.Id }, 1, "1.0.0");
        Assert.Equal(("malformed", bad), (refused.Code, refused.Reason));
    }

    static void IsMalformedSigs(BundleVerdict v)
    {
        Assert.False(v.Ok);
        Assert.Equal(("malformed", "bad sigs or threshold"), (v.Code, v.Reason));
    }

    [Fact]
    public void BundleSigsAtMost64AndThresholdAtLeastOne()
    {
        var pinned = new[] { Key.Id };
        var ok = K3.VerifyBundle(Signed(Body(), Key), pinned, 1, "1.0.0");
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal(1, ok.Revision);
        Assert.Equal(K3.BundleDigest(Body()), ok.Digest);
        Assert.Equal(new[] { Key.Id }, ok.Signers);
        IsMalformedSigs(K3.VerifyBundle(Signed(Body(), Key), pinned, 0, "1.0.0"));
        IsMalformedSigs(K3.VerifyBundle(new JD(Body()) { ["sigs"] = "x" }, pinned, 1, "1.0.0"));
        IsMalformedSigs(K3.VerifyBundle(new JD(Body()) { ["sigs"] = Copies(new JD(), 65) }, pinned, 1, "1.0.0"));
        var at64 = K3.VerifyBundle(new JD(Body()) { ["sigs"] = Copies(new JD(), 64) }, pinned, 1, "1.0.0");
        Assert.Equal(("below_threshold", "0 valid pinned signature(s), need 1"), (at64.Code, at64.Reason));
    }

    [Fact]
    public void ABundleThatOnlySignsButCannotBeAddressedIsMalformed()
    {
        // the body fits the depth cap (32); the digest wraps it one level deeper, where it does not
        object? deep = new JL();
        for (int i = 1; i < 31; i++) deep = new JL { deep };
        IsMalformedSigs(K3.VerifyBundle(Signed(Body(b => b["x"] = deep), Key), new[] { Key.Id }, 1, "1.0.0"));
    }

    [Fact]
    public void ABundleThatThrowsIsMalformed() =>
        IsMalformedSigs(K3.VerifyBundle(Throwing(Signed(Body(), Key)), new[] { Key.Id }, 1, "1.0.0"));

    [Fact]
    public void CompareVersionIsTheReferenceOrder()
    {
        Assert.Equal(0, K3.CompareVersion("1.", "1"));           // an empty part is 0
        Assert.Equal(1, K3.CompareVersion("1a", "1"));           // a part that is not a number reads as greater (NaN)
        Assert.Equal(1, K3.CompareVersion("1", "1a"));
        Assert.Equal(1, K3.CompareVersion("1.2", "1"));          // the longer one's extra parts count
        Assert.Equal(-1, K3.CompareVersion("1", "1.2"));
        Assert.Equal(0, K3.CompareVersion("1", "1.0"));
        Assert.Equal(0, K3.CompareVersion("1.0", "1"));
        Assert.Equal(1, K3.CompareVersion("2", "1"));
        Assert.Equal(-1, K3.CompareVersion("1", "2"));
    }

    // ---------------------------------------------------------------- decision log

    static JD Head(Action<JD>? tweak = null, long size = 1, string lastCommit = "lc")
    {
        var h = new JD { ["v"] = N(1), ["size"] = N(size), ["root"] = "r", ["last_commit"] = lastCommit, ["issued_at"] = N(1), ["signer"] = Key.Id };
        tweak?.Invoke(h);
        var sig = Sign(Key, K3.LogHeadDomain, h);
        h["sig"] = sig;
        return h;
    }

    [Fact]
    public void ALogHeadWithAnyBadMemberIsRefusedEvenWhenSigned()
    {
        Assert.True(K3.VerifyLogHead(Head(), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["v"] = N(2)), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["signer"] = "someone-else"), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["size"] = "1"), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["issued_at"] = "1"), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["root"] = N(1)), Key.Id));
        Assert.False(K3.VerifyLogHead(Head(h => h["last_commit"] = N(1)), Key.Id));
    }

    [Fact]
    public void ALogHeadThatThrowsIsRefused() => Assert.False(K3.VerifyLogHead(Throwing(Head()), Key.Id));

    [Fact]
    public void AnInclusionCheckThatThrowsIsRefused()
    {
        // the head verifies (first lookup of root); reading the root for the inclusion check (second lookup) throws
        int roots = 0;
        var head = Armed(Head(), k => k == "root" && ++roots == 2);
        Assert.False(K3.VerifyRecordInclusion(new JD { ["seq"] = N(0) }, null, head, Key.Id));
        Assert.Equal(2, roots);
    }

    static JD Rec(long seq, string prev) => new() { ["seq"] = N(seq), ["prev"] = prev };

    static string? BatchReason(object? batch, long next = 0, string last = "")
    {
        var v = K3.VerifyBatch(batch, next, last, Key.Id);
        Assert.False(v.Ok);
        return v.Reason;
    }

    static JD Batch(object? records, JD? head = null) => new() { ["from"] = N(0), ["head"] = head ?? Head(size: 10), ["records"] = records };

    [Fact]
    public void BatchReasonsAreTheReferencesStrings()
    {
        Assert.Equal("malformed batch", BatchReason("x"));
        Assert.Equal("gap or replay: batch starts at undefined, expected 7", BatchReason(new JD(), 7));
        Assert.Equal("malformed batch", BatchReason(Batch("x")));
        Assert.Equal("malformed batch", BatchReason(Batch(new JL { "x" })));
        Assert.Equal("chain broken at seq 5", BatchReason(Batch(new JL { Rec(5, "") })));
        Assert.Equal("malformed batch", BatchReason(Batch(new JL { new JD(Rec(0, "")) { ["bad"] = new Num("01") } })));
        Assert.Equal("batch is longer than the signed head", BatchReason(Batch(new JL { Rec(0, "") }, Head(size: 0))));
        Assert.Equal("batch end does not match the signed head", BatchReason(Batch(new JL { Rec(0, "") }, Head(size: 1, lastCommit: "other"))));
        Assert.Equal("malformed batch", BatchReason(Throwing(new JD { ["from"] = N(0) })));
    }

    [Fact]
    public void ABatchReachingTheHeadMovesTheCursor()
    {
        var r = Rec(0, "");
        var c = K3.RecordCommit(r)!;
        var v = K3.VerifyBatch(Batch(new JL { r }, Head(size: 1, lastCommit: c)), 0, "", Key.Id);
        Assert.True(v.Ok, v.Reason);
        Assert.Equal((1L, c), (v.Next, v.LastCommit));
    }

    // ---------------------------------------------------------------- list-authorized

    static JD Receipt(Action<JD>? tweak = null)
    {
        var r = new JD { ["v"] = N(1), ["subject"] = "s", ["resource_type"] = "t", ["count"] = N(1), ["issued_at"] = N(1), ["signer"] = Key.Id };
        tweak?.Invoke(r);
        var sig = Sign(Key, K3.ListReceiptDomain, r);
        r["sig"] = sig;
        return r;
    }

    [Fact]
    public void AReceiptWithAnyBadMemberIsRefusedEvenWhenSigned()
    {
        Assert.True(K3.VerifyListReceipt(Receipt(), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["signer"] = "someone-else"), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["subject"] = ""), Key.Id));
        Assert.True(K3.VerifyListReceipt(Receipt(r => r["subject"] = Chars(512)), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["subject"] = Chars(513)), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["resource_type"] = ""), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["count"] = "1"), Key.Id));
        Assert.False(K3.VerifyListReceipt(Receipt(r => r["issued_at"] = "1"), Key.Id));
        Assert.False(K3.VerifyListReceipt(Throwing(Receipt()), Key.Id));
    }

    static string Payload(string json) => Pca.B64u(System.Text.Encoding.UTF8.GetBytes(json));

    static string Cursor(Action<JD>? tweak = null)
    {
        var c = new JD { ["v"] = N(1), ["bind"] = "b", ["skip"] = N(3), ["signer"] = Key.Id };
        tweak?.Invoke(c);
        return Payload(Pca.Canonicalize(c)) + "." + Sign(Key, K3.ListCursorDomain, c);
    }

    [Fact]
    public void AValidCursorVerifies()
    {
        var v = K3.VerifyListCursor(Cursor(), Key.Id);
        Assert.True(v.Ok, v.Reason);
        Assert.Null(v.Inner);
        Assert.Equal(3L, v.Skip);
        Assert.Equal("i", K3.VerifyListCursor(Cursor(c => c["inner"] = "i"), Key.Id).Inner);
    }

    public static IEnumerable<object[]> MalformedCursors()
    {
        var good = Cursor();
        var head = good.Split('.')[0];
        var sig = good.Split('.')[1];
        yield return new object[] { good + ".extra" };
        yield return new object[] { head };
        yield return new object[] { head + "." };
        yield return new object[] { "." + sig };
        yield return new object[] { "!!!." + sig };
        yield return new object[] { Payload("not json") + "." + sig };
        yield return new object[] { Payload("[1]") + "." + sig };
        yield return new object[] { Cursor(c => c["v"] = N(2)) };
        yield return new object[] { Cursor(c => c["bind"] = N(1)) };
        yield return new object[] { Cursor(c => c["skip"] = "3") };
        yield return new object[] { Cursor(c => c["inner"] = N(1)) };
    }

    [Theory]
    [MemberData(nameof(MalformedCursors))]
    public void EveryBadCursorShapeIsMalformed(string token)
    {
        var v = K3.VerifyListCursor(token, Key.Id);
        Assert.False(v.Ok);
        Assert.Equal("malformed", v.Reason);
    }

    [Fact]
    public void ACursorThatIsNotAStringOrIsEmptyIsMalformed()
    {
        Assert.Equal("malformed", K3.VerifyListCursor(N(1), Key.Id).Reason);
        Assert.Equal("malformed", K3.VerifyListCursor("", Key.Id).Reason);
    }

    // ---------------------------------------------------------------- authority

    static JD Auth(string[] verbs, string[] resources, Action<JD>? tweak = null)
    {
        var a = new JD { ["verbs"] = verbs.Cast<object?>().ToList(), ["resources"] = resources.Cast<object?>().ToList() };
        tweak?.Invoke(a);
        return a;
    }

    static JD Ok1(Action<JD>? tweak = null) => Auth(new[] { "r" }, new[] { "/a" }, tweak);

    [Fact]
    public void AuthorityShapeBoundaries()
    {
        Assert.True(K3.AuthorityOk(Ok1()));
        Assert.False(K3.AuthorityOk("x"));
        Assert.True(K3.AuthorityOk(Ok1(a => a["verbs"] = Copies("r", 256))));
        Assert.False(K3.AuthorityOk(Ok1(a => a["verbs"] = Copies("r", 257))));
        Assert.False(K3.AuthorityOk(Ok1(a => a["verbs"] = new JL { "r", "" })));
        Assert.True(K3.AuthorityOk(Ok1(a => a["resources"] = Copies("/a", 1024))));
        Assert.False(K3.AuthorityOk(Ok1(a => a["resources"] = Copies("/a", 1025))));
        Assert.False(K3.AuthorityOk(Ok1(a => a["resources"] = new JL { "/a", "" })));
        Assert.False(K3.AuthorityOk(Ok1(a => a["resources"] = "x")));
        Assert.False(K3.AuthorityOk(Ok1(a => a["verbs"] = "x")));
    }

    [Fact]
    public void AuthorityLimitsAndExpiry()
    {
        Assert.True(K3.AuthorityOk(Ok1(a => a["limits"] = new JD { ["x"] = N(0), ["y"] = N(5) })));
        Assert.False(K3.AuthorityOk(Ok1(a => a["limits"] = "x")));
        Assert.False(K3.AuthorityOk(Ok1(a => a["limits"] = new JD { ["x"] = N(1), ["y"] = N(-1) })));
        Assert.False(K3.AuthorityOk(Ok1(a => a["limits"] = new JD { ["x"] = "1" })));
        Assert.True(K3.AuthorityOk(Ok1(a => a["expires_at"] = N(5))));
        Assert.False(K3.AuthorityOk(Ok1(a => a["expires_at"] = "5")));
    }

    [Fact]
    public void AnAuthorityThatThrowsIsNotWellFormed() => Assert.False(K3.AuthorityOk(Throwing(Ok1())));

    static string Order(string[] oldRes, string[] newRes) => K3.CompareAuthority(Auth(new[] { "r" }, oldRes), Auth(new[] { "r" }, newRes));

    [Fact]
    public void ResourceCoverage()
    {
        Assert.Equal("equal", Order(new[] { "/a" }, new[] { "/a" }));
        Assert.Equal("incomparable", Order(new[] { "/a/bc" }, new[] { "/a/bd" }));          // an exact id is not a prefix
        Assert.Equal("narrower", Order(new[] { "/a/*" }, new[] { "/a/1" }));
        Assert.Equal("narrower", Order(new[] { "/a/*" }, new[] { "/a/b/*" }));
        Assert.Equal("wider", Order(new[] { "/a" }, new[] { "/a", "/z" }));                 // every new resource must be covered
        Assert.Equal("narrower", Order(new[] { "/a", "/b" }, new[] { "/a" }));              // one covering resource is enough
    }

    [Fact]
    public void AMergeOnlyRaisesAndATieKeepsTheOriginal()
    {
        Num own = N(7), same = N(7), higher = N(9);
        var tie = K3.MergeAuthority(Ok1(a => { a["limits"] = new JD { ["x"] = own }; a["expires_at"] = own; }), Ok1(a => { a["limits"] = new JD { ["x"] = same }; a["expires_at"] = same; }));
        Assert.Same(own, ((JD)tie["limits"]!)["x"]);
        Assert.Same(own, tie["expires_at"]);
        var raised = K3.MergeAuthority(Ok1(a => { a["limits"] = new JD { ["x"] = own }; a["expires_at"] = own; }), Ok1(a => { a["limits"] = new JD { ["x"] = higher }; a["expires_at"] = higher; }));
        Assert.Same(higher, ((JD)raised["limits"]!)["x"]);
        Assert.Same(higher, raised["expires_at"]);
        Assert.False(K3.MergeAuthority(Ok1(), Ok1()).ContainsKey("limits"));
    }

    // ---------------------------------------------------------------- grant management

    static JD Grant(JD authority) => new() { ["id"] = "g", ["rev"] = N(1), ["principal"] = Pr.Id, ["agent"] = Ag.Id, ["status"] = "active", ["authority"] = authority };

    static JD Amend(JD cur, string action, JD authority, string by, EdKey key) => new()
    {
        ["action"] = action, ["authority"] = authority, ["signed_by"] = by, ["sig"] = Sign(key, K3.GrantAmendDomain, K3.AmendMessage(cur, action, authority)),
    };

    [Fact]
    public void AGrantWithoutAnAuthorityIsABadRequest()
    {
        var cur = Grant(Ok1());
        cur.Remove("authority");
        Assert.Equal("bad_request", K3.VerifyAmendment(cur, Amend(cur, "replace", Ok1(), "principal", Pr), true).Code);
    }

    [Fact]
    public void WiderAndIncomparableBothWiden()
    {
        var cur = Grant(Ok1());
        foreach (var next in new[] { Auth(new[] { "r", "w" }, new[] { "/a" }), Auth(new[] { "r" }, new[] { "/b" }) })
        {
            var ok = K3.VerifyAmendment(cur, Amend(cur, "replace", next, "principal", Pr), true);
            Assert.True(ok.Ok, ok.Code);
            Assert.True(ok.Widens);
            Assert.Same(next, ok.Authority);
            Assert.Equal("signature_required", K3.VerifyAmendment(cur, Amend(cur, "replace", next, "holder", Ag), true).Code);
            Assert.Equal("step_up_required", K3.VerifyAmendment(cur, Amend(cur, "replace", next, "principal", Pr), false).Code);
        }
        var narrower = K3.VerifyAmendment(Grant(Auth(new[] { "r", "w" }, new[] { "/a" })), Amend(Grant(Auth(new[] { "r", "w" }, new[] { "/a" })), "narrow", Ok1(), "holder", Ag), false);
        Assert.True(narrower.Ok, narrower.Code);
        Assert.False(narrower.Widens);
    }

    [Fact]
    public void AnAmendmentNeedsAStringSignatureAndAKnownSignerKind()
    {
        var cur = Grant(Auth(new[] { "r", "w" }, new[] { "/a" }));
        var noSig = Amend(cur, "narrow", Ok1(), "holder", Ag);
        noSig["sig"] = N(1);
        Assert.Equal("signature_required", K3.VerifyAmendment(cur, noSig, true).Code);
        Assert.Equal("signature_required", K3.VerifyAmendment(cur, Amend(cur, "narrow", Ok1(), "someone", Ag), true).Code);
    }

    [Fact]
    public void AMergeIntoAMalformedAuthorityIsABadRequest()
    {
        var cur = Grant(new JD());
        Assert.Equal("bad_request", K3.VerifyAmendment(cur, Amend(cur, "merge", Ok1(), "principal", Pr), true).Code);
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("agent")]
    [InlineData("subtree")]
    public void EveryRevokeScopeVerifies(string scope)
    {
        var v = K3.VerifyRevokeSignature(new JD { ["id"] = "g", ["principal"] = Pr.Id }, scope, Sign(Pr, K3.GrantRevokeDomain, K3.GrantRevokeMessage("g", scope)));
        Assert.True(v.Ok, v.Code);
        Assert.Equal(scope, v.Scope);
        Assert.False(v.Widens);
    }

    [Fact]
    public void ARevokeThatThrowsOrNamesAnotherScopeIsABadRequest()
    {
        Assert.Equal("bad_request", K3.VerifyRevokeSignature(new JD { ["id"] = "g", ["principal"] = Pr.Id }, "other", "s").Code);
        Assert.Equal("bad_request", K3.VerifyRevokeSignature(Throwing(new JD { ["id"] = "g", ["principal"] = Pr.Id }), "grant", "s").Code);
    }

    static JD Need(object? limit, bool adjustable = false)
    {
        var n = new JD { ["verb"] = "w", ["resource"] = "/n", ["limits"] = new JD { ["x"] = limit } };
        if (adjustable) n["adjustable"] = true;
        return n;
    }

    static GrantVerdict Approve(JD grant, JL needs, object? approved, bool stepUp = true)
    {
        var request = new JD { ["id"] = "n1", ["grant_id"] = "g", ["status"] = "pending", ["needs"] = needs };
        return K3.VerifyNeedApproval(request, grant, approved, Sign(Pr, K3.NeedApproveDomain, K3.NeedApproveMessage(request, grant["rev"], approved)), stepUp);
    }

    static JD Limited() => Grant(Ok1(a => a["limits"] = new JD { ["x"] = N(1) }));

    [Fact]
    public void AnApprovalEntryThatIsNotAnObjectIsNotLoweredOnly()
    {
        Assert.Equal("need_not_lowered_only", Approve(Limited(), new JL { Need(N(5)) }, new JL { N(5) }).Code);
        Assert.Equal("need_not_lowered_only", Approve(Limited(), new JL { N(5) }, new JL { Need(N(5)) }).Code);
    }

    [Fact]
    public void AnEqualAmountNeedsNoAdjustableNeedALowerOneDoes()
    {
        var v = Approve(Limited(), new JL { Need(N(5)) }, new JL { Need(N(5)) });
        Assert.True(v.Ok, v.Code);
        Assert.False(v.Widens);
        Assert.Contains("w", (JL)v.Authority!["verbs"]!);
        Assert.Contains("/n", (JL)v.Authority!["resources"]!);
        Assert.Equal("need_not_adjustable", Approve(Limited(), new JL { Need(N(5)) }, new JL { Need(N(4)) }).Code);
        Assert.True(Approve(Limited(), new JL { Need(N(5), true) }, new JL { Need(N(4)) }).Ok);
    }

    [Fact]
    public void TheHighestApprovedAmountWinsAndATieKeepsTheFirst()
    {
        var needs = new JL { Need(N(5), true), Need(N(5), true) };
        Assert.Equal(N(5), ((JD)Approve(Limited(), needs, new JL { Need(N(5)), Need(N(3)) }).Authority!["limits"]!)["x"]);
        Assert.Equal(N(5), ((JD)Approve(Limited(), needs, new JL { Need(N(3)), Need(N(5)) }).Authority!["limits"]!)["x"]);
        Num first = N(5), second = N(5);
        Assert.Same(first, ((JD)Approve(Limited(), needs, new JL { Need(first), Need(second) }).Authority!["limits"]!)["x"]);
    }

    [Fact]
    public void AnApprovalWithAMalformedGrantOrAmountIsABadRequest()
    {
        var noAuthority = Limited();
        noAuthority.Remove("authority");
        Assert.Equal("bad_request", Approve(noAuthority, new JL { Need(N(5)) }, new JL { Need(N(5)) }).Code);
        Assert.Equal("bad_request", Approve(Limited(), new JL { Need(N(5)) }, new JL { Need("five") }).Code);
    }
}
