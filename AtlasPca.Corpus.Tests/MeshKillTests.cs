using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Mutation kills for Ext/Mesh.cs. Every limit and message pinned here is the reference's: packages/pca/src/mesh.ts,
/// ledger.ts verifyLedgerConsistency and revocation.ts verifyNonMembership. The private helpers are reached by reflection; the
/// branches a real chain can never reach (defence in depth) are tested directly.</summary>
public class MeshKillTests
{
    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;
    const long Now = 1_800_000_000_000;

    static object? Call(string name, object?[] args) => typeof(Mesh).GetMethod(name, NP)!.Invoke(null, args);
    static Num N(long v) => IntentJs.OfLong(v);
    static L Strs(int n) => Enumerable.Range(0, n).Select(_ => (object?)"x").ToList();

    static readonly string Empty = Pca.B64u(Pca.Sha256Of(Array.Empty<byte>()));
    static string Hx(byte b) => Pca.B64u(Enumerable.Repeat(b, 32).ToArray());
    static string NodeOf(string l, string r) => Pca.B64u(Pca.Sha256Of(new byte[] { 0x01 }, Pca.B64uDecode(l, 32)!, Pca.B64uDecode(r, 32)!));

    // ---- shapes and bounds (mesh.ts validConsistency, validInclusion)

    static long NatV(object? x) => (long)Call("NatV", new object?[] { x })!;
    static D? ValidConsistency(object? c) => (D?)Call("ValidConsistency", new object?[] { c });
    static D? ValidInclusion(object? c) => (D?)Call("ValidInclusion", new object?[] { c });
    static D Cp(object? oldSize, object? newSize, L? path = null) => new() { ["oldSize"] = oldSize, ["newSize"] = newSize, ["path"] = path ?? new L() };

    [Fact]
    public void NatValueIsZeroUnlessASafeInteger()
    {
        Assert.Equal(0L, NatV(null));
        Assert.Equal(0L, NatV("x"));
        Assert.Equal(0L, NatV(new Num("1.5")));
        Assert.Equal(0L, NatV(new Num("9007199254740992")));
        Assert.Equal(9007199254740991L, NatV(new Num("9007199254740991")));
        Assert.Equal(7L, NatV(N(7)));
    }

    [Fact]
    public void ValidConsistencyNeedsBothSizesNatural()
    {
        Assert.NotNull(ValidConsistency(Cp(N(1), N(2))));
        Assert.Null(ValidConsistency(Cp("a", N(2))));
        Assert.Null(ValidConsistency(Cp(N(1), "a")));
        Assert.Null(ValidConsistency(Cp(N(-1), N(2))));
        Assert.Null(ValidConsistency(Cp(N(1), N(-2))));
    }

    [Fact]
    public void ValidConsistencyPathBoundIs128()
    {
        Assert.NotNull(ValidConsistency(Cp(N(1), N(2), Strs(127))));
        Assert.NotNull(ValidConsistency(Cp(N(1), N(2), Strs(128))));
        Assert.Null(ValidConsistency(Cp(N(1), N(2), Strs(129))));
    }

    [Fact]
    public void ValidInclusionPathBoundIs128()
    {
        static D Inc(int n) => new() { ["index"] = N(0), ["size"] = N(1), ["path"] = Strs(n) };
        Assert.NotNull(ValidInclusion(Inc(127)));
        Assert.NotNull(ValidInclusion(Inc(128)));
        Assert.Null(ValidInclusion(Inc(129)));
    }

    // ---- effective authority (mesh.ts effectiveAuthority; a throw there is 'malformed proof' from verifyMeshProof's catch-all)

    [Fact]
    public void EffectiveRefusesANonArrayAndNonObjectCaveats()
    {
        Assert.Equal("malformed proof", Mesh.Effective(null).Why);
        Assert.Equal("malformed proof", Mesh.Effective(N(5)).Why);
        Assert.Equal("malformed proof", Mesh.Effective(new L { null }).Why);
        Assert.Equal("unknown caveat type \"undefined\" (fail closed)", Mesh.Effective(new L { N(5) }).Why);
        Assert.Equal("unknown caveat type \"undefined\" (fail closed)", Mesh.Effective(new L { new L() }).Why);
        Assert.Null(Mesh.Effective(new L()).Why);
    }

    // ---- narrows (mesh.ts narrows)

    static bool Narrows(Mesh.Authority child, Mesh.Authority parent) => (bool)Call("Narrows", new object?[] { child, parent })!;
    static List<string> Ls(params string[] x) => x.ToList();

    [Fact]
    public void NarrowsActions()
    {
        var p = new Mesh.Authority { Actions = Ls("a", "b") };
        Assert.False(Narrows(new Mesh.Authority(), p));
        Assert.False(Narrows(new Mesh.Authority { Actions = Ls("c") }, p));
        Assert.True(Narrows(new Mesh.Authority { Actions = Ls("a") }, p));
    }

    [Fact]
    public void NarrowsAudience()
    {
        var p = new Mesh.Authority { Audience = Ls("a", "b") };
        Assert.False(Narrows(new Mesh.Authority(), p));
        Assert.False(Narrows(new Mesh.Authority { Audience = Ls("c") }, p));
        Assert.True(Narrows(new Mesh.Authority { Audience = Ls("b") }, p));
    }

    [Fact]
    public void NarrowsMaxAmount()
    {
        var p = new Mesh.Authority { MaxAmount = 10 };
        Assert.False(Narrows(new Mesh.Authority(), p));
        Assert.False(Narrows(new Mesh.Authority { MaxAmount = 11 }, p));
        Assert.True(Narrows(new Mesh.Authority { MaxAmount = 10 }, p));
    }

    [Fact]
    public void NarrowsExpiresAt()
    {
        var p = new Mesh.Authority { ExpiresAt = 10 };
        Assert.False(Narrows(new Mesh.Authority(), p));
        Assert.False(Narrows(new Mesh.Authority { ExpiresAt = 11 }, p));
        Assert.True(Narrows(new Mesh.Authority { ExpiresAt = 10 }, p));
    }

    [Fact]
    public void NarrowsMaxHops()
    {
        var p = new Mesh.Authority { MaxHops = 10 };
        Assert.False(Narrows(new Mesh.Authority(), p));
        Assert.False(Narrows(new Mesh.Authority { MaxHops = 11 }, p));
        Assert.True(Narrows(new Mesh.Authority { MaxHops = 10 }, p));
    }

    [Fact]
    public void WidenReasonNamesAWideningHopOnly()
    {
        var parent = new Mesh.Authority { MaxAmount = 10 };
        Assert.Equal("hop widens authority", Mesh.WidenReason(parent, new Mesh.Authority { MaxAmount = 11 }));
        Assert.Null(Mesh.WidenReason(parent, new Mesh.Authority { MaxAmount = 10 }));
        Assert.Null(Mesh.WidenReason(null, new Mesh.Authority()));
    }

    // ---- admits: a missing member reads as the empty string

    static string? Admits(Mesh.Authority e, D a) => (string?)Call("Admits", new object?[] { e, a, 0d, 1 });

    [Fact]
    public void AdmitsReadsMissingMembersAsEmpty()
    {
        Assert.Equal("action \"\" not in scope", Admits(new Mesh.Authority { Actions = Ls("x") }, new D()));
        Assert.Equal("resource \"\" outside prefix \"x\"", Admits(new Mesh.Authority { Prefixes = Ls("x") }, new D()));
        Assert.Null(Admits(new Mesh.Authority { Audience = Ls("") }, new D()));
    }

    // ---- revocation roots and leaves (revocation.ts bindRoot, leafOk, verifyNonMembership)

    static string? Bind(double size, string tree) => (string?)Call("BindRevRoot", new object?[] { size, tree });
    static string LeafRoot(string id) => Bind(1, Pca.B64u(Pca.Sha256Of(new byte[] { 0x00 }, IntentJs.CanonBytes(id))))!;
    static D OneLeaf(long index = 0) => new() { ["size"] = N(1), ["index"] = N(index), ["path"] = new L() };

    [Fact]
    public void BindRevRootNeedsASafeInteger()
    {
        Assert.Null(Bind(1.5, "t"));
        Assert.Null(Bind(9007199254740992d, "t"));
        var want = Pca.B64u(Pca.Sha256Of(Encoding.UTF8.GetBytes("pca-revset/v1\0"), Encoding.UTF8.GetBytes("{\"size\":9007199254740991,\"tree\":\"t\"}")));
        Assert.Equal(want, Bind(9007199254740991d, "t"));
    }

    [Fact]
    public void LeafIndexMustBeBelowTheSize()
    {
        static bool Leaf(long index) => (bool)Call("LeafOk", new object?[] { LeafRoot("a"), 1L, "a", OneLeaf(index) })!;
        Assert.True(Leaf(0));
        Assert.False(Leaf(1));
        Assert.False(Leaf(-1));
    }

    static D Side(string? id) { var o = new D { ["proof"] = OneLeaf() }; if (id != null) o["id"] = id; return o; }

    [Fact]
    public void NonMembershipLeafNeedsAStringId()
    {
        Assert.True(Mesh.NonMembership(LeafRoot(""), new D { ["size"] = N(1), ["lo"] = Side("") }, "x"));
        Assert.False(Mesh.NonMembership(LeafRoot(""), new D { ["size"] = N(1), ["lo"] = Side(null) }, "x"));
        Assert.True(Mesh.NonMembership(LeafRoot("z"), new D { ["size"] = N(1), ["hi"] = Side("z") }, "a"));
        Assert.False(Mesh.NonMembership(LeafRoot("z"), new D { ["size"] = N(1), ["hi"] = Side(null) }, "a"));
    }

    [Fact]
    public void NonMembershipTreatsATruthyNonObjectSideAsPresent()
    {
        Assert.False(Mesh.NonMembership(LeafRoot("z"), new D { ["size"] = N(1), ["lo"] = N(1), ["hi"] = Side("z") }, "a"));
        Assert.True(Mesh.NonMembership(LeafRoot("z"), new D { ["size"] = N(1), ["lo"] = N(0), ["hi"] = Side("z") }, "a"));
        Assert.False(Mesh.NonMembership(LeafRoot("a"), new D { ["size"] = N(1), ["lo"] = Side("a"), ["hi"] = true }, "b"));
        Assert.True(Mesh.NonMembership(LeafRoot("a"), new D { ["size"] = N(1), ["lo"] = Side("a"), ["hi"] = "" }, "b"));
        var emptyRoot = Bind(0, Empty)!;
        Assert.True(Mesh.NonMembership(emptyRoot, new D { ["size"] = N(0) }, "a"));
        Assert.False(Mesh.NonMembership(emptyRoot, new D { ["size"] = N(0), ["lo"] = N(1) }, "a"));
    }

    // ---- consistency (ledger.ts verifyLedgerConsistency)

    static bool C(string oldRoot, string newRoot, D proof) => (bool)Call("Consistency", new object?[] { oldRoot, newRoot, proof })!;

    [Fact]
    public void ConsistencySizesMustBeIntegers()
    {
        var r = Hx(1);
        Assert.False(C(r, r, Cp("a", N(1))));
        Assert.False(C(r, r, Cp(N(1), "a")));
        Assert.False(C(r, r, new D { ["path"] = new L() }));
    }

    [Fact]
    public void ConsistencyOldSizeMustBeWithinRange()
    {
        var r = Hx(1);
        Assert.False(C(r, r, Cp(N(2), N(1))));
        Assert.False(C(r, r, Cp(N(-1), N(0))));
        Assert.True(C(r, r, Cp(N(5), N(5))));
    }

    [Fact]
    public void ConsistencyPathMustBeAnArrayWithinTheLedgerBound()
    {
        Assert.Equal(108, Ledger.MaxConsistencyPath);
        Assert.False(C(Empty, Hx(1), new D { ["oldSize"] = N(0), ["newSize"] = N(5) }));
        Assert.False(C(Empty, Hx(1), new D { ["oldSize"] = N(0), ["newSize"] = N(5), ["path"] = "x" }));
        Assert.True(C(Empty, Hx(1), Cp(N(0), N(5))));
        var r = Hx(1);
        Assert.False(C(r, r, Cp(N(1), N(2), Strs(109))));
    }

    [Fact]
    public void ConsistencyFromTheEmptyTree()
    {
        Assert.True(C(Empty, Empty, Cp(N(0), N(0))));
        Assert.False(C(Empty, Hx(1), Cp(N(0), N(0))));
        Assert.True(C(Empty, Hx(1), Cp(N(0), N(5))));
    }

    [Fact]
    public void ConsistencyAtEqualSizes()
    {
        string r = Hx(1), s = Hx(2);
        Assert.True(C(r, r, Cp(N(1), N(1))));
        Assert.False(C(r, r, Cp(N(1), N(1), new L { s })));
        Assert.False(C(r, s, Cp(N(1), N(1))));
    }

    [Fact]
    public void ConsistencyDecodesEveryNodeStrictly()
    {
        string r = Hx(1), c = Hx(2);
        Assert.True(C(r, NodeOf(r, c), Cp(N(1), N(2), new L { c })));
        Assert.False(C("!!!", NodeOf(r, c), Cp(N(1), N(2), new L { c })));
        Assert.False(C(r, NodeOf(r, c), Cp(N(1), N(2), new L { N(5) })));
    }

    // ---- trust (mesh.ts validTrust)

    static readonly EdKey Human = Key(1), DomA = Key(2), DomB = Key(3), Wit = Key(4), H0 = Key(5), H1 = Key(6);
    static EdKey Key(byte b) => EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray());

    static D BaseTrust() => new()
    {
        ["humanPrincipal"] = Human.Id, ["witnesses"] = new L { Wit.Id }, ["threshold"] = N(1), ["now"] = N(Now),
        ["allowedDomains"] = new L { DomA.Id, DomB.Id }, ["rootDomain"] = DomA.Id,
    };

    static object TrustObject(D t)
    {
        var tuple = (ITuple)Call("ValidTrust", new object?[] { t })!;
        Assert.Null(tuple[1]);
        return tuple[0]!;
    }

    [Fact]
    public void IssuerDomainsMustAllBeStrings()
    {
        static string Reason(D map) { var t = BaseTrust(); t["issuerDomains"] = map; return Mesh.Verify(null, t).Reason; }
        Assert.Equal("malformed proof", Reason(new D()));
        Assert.Equal("malformed proof", Reason(new D { ["a"] = "x" }));
        Assert.Equal("invalid trust configuration: issuerDomains", Reason(new D { ["a"] = "x", ["b"] = N(1) }));
        Assert.Equal("invalid trust configuration: issuerDomains", Reason(new D { ["b"] = N(1) }));
    }

    [Fact]
    public void PqPinsAreReadFromTheirKeyKeepingStringsOnly()
    {
        var t = BaseTrust();
        t["pqPins"] = new D { ["k"] = "v", ["n"] = N(1) };
        var trust = TrustObject(t);
        var pins = (Dictionary<string, string>?)trust.GetType().GetField("PqPins")!.GetValue(trust);
        Assert.NotNull(pins);
        Assert.Single(pins!);
        Assert.Equal("v", pins!["k"]);
    }

    // ---- heads (mesh.ts checkCosignedHead)

    static string Signed(EdKey k, string domain, object? body) => Pca.B64u(k.Sign(IntentJs.Message(domain, body)));

    static D Cosigned(EdKey dom, string root)
    {
        var head = new D
        {
            ["domain"] = dom.Id, ["size"] = N(1), ["root"] = root, ["rev_root"] = Bind(0, Empty), ["rev_size"] = N(0), ["timestamp"] = N(Now - 1000),
        };
        return new D
        {
            ["head"] = head, ["sig"] = Signed(dom, Mesh.HeadDomain, head),
            ["cosigs"] = new L { new D { ["witness"] = Wit.Id, ["sig"] = Signed(Wit, Mesh.CosigDomain, head) } },
        };
    }

    static string? CheckHead(object? ch, string domain) => (string?)Call("CheckCosignedHead", new object?[] { ch, domain, TrustObject(BaseTrust()), null });

    [Fact]
    public void CosignedHeadForAnotherDomainIsNamed()
    {
        Assert.Equal("head is for a different domain", CheckHead(new D { ["head"] = new D { ["domain"] = "y" } }, "x"));
        Assert.Equal("head is for a different domain", CheckHead(null, "x"));
    }

    [Fact]
    public void CosigListBoundIs256()
    {
        var ch = Cosigned(DomA, Hx(9));
        var cosigs = (L)ch["cosigs"]!;
        while (cosigs.Count < 256) cosigs.Add(null);
        Assert.Null(CheckHead(ch, DomA.Id));
        cosigs.Add(null);
        Assert.Equal("malformed head", CheckHead(ch, DomA.Id));
    }

    // ---- whole proofs (mesh.ts verifyMeshProof)

    static D Hop(EdKey dom, long head, D? binding = null)
    {
        var ev = new D
        {
            ["domain"] = dom.Id, ["head"] = N(head),
            ["inclusion"] = new D { ["index"] = N(0), ["size"] = N(1), ["path"] = new L() },
            ["revocation"] = new D { ["cap"] = new D { ["size"] = N(0) }, ["issuer_key"] = new D { ["size"] = N(0) } },
        };
        if (binding != null) ev["binding"] = binding;
        return ev;
    }

    static D Act() => new() { ["type"] = "t", ["resource"] = "/r/x", ["service_domain"] = "svc", ["nonce"] = "n", ["at"] = N(Now) };

    static D ProofOf(L chain, L hops, L heads, EdKey tipHolder)
    {
        var action = Act();
        var tip = chain[^1];
        return new D
        {
            ["chain"] = chain, ["hops"] = hops, ["heads"] = heads, ["rev_leaves"] = new L(), ["action"] = action,
            ["action_sig"] = Signed(tipHolder, Mesh.ActionDomain, new D { ["action"] = action, ["tip"] = Pca.CapHash(tip) }),
        };
    }

    static D Root() => Issue.MintRoot(SuiteKey.Ed25519(Human), H0.Id, null, new L { new D { ["type"] = "scope", ["actions"] = new L { "t" } } });

    static D OneHop()
    {
        var root = Root();
        return ProofOf(new L { root }, new L { Hop(DomA, 0) }, new L { Cosigned(DomA, Pca.MerkleRoot(new L { Pca.CapHash(root) })) }, H0);
    }

    static D TwoHops()
    {
        var root = Root();
        var child = Issue.Delegate(root, H1.Id, new L { new D { ["type"] = "resource", ["prefix"] = "/r/" } }, SuiteKey.Ed25519(H0));
        var bindingBody = new D { ["agent"] = H0.Id, ["domain"] = DomB.Id, ["role"] = "r" };
        var binding = new D(bindingBody) { ["sig"] = Signed(DomB, Mesh.BindingDomain, bindingBody) };
        return ProofOf(new L { root, child }, new L { Hop(DomA, 0), Hop(DomB, 1, binding) },
            new L { Cosigned(DomA, Pca.MerkleRoot(new L { Pca.CapHash(root) })), Cosigned(DomB, Pca.MerkleRoot(new L { Pca.CapHash(child) })) }, H1);
    }

    [Fact]
    public void ASingleHopProofVerifiesWithAnEmptyReasonAndNoHop()
    {
        var v = Mesh.Verify(OneHop(), BaseTrust());
        Assert.True(v.Ok, v.Reason);
        Assert.Equal("", v.Reason);
        Assert.Equal(-1, v.Hop);
    }

    [Fact]
    public void ATwoHopProofVerifies()
    {
        var v = Mesh.Verify(TwoHops(), BaseTrust());
        Assert.True(v.Ok, v.Reason);
    }

    // capHash(cap) throws in the reference, past its chain check: an unsigned member is not in the signed body.
    [Fact]
    public void AnUnhashableUnsignedCapMemberIsAMalformedProofWithNoHop()
    {
        var p = OneHop();
        ((D)((L)p["chain"]!)[0]!)["x"] = "\ud800";
        Assert.Equal(new MeshVerdict(false, "malformed proof", -1), Mesh.Verify(p, BaseTrust()));
    }

    [Fact]
    public void PinProofBoundIs256()
    {
        static string Reason(int n)
        {
            var pins = Enumerable.Range(0, n).Select(_ => (object?)new D { ["domain"] = "d", ["proof"] = Cp(N(0), N(0)) }).ToList();
            var p = new D
            {
                ["chain"] = new L(), ["hops"] = new L(), ["heads"] = new L(), ["rev_leaves"] = new L(), ["action"] = Act(), ["action_sig"] = "s", ["pin_proofs"] = pins,
            };
            return Mesh.Verify(p, BaseTrust()).Reason;
        }
        Assert.Equal("chain length out of bounds", Reason(255));
        Assert.Equal("chain length out of bounds", Reason(256));
        Assert.Equal("malformed pin proofs", Reason(257));
    }
}
