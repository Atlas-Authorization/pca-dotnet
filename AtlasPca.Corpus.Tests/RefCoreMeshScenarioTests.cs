using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the two scripted mesh corpora: the issuing side of a domain (test-data/ref-core-mesh-domain-java.json.gz: enrolment, per-hop evidence,
/// pin proofs, non-membership proofs) and proof assembly with action signing (test-data/ref-core-mesh-proof-java.json.gz). A case is one op sequence over
/// fresh domains and witnesses; every op's result must equal the reference's, a refused op is recorded as <c>{"$err": "Error"}</c>.</summary>
public class RefCoreMeshScenarioTests
{
    const string Dom = "ref-core-mesh-domain-java";
    const string Proof = "ref-core-mesh-proof-java";

    static EdKey Key(string scope, object? label) => EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + scope + "/" + (string)label!)));

    static D Cap(object? label) => new()
    {
        ["id"] = (string)label!, ["issuer"] = "iss-" + (string)label!, ["holder"] = "h",
        ["caveats"] = new L { new D { ["type"] = "scope", ["actions"] = new L { label } } },
    };

    static L Script(L args, Func<L, object?> f)
    {
        var outp = new L();
        foreach (var o in (L)args[0]!)
        {
            try { outp.Add(f((L)o!)); }
            catch (Exception) { outp.Add(new D { ["$err"] = "Error" }); }
        }
        return outp;
    }

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");
    static int? Threshold(object? o) => o == null ? null : (int)Dbl(o);
    static D Need(Dictionary<string, D> store, object? name) => store.TryGetValue((string)name!, out var v) ? v : throw new InvalidOperationException("unknown " + name);

    [Fact]
    public void MeshDomainOps() => Base.Check(Dom, "meshDomain", a =>
    {
        var doms = new Dictionary<string, MeshDomain>();
        var ws = new Dictionary<string, MeshWitness>();
        var heads = new Dictionary<string, D>();
        var binds = new Dictionary<string, D>();
        return Script(a, op =>
        {
            switch ((string)op[0]!)
            {
                case "domain": { var d = new MeshDomain((string)op[1]!, Key("mesh-domain", op[2])); doms[d.Name] = d; return d.Id; }
                case "witness": { var w = new MeshWitness(Key("mesh-domain", op[2])); ws[(string)op[1]!] = w; return w.Id; }
                case "record": return doms[(string)op[1]!].Record(Cap(op[2]));
                case "revoke": doms[(string)op[1]!].Revoke((string)op[2]!); return null;
                case "publish":
                {
                    var h = doms[(string)op[1]!].PublishHead(((L)op[4]!).Select(w => ws[(string)w!]).ToList(), Dbl(op[3]), Threshold(op[5]));
                    heads[(string)op[2]!] = h;
                    return h;
                }
                case "fork": heads[(string)op[1]!] = new D(Need(heads, op[2])) { [(string)op[3]!] = op[4] }; return null;
                case "enroll": { var b = doms[(string)op[1]!].Enroll((string)op[3]!, (string)op[4]!); binds[(string)op[2]!] = b; return b; }
                case "evidence": return doms[(string)op[1]!].Evidence(Cap(op[2]), Need(heads, op[3]), op[4] == null ? null : Need(binds, op[4]));
                case "pinProof": return doms[(string)op[1]!].PinProof(op[2] is string pin ? (D)Need(heads, pin)["head"]! : (D)op[2]!, Need(heads, op[3]));
                // the domain's revocation set as of now (its revoke calls so far)
                case "nonMembership": return doms[(string)op[1]!].RevocationSetCopy().NonMembershipProof(op[2] as string ?? throw new ArgumentException("not a string"));
                default: throw new InvalidOperationException("op");
            }
        });
    }, min: 18);

    [Fact]
    public void MeshProofOps() => Base.Check(Proof, "meshProof", a =>
    {
        var doms = new Dictionary<string, MeshDomain>();
        var ws = new Dictionary<string, MeshWitness>();
        var store = new Dictionary<string, D>();
        List<D> Chain(object? labels) => ((L)labels!).Select(Cap).ToList();
        return Script(a, op =>
        {
            switch ((string)op[0]!)
            {
                case "domain": { var d = new MeshDomain((string)op[1]!, Key("mesh-proof", op[2])); doms[d.Name] = d; return d.Id; }
                case "witness": { var w = new MeshWitness(Key("mesh-proof", op[2])); ws[(string)op[1]!] = w; return w.Id; }
                case "record": return doms[(string)op[1]!].Record(Cap(op[2]));
                case "revoke": doms[(string)op[1]!].Revoke((string)op[2]!); return null;
                case "publish":
                {
                    var h = doms[(string)op[1]!].PublishHead(((L)op[4]!).Select(w => ws[(string)w!]).ToList(), Dbl(op[3]), Threshold(op[5]));
                    store[(string)op[2]!] = h;
                    return h;
                }
                case "subcos":
                {
                    var h = new D(Need(store, op[2]));
                    var all = (L)h["cosigs"]!;
                    h["cosigs"] = ((L)op[3]!).Select(i => all[(int)Dbl(i)]).ToList();
                    store[(string)op[1]!] = h;
                    return null;
                }
                case "fork": store[(string)op[1]!] = new D(Need(store, op[2])) { [(string)op[3]!] = op[4] }; return null;
                case "forkHead":
                {
                    var h = new D(Need(store, op[2]));
                    h["head"] = new D((D)h["head"]!) { [(string)op[3]!] = op[4] };
                    store[(string)op[1]!] = h;
                    return null;
                }
                case "enroll": { var b = doms[(string)op[1]!].Enroll((string)op[3]!, (string)op[4]!); store[(string)op[2]!] = b; return b; }
                case "ev":
                {
                    var e = doms[(string)op[1]!].Evidence(Cap(op[3]), Need(store, op[4]), op[5] == null ? null : Need(store, op[5]));
                    store[(string)op[2]!] = e;
                    return e;
                }
                case "setEv":
                {
                    var e = new D(Need(store, op[2]));
                    var member = (string)op[3]!;
                    // {"$del": true} removes the member; a stored head's name stands for that head
                    if (op[4] is D del && del.ContainsKey("$del")) e.Remove(member);
                    else if (member == "head" && op[4] is string hn && store.ContainsKey(hn)) e["head"] = store[hn];
                    else e[member] = op[4];
                    store[(string)op[1]!] = e;
                    return null;
                }
                case "pinProofAs":
                {
                    var p = doms[(string)op[1]!].PinProof(op[3] is string pin ? (D)Need(store, pin)["head"]! : (D)op[3]!, Need(store, op[4]));
                    store[(string)op[2]!] = p;
                    return p;
                }
                case "assemble":
                {
                    var hops = ((L)op[2]!).Select(n => Need(store, n)).ToList();
                    var pins = op[5] == null ? null : ((L)op[5]!).Select(n => (object?)Need(store, n)).ToList();
                    return Signers.AssembleMeshProof(Chain(op[1]), hops, (D)op[3]!, Key("mesh-proof", op[4]), pins);
                }
                case "sign": return Signers.SignMeshAction(Chain(op[1]), (D)op[2]!, Key("mesh-proof", op[3]));
                default: throw new InvalidOperationException("op");
            }
        });
    }, min: 8);

    [Fact]
    public void Covers()
    {
        Base.Covers(Dom, new[] { "meshDomain" });
        Assert.Equal(18, Base.Cases(Dom).Count);
        Base.Covers(Proof, new[] { "meshProof" });
        Assert.Equal(8, Base.Cases(Proof).Count);
    }
}
