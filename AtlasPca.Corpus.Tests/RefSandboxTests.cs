using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using AtlasPca.Sandbox;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using S = AtlasPca.Sandbox.PcaSandbox;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-sandbox oracle: policy compile, OS profiles, runtime claims, receipt chains, handle table, egress admission, the private-address
/// check and the reference WebAssembly builders. The WebAssembly host, the component host and the proxy server are not part of the port.</summary>
public class RefSandboxTests
{
    const string M = "ref-sandbox";

    static D Err() => new() { ["$err"] = true };
    static D AsD(object? o) => (D)o!;
    static L AsL(object? o) => (L)o!;
    static object? Arg(L a, int i) => i < a.Count ? a[i] : null;
    static double Dbl(object? o) => IntentJs.NumOf(o) ?? double.NaN;
    static long Idx(object? o) { var d = IntentJs.NumOf(o); return d == null || d != Math.Round(d.Value) ? 0 : (long)d.Value; }
    static Num N(double d) => new(JsJson.NumberToString(d));
    static byte[] SeedOf(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    /// <summary>What the reference's authorization result looks like for {allow, bind}: an operation bound to the digest of bind.params.</summary>
    static AuthorizeResult Result(bool allow, object? bind)
    {
        AuthorizedOperation? op = null;
        if (bind != null)
        {
            var b = AsD(bind);
            op = new AuthorizedOperation((string)b["verb"]!, (string)b["resource"]!, Pca.HashCanonical(b.GetValueOrDefault("params")), b.GetValueOrDefault("id") as string ?? "op");
        }
        return new AuthorizeResult { Allow = allow, Status = allow ? 200 : 403, Operation = op };
    }

    static Operation Op(object? o)
    {
        var op = AsD(o);
        return new Operation((string)op["verb"]!, (string)op["resource"]!, op.GetValueOrDefault("params"));
    }

    [Fact]
    public void Consts() => Base.Check(M, "moduleConsts", _ => new D
    {
        ["IMPORT_MODULE"] = S.ImportModule,
        ["ALLOWED_IMPORTS"] = S.AllowedImports,
        ["USE_ERR"] = S.UseErr,
        ["GENESIS"] = S.Genesis,
        ["RUNTIME_CLASSES"] = S.RuntimeClasses,
        ["DOMAIN"] = S.RuntimeClaimDomain,
    });

    [Fact] public void Satisfies() => Base.Check(M, "satisfiesRuntimeClass", a => S.SatisfiesRuntimeClass(a[0], a[1]));

    [Fact]
    public void ReceiptLog() => Base.Check(M, "receiptLog", a =>
    {
        var spec = AsD(a[0]);
        object? t = new Num("0");
        var log = new S.ReceiptLog(() => t, spec.GetValueOrDefault("sign") is true ? d => "sig:" + d : null);
        var outs = new L();
        foreach (var s in AsL(spec["appends"]))
        {
            var st = AsD(s);
            t = st["t"];
            try { outs.Add(log.Append((string)st["rc"]!, AsD(st["body"]))); } catch (Exception) { outs.Add(Err()); }
        }
        return outs;
    });

    [Fact] public void ReceiptChain() => Base.Check(M, "verifyReceiptChain", a => S.VerifyReceiptChain(a[0], a[1] is "tag" ? (d, s) => s == "sig:" + d : null));

    [Fact] public void PolicyFromNeeds() => Base.Check(M, "policyFromNeeds", a => S.PolicyFromNeeds(a[0], Arg(a, 1)));

    [Fact]
    public void CompilePolicy() => Base.Check(M, "compilePolicy", a =>
    {
        var spec = AsD(a[0]);
        var items = new List<AuthorizedOp>();
        foreach (var o in AsL(spec["items"]))
        {
            var it = AsD(o);
            items.Add(new AuthorizedOp(Result(it.GetValueOrDefault("allow") is true, it.GetValueOrDefault("bind")), Op(it["operation"])));
        }
        var needs = AsD(spec["needs"]);
        return S.CompilePolicy(items, op => needs.GetValueOrDefault(op.Verb + " " + op.Resource), spec.GetValueOrDefault("proxyPort"));
    });

    [Fact] public void Seccomp() => Base.Check(M, "seccompProfile", a => S.SeccompProfile(AsD(a[0])));
    [Fact] public void Landlock() => Base.Check(M, "landlockRuleset", a => S.LandlockRuleset(AsD(a[0])));
    [Fact] public void Macos() => Base.Check(M, "macosProfile", a => S.MacosProfile(AsD(a[0])));
    [Fact] public void ConfineArgs() => Base.Check(M, "confineArgs", a => S.ConfineArgs(AsD(a[0])));
    [Fact]
    public void PrivateAddress()
    {
        Base.Check(M, "isPrivateAddress", a => S.IsPrivateAddress(a[0]));
        foreach (var ip in new object?[] { null, 1.0, new L { "::1" }, new D() }) Assert.True(S.IsPrivateAddress(ip));
        foreach (var ip in new[] { "0::1", "::FFFF:7F00:0001", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "fe80::1%25eth0", "2606:4700::1111%eth0", "FE80::1",
                     "fc::1", "1fff::1", "4000::1", "1::2::3", "::00001", "::01.2.3.4", "[::1]", " ::1" })
            Assert.True(S.IsPrivateAddress(ip), ip);
        foreach (var ip in new[] { "2606:4700:0:0:0:0:0:1111", "2001:DB8::1", "::ffff:808:808", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2000::", "3fff::1", "8.8.8.8" })
            Assert.False(S.IsPrivateAddress(ip), ip);
    }

    [Fact]
    public void Egress() => Base.Check(M, "egress", a =>
    {
        double t = 0;
        var p = new S.EgressPolicy(() => t);
        var outs = new L();
        foreach (var s in AsL(AsD(a[0])["steps"]))
        {
            var st = AsD(s);
            try
            {
                var op = (string)st["op"]!;
                if (op == "now") { t = Dbl(st["t"]); outs.Add(null); }
                else if (op == "admit")
                {
                    var tmpl = st.GetValueOrDefault("template");
                    var opts = st.GetValueOrDefault("opts") is D od ? od : new D();
                    p.Admit(Result(st.GetValueOrDefault("allow") is true, st.GetValueOrDefault("bind")), Op(st["operation"]), _ =>
                    {
                        if (tmpl == null) return null;
                        return tmpl as D ?? throw new ArgumentException("bad_template");
                    }, opts.GetValueOrDefault("uses"), opts.GetValueOrDefault("expiresAt"));
                    outs.Add("ok");
                }
                else
                {
                    var req = AsD(st["req"]);
                    outs.Add(p.Claim(req.GetValueOrDefault("method"), req.GetValueOrDefault("url"), req.GetValueOrDefault("body") == null ? null : Base.Bytes(req["body"])));
                }
            }
            catch (Exception) { outs.Add(Err()); }
        }
        return outs;
    });

    static readonly Dictionary<string, SandboxExecutor> Exec = new()
    {
        ["fs.read"] = (verb, resource, prms) => new byte[] { 1, 2, 3 },
        ["fs.echo"] = (verb, resource, prms) => Encoding.UTF8.GetBytes(JsJson.Stringify(new D { ["verb"] = verb, ["resource"] = resource, ["params"] = prms })),
        ["fs.throw"] = (verb, resource, prms) => throw new InvalidOperationException("boom"),
        ["fs.notbytes"] = (verb, resource, prms) => null,
    };

    [Fact]
    public void Handles() => Base.Check(M, "handles", a =>
    {
        var spec = AsD(a[0]);
        object? t = new Num("0");
        var log = new S.ReceiptLog(() => t);
        var table = new S.HandleTable((string)spec["cls"]!, log, Exec, () => Dbl(t));
        var outs = new L();
        foreach (var s in AsL(spec["steps"]))
        {
            var st = AsD(s);
            try
            {
                switch ((string)st["op"]!)
                {
                    case "now": t = st["t"]; outs.Add(null); break;
                    case "mint":
                    {
                        object? bind;
                        if (st.ContainsKey("bind")) bind = st["bind"];
                        else
                        {
                            var b = new D(AsD(st["operation"]));
                            b["id"] = st.GetValueOrDefault("id") ?? "op-h";
                            bind = b;
                        }
                        var opts = st.GetValueOrDefault("opts") is D od ? od : new D();
                        var mo = new S.MintOptions { Uses = opts.GetValueOrDefault("uses"), ExpiresAt = opts.GetValueOrDefault("expiresAt"), Requires = opts.GetValueOrDefault("requires") as string };
                        bool allow = st.GetValueOrDefault("allow") == null || st["allow"] is true;
                        outs.Add((long)table.Mint(Result(allow, bind), Op(st["operation"]), mo));
                        break;
                    }
                    case "attenuate":
                    {
                        var n = st.GetValueOrDefault("narrower") is D nd ? nd : new D();
                        outs.Add((long)table.Attenuate(Idx(st.GetValueOrDefault("index")), n.GetValueOrDefault("uses"), n.GetValueOrDefault("expiresAt")));
                        break;
                    }
                    case "revoke": table.Revoke(Idx(st.GetValueOrDefault("index"))); outs.Add(null); break;
                    case "use": outs.Add(table.Use(Idx(st.GetValueOrDefault("index"))).ToMap()); break;
                    case "verbOf": outs.Add(table.VerbOf(Idx(st.GetValueOrDefault("index")))); break;
                    default: outs.Add((long)table.Size); break;
                }
            }
            catch (Exception) { outs.Add(Err()); }
        }
        return new D { ["outs"] = outs, ["log"] = log.Entries };
    });

    [Fact]
    public void RuntimeClaims()
    {
        Base.Check(M, "signRuntimeClaim", a =>
        {
            var k = a[0];
            var sk = k is string ks ? SeedOf(ks) : new byte[(int)Dbl(AsD(k)["short"])];
            return S.SignRuntimeClaim(sk, EdKey.FromSeed(SeedOf((string)a[1]!)).Pub, AsD(a[2]));
        });
        Base.Check(M, "verifiedRuntimeClass", a => S.VerifiedRuntimeClass(a[0], a[1]));
        Base.Check(M, "passportDigest", a => S.PassportDigest(a[0]));
        Base.Check(M, "evidenceDigest", a => S.EvidenceDigest(a[0]));
    }

    /// <summary>Negative times and empty or over-long digests are none even when correctly signed and trusted.</summary>
    [Fact]
    public void RuntimeClaimStrictForm()
    {
        var sk = SeedOf("strict-attestor");
        var pub = EdKey.FromSeed(sk).Pub;
        string Run(D over, D tOver)
        {
            var c = new D { ["class"] = "os_confined", ["passport_digest"] = "pd", ["evidence_digest"] = "ev", ["iat"] = N(0), ["exp"] = N(100) };
            foreach (var kv in over) c[kv.Key] = kv.Value;
            var claim = S.SignRuntimeClaim(sk, pub, c);
            var t = new D { ["pinnedAttestors"] = new L { claim["attestor"] }, ["passportDigest"] = claim["passport_digest"], ["verifiedEvidenceDigests"] = new L { claim["evidence_digest"] }, ["now"] = N(50) };
            foreach (var kv in tOver) t[kv.Key] = kv.Value;
            return S.VerifiedRuntimeClass(claim, t);
        }
        Assert.Equal("os_confined", Run(new D(), new D()));
        Assert.Equal("none", Run(new D { ["iat"] = N(-5) }, new D()));
        Assert.Equal("none", Run(new D { ["iat"] = N(-10), ["exp"] = N(-1) }, new D { ["now"] = N(-5) }));
        Assert.Equal("none", Run(new D { ["iat"] = N(-10) }, new D { ["now"] = N(-1) }));
        Assert.Equal("none", Run(new D { ["evidence_digest"] = "" }, new D()));
        Assert.Equal("none", Run(new D { ["passport_digest"] = "" }, new D()));
        Assert.Equal("none", Run(new D { ["evidence_digest"] = new string('d', 129) }, new D()));
        Assert.Equal("none", Run(new D { ["passport_digest"] = new string('d', 129) }, new D()));
        Assert.Equal("none", Run(new D(), new D { ["now"] = N(9007199254740992) }));
        Assert.Equal("os_confined", Run(new D { ["evidence_digest"] = new string('d', 128), ["passport_digest"] = new string('p', 128) }, new D()));
    }

    [Fact]
    public void ReferenceModules()
    {
        Base.Check(M, "buildTool", a => S.BuildTool(AsD(a[0])));
        Base.Check(M, "buildProbeTool", a => S.BuildProbeTool(Arg(a, 0)));
        Base.Check(M, "referenceComponentWat", a => S.ReferenceComponentWat(a.Count == 0 ? null : AsD(a[0])));
    }

    [Fact]
    public void TrustFromAttestationAdmitsOnlyBoundEvidence()
    {
        var doc = new D { ["format"] = "x" };
        var good = new D { ["ok"] = true, ["bound"] = true };
        var unbound = new D { ["ok"] = true, ["bound"] = false };
        var pinned = new[] { "k" };
        Assert.Equal(S.EvidenceDigest(doc), (string)AsL(S.TrustFromAttestation(doc, () => good, 5, pinned, "p")["verifiedEvidenceDigests"])[0]!);
        Assert.Empty(AsL(S.TrustFromAttestation(doc, () => unbound, 5, pinned, "p")["verifiedEvidenceDigests"]));
        Assert.Empty(AsL(S.TrustFromAttestation(doc, () => throw new InvalidOperationException("x"), 5, pinned, "p")["verifiedEvidenceDigests"]));
        Assert.Empty(AsL(S.TrustFromAttestation(doc, () => "nope", 5, pinned, "p")["verifiedEvidenceDigests"]));
    }

    [Fact]
    public void AllFnsCovered() { Base.Covers(M, new[]
    {
        "moduleConsts", "satisfiesRuntimeClass", "receiptLog", "verifyReceiptChain", "policyFromNeeds", "compilePolicy", "seccompProfile", "landlockRuleset", "macosProfile",
        "confineArgs", "isPrivateAddress", "egress", "handles", "signRuntimeClaim", "verifiedRuntimeClass", "passportDigest", "evidenceDigest", "buildTool", "buildProbeTool", "referenceComponentWat",
    }); Assert.Equal(1604, Base.Total(M)); }
}
