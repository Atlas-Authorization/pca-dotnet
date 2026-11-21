using System.Security.Cryptography;
using AtlasPca.AttestEat;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the entity-attestation-token package against the TypeScript reference: the constants, the channel binding, the
/// freshness and channel-binding gates, the RATS appraisal, the verdict projection and its canonical co-signature bytes, the token build and verify, the digest join, the tolerant
/// report parse, the AMD silicon verification, the fresh-token pipeline, the post-quantum co-signature, the admission evidence and the artifact discharge.</summary>
public class RefAttestEatTests
{
    const string M = "ref-attest-eat";

    [Fact] public void GenCorpusIsPresent() => Base.RequireGenCorpus(M);
    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["EAT_TYP"] = PcaAttestEat.EatTyp,
        ["DEFAULT_EAT_ALG"] = PcaAttestEat.DefaultEatAlg,
        ["DEFAULT_MAX_AGE_MS"] = PcaAttestEat.DefaultMaxAgeMs,
        ["CHANNEL_BINDING_DOMAIN"] = PcaAttestEat.ChannelBindingDomain,
        ["AMD_SEV_SNP_SIGNED_REGION_END"] = PcaAttestEat.AmdSevSnpSignedRegionEnd,
        ["AMD_SEV_SNP_HARDWARE_ROOT_LABEL"] = PcaAttestEat.AmdSevSnpHardwareRootLabel,
        ["KNOWN_REPORT_VERSIONS"] = PcaAttestEat.KnownReportVersions,
        ["KNOWN_AMD_ARK_SPKI_SHA384"] = PcaAttestEat.KnownAmdArkSpkiSha384.ToDictionary(e => e.Key, e => (object?)e.Value),
        ["AMD_MILAN_ARK_SPKI_SHA384"] = PcaAttestEat.KnownAmdArkSpkiSha384["milan"],
        ["PQCOSIGN_DOMAIN"] = PcaAttestEat.PqCoSignDomain,
        ["DEFAULT_PQ_COSIGN_SUITE"] = PcaAttestEat.DefaultPqCoSignSuite,
        ["PQ_COSIGN_SUITES"] = PcaAttestEat.PqCoSignSuites,
    });

    [Fact] public void DeriveChannelCnf() => Base.Check(M, "deriveChannelCnf", a => PcaAttestEat.DeriveChannelCnf(a[0], a.Count > 1 ? a[1] : null));
    [Fact] public void BindChannel() => Base.Check(M, "bindChannel", a => PcaAttestEat.BindChannel(a[0], a[1], a[2]));
    /// <summary>Cases where the port is stricter than these vectors (a present clock skew that is not a finite number; a minimum tier other than
    /// affirming / affirming-hw-rooted): the current reference refuses them too, the vectors predate that fix. Each must refuse.</summary>
    static readonly HashSet<string> Stricter = new()
    {
        "verifyFreshness/skew junk string", "verifyFreshness/skew junk stale", "verifyFreshness/skew string number", "verifyFreshness/skew null",
        "verifyFreshness/skew true", "verifyFreshAttestedEAT/amd skew junk", "eatAdmissionEvidence/min tier unknown", "eatAdmissionEvidence/min tier null",
    };

    static bool StrictEq(D c, object? have) => Stricter.Contains((string)c["name"]!) ? have is D d && d.GetValueOrDefault("ok") is false : Base.Eq(c["out"], have);

    /// <summary>The corpus clock of the generator: its first read (every later read is one millisecond on). A case without a usable "now" ran against it.</summary>
    static readonly double GeneratorClockMs = Base.ClockMs(M);

    [Fact] public void VerifyFreshness() => Base.Check(M, "verifyFreshness", a => PcaAttestEat.VerifyFreshness(a[0], a[1], () => GeneratorClockMs + 1), StrictEq);

    [Fact]
    public void NonFiniteSkewAndUnknownMinTierAreRefused()
    {
        var eat = new D { ["eat_nonce"] = "n1", ["iat"] = 1_000_000_000.0 }; // decades stale: only an unbounded skew would admit it
        foreach (var skew in new object?[] { double.PositiveInfinity, double.NegativeInfinity, double.NaN, "5", null, true })
        {
            var r = PcaAttestEat.VerifyFreshness(eat, new D { ["expectedNonce"] = "n1", ["now"] = 1_800_000_000_000.0, ["maxAgeMs"] = 60_000.0, ["clockSkewMs"] = skew });
            Assert.Equal(false, r["ok"]);
            Assert.Equal("invalid clockSkewMs (must be a finite number)", r["reason"]);
        }
    }
    [Fact] public void VerifyChannelBinding() => Base.Check(M, "verifyChannelBinding", a => PcaAttestEat.VerifyChannelBinding(a[0], a[1]));

    [Fact]
    public void Appraise() => Base.Check(M, "appraise", a =>
    {
        // the reference refuses an explicit null policy argument (it reads a member of it)
        for (int i = 1; i < a.Count; i++) if (a[i] == null) return Base.Refused;
        return PcaAttestEat.Appraise(a[0], a.Count > 1 ? a[1] : null, a.Count > 2 ? a[2] : null, a.Count > 3 ? a[3] : null);
    });

    [Fact] public void VerdictFromAppraisal() => Base.Check(M, "verdictFromAppraisal", a => PcaAttestEat.VerdictFromAppraisal(a[0], a[1]));
    [Fact] public void CanonicalVerdictBytes() => Base.Check(M, "canonicalVerdictBytes", a => PcaAttestEat.CanonicalVerdictBytes(a[0], a[1]));
    [Fact] public void IsPqCoSignSuite() => Base.Check(M, "isPqCoSignSuite", a => PcaAttestEat.IsPqCoSignSuite(a[0]));
    [Fact] public void Ed25519Jkt() => Base.Check(M, "ed25519Jkt", a => PcaAttestEat.Ed25519Jkt((string)a[0]!));

    static byte[] Bx(object? s) => Pca.B64uDecode(s) ?? throw new InvalidDataException("bad base64url key member");

    /// <summary>A key spec: signing {alg: "EdDSA", seed} / {alg: "ES256", d, x, y}; verifying {alg: "EdDSA", pub} / {alg: "ES256", x, y}.</summary>
    static EatKey KeyOf(object? spec)
    {
        var k = (D)spec!;
        return (string)k["alg"]! == "EdDSA"
            ? (k.ContainsKey("seed") ? EatKey.Ed25519Private(Bx(k["seed"])) : EatKey.Ed25519Public(Bx(k["pub"])))
            : (k.ContainsKey("d") ? EatKey.Es256Private(Bx(k["d"]), Bx(k["x"]), Bx(k["y"])) : EatKey.Es256Public(Bx(k["x"]), Bx(k["y"])));
    }

    [Fact]
    public void BuildEat() => Base.Check(M, "buildEAT", a =>
    {
        var args = (D)a[0]!;
        var rest = new D(args); rest.Remove("key");
        return EatToken.BuildEat(rest, KeyOf(args["key"]));
    });

    [Fact] public void VerifyEat() => Base.Check(M, "verifyEAT", a => EatToken.VerifyEat(a[0], KeyOf(a[1]), a.Count > 2 ? a[2] : null));
    [Fact] public void RuntimeDigestFromEat() => Base.Check(M, "runtimeDigestFromEat", a => EatToken.RuntimeDigestFromEat(a[0], a.Count > 1 ? a[1] : null));

    /// <summary>The tree with every {"$bytes": ...} object replaced by its bytes.</summary>
    static object? Rev(object? v) => v switch
    {
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Rev(e.Value)),
        L l => l.Select(Rev).ToList(),
        _ => v,
    };

    /// <summary>The options without their verifyKey member, and that key.</summary>
    static (D Opts, EatKey Key) SplitKey(object? opts)
    {
        var o = new D((D)Rev(opts)!);
        var key = KeyOf(o["verifyKey"]);
        o.Remove("verifyKey");
        return (o, key);
    }

    [Fact]
    public void ParseReportTolerant() => Base.Check(M, "parseReportTolerant", a =>
    {
        var r = EatAmd.ParseReportTolerant(Base.Bytes(a[0]));
        var o = new D { ["ok"] = r.Ok, ["version"] = r.Version, ["known"] = r.Known, ["degraded"] = r.Degraded, ["notes"] = r.Notes, ["hasReport"] = r.HasReport };
        if (r.Evidence != null) o["evidence"] = r.Evidence;
        if (r.Measured != null) o["measured"] = r.Measured;
        return o;
    });

    [Fact]
    public void VerifyAmdAttestation() => Base.Check(M, "verifyAmdAttestation", a =>
    {
        var r = EatAmd.VerifyAmdAttestation(Base.Bytes(a[0]), Rev(a[1]));
        var o = new D { ["ok"] = r.Ok, ["hardwareRoot"] = r.HardwareRoot };
        if (r.Reason != null) o["reason"] = r.Reason;
        if (r.Evidence != null) o["evidence"] = r.Evidence;
        if (r.Measured != null) o["measured"] = r.Measured;
        return o;
    });

    [Fact]
    public void VerifyFreshAttestedEat() => Base.Check(M, "verifyFreshAttestedEAT", a =>
    {
        var (o, key) = SplitKey(a[1]);
        return EatFresh.VerifyFreshAttestedEat(a[0], key, o);
    }, StrictEq);

    [Fact]
    public void EatAdmissionEvidence() => Base.Check(M, "eatAdmissionEvidence", a =>
    {
        var (o, key) = SplitKey(a[1]);
        return EatFresh.EatAdmissionEvidence(a[0], key, o);
    }, StrictEq);

    static Pq.Prim PrimOf(string name) => name switch
    {
        "ml-dsa-65" => Pq.Prim.MlDsa65,
        "ml-dsa-87" => Pq.Prim.MlDsa87,
        "slh-dsa-sha2-128f" => Pq.Prim.Slh128f,
        "slh-dsa-sha2-256s" => Pq.Prim.Slh256s,
        _ => throw new InvalidDataException("unknown primitive " + name),
    };

    [Fact]
    public void CoSignAttestation() => Base.Check(M, "coSignAttestation", a =>
    {
        var op = (D)a[1]!;
        var spec = (D)op["key"]!;
        EdKey? ed = spec.TryGetValue("ed", out var e) ? EdKey.FromSeed(Bx(e)) : null;
        PqKey? pq = null;
        if (spec.TryGetValue("pq", out var p)) { var pd = (D)p!; pq = PqKey.FromSeed(PrimOf((string)pd["prim"]!), Bx(pd["seed"])); }
        return EatPqCoSign.CoSignAttestation(a[0], ed, pq, op.GetValueOrDefault("suite"), op.GetValueOrDefault("now"));
    });

    /// <summary>Without a usable "now" the age is measured against the generator's counted clock (one more millisecond per read): the age is not reproducible, everything else is compared.</summary>
    static bool CoSignedEq(D c, object? have)
    {
        var args = Base.Args(c);
        bool clocked = !(args.Count > 1 && args[1] is D o && IntentJs.IsNumber(o.GetValueOrDefault("now")));
        if (!clocked || c["out"] is not D want || !want.ContainsKey("ageMs")) return Base.Eq(c["out"], have);
        var w = new D(want); w.Remove("ageMs");
        var h = Base.Json(have) is D hd ? new D(hd) : null;
        if (h == null) return false;
        h.Remove("ageMs");
        return Base.Show(w) == Base.Show(h);
    }

    [Fact] public void VerifyCoSignedAttestation() => Base.Check(M, "verifyCoSignedAttestation", a => EatPqCoSign.VerifyCoSignedAttestation(a[0], a.Count > 1 ? a[1] : null), CoSignedEq);

    [Fact]
    public void IssueArtifactDischarge() => Base.Check(M, "issueArtifactDischarge", a =>
    {
        var i = (D)a[0]!;
        var roots = Sigstore.ParseTrustedRoot(i["roots"]);
        var issuer = SuiteKey.Ed25519(EdKey.FromSeed(Bx(((D)i["issuerKey"]!)["seed"])));
        // the reference's discharge nonce is the first 16 bytes of sha256("eat-oracle-nonce/0")
        return EatProvenance.IssueArtifactDischarge(i, roots, issuer, () => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("eat-oracle-nonce/0"))[..16]);
    });

    [Fact]
    public void CoversEveryFn() { Base.Covers(M, new[]
    {
        "constants", "deriveChannelCnf", "bindChannel", "verifyFreshness", "verifyChannelBinding", "appraise", "verdictFromAppraisal", "canonicalVerdictBytes", "isPqCoSignSuite", "ed25519Jkt",
        "buildEAT", "verifyEAT", "runtimeDigestFromEat",
        "parseReportTolerant", "verifyAmdAttestation", "verifyFreshAttestedEAT", "coSignAttestation", "verifyCoSignedAttestation", "eatAdmissionEvidence", "issueArtifactDischarge",
    }); Assert.Equal(1448, Base.Total(M)); }
}
