using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The RIM half of the NVIDIA collateral against the reference (packages/pca/src/attest-nvidia-rim.ts and its
/// mutation-kill-nvidia-rim.test.ts): exact reasons, boundaries, the firmware policy, the RIM ids, the golden comparison and revocation.
/// RIMs are real enveloped XMLDSig documents signed here under a generated P-384 chain.</summary>
public class NvidiaRimKillTests
{
    const string Ds = "http://www.w3.org/2000/09/xmldsig#", C14n = "http://www.w3.org/2006/12/xml-c14n11", Env = "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        Ecdsa384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", Sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    const string DefaultMeta = "<Meta product=\"GH100\" colloquialVersion=\"1.2\"/>";
    const string IdsMissing = "GPU report does not carry the opaque fields needed to name its RIMs";
    const string NoCollateral = "no RIM collateral supplied for this report";
    const string NoCrls = "revocation: no CRLs supplied";
    const string Malformed = "RIM: malformed Measurement resource";
    const string Inconsistent = "RIM: Measurement 4 hash list is inconsistent with alternatives/size";
    const string BadTransforms = "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]";
    const string MissingValues = "RIM: missing DigestValue / SignatureValue";
    const string NoSigners = "RIM: no signer certificates in KeyInfo";
    const string MissingParts = "RIM: missing Meta / Payload";
    const string BadSignature = "RIM: SignedInfo signature does not verify under the signer certificate";
    const string BadSigLength = "RIM: SignatureValue is not a 96-byte P-384 signature";

    static readonly long Now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    static readonly ECDsa LeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384), MidKey = ECDsa.Create(ECCurve.NamedCurves.nistP384),
        RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384), Stranger = ECDsa.Create(ECCurve.NamedCurves.nistP384);

    static byte[] Cert(string subject, ECDsa key, string issuerCn, ECDsa signer, byte serial, bool ca)
    {
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA384);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        if (ca) req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return req.Create(new X500DistinguishedName("CN=" + issuerCn), X509SignatureGenerator.CreateForECDsa(signer),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new[] { serial }).RawData;
    }

    static readonly byte[] LeafDer = Cert("CN=GH100-leaf", LeafKey, "mid", MidKey, 0x11, false),
        MidDer = Cert("CN=mid", MidKey, "root", RootKey, 0x22, true),
        RootDer = Cert("CN=root", RootKey, "root", RootKey, 0x33, true);
    static string Pin => AttestCerts.KeyOf(AttestCerts.ParseDer(RootDer)).SpkiSha256();
    static string[] Pins => new[] { Pin };
    static List<AttCert> Chain => new List<AttCert> { AttestCerts.ParseDer(LeafDer), AttestCerts.ParseDer(MidDer), AttestCerts.ParseDer(RootDer) };

    static readonly Regex DigestRe = new("<ds:DigestValue>[^<]*</ds:DigestValue>"), SigValueRe = new("<ds:SignatureValue>[^<]*</ds:SignatureValue>");

    static string CertElems() => string.Concat(new[] { LeafDer, MidDer, RootDer }.Select(d => "<ds:X509Certificate>" + Convert.ToBase64String(d) + "</ds:X509Certificate>"));

    static string TransformList(params string[] algs) => string.Concat(algs.Select(a => $"<ds:Transform Algorithm=\"{a}\"/>"));

    static readonly string SigBlock =
        $"<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{C14n}\"/><ds:SignatureMethod Algorithm=\"{Ecdsa384}\"/>" +
        $"<ds:Reference URI=\"\"><ds:Transforms>{TransformList(Env, C14n)}</ds:Transforms>" +
        $"<ds:DigestMethod Algorithm=\"{Sha384}\"/><ds:DigestValue>x</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>x</ds:SignatureValue>" +
        $"<ds:KeyInfo><ds:X509Data>{CertElems()}</ds:X509Data></ds:KeyInfo></ds:Signature>";

    /// <summary>A measurement resource; hash value "aa", one alternative, size one unless told otherwise.</summary>
    static string Res(string index = "0", string active = "True", string alts = "1", string size = "1", string hashes = "Hash0=\"aa\"", string type = "Measurement", string tag = "Resource") =>
        $"<{tag} type=\"{type}\" index=\"{index}\" active=\"{active}\" alternatives=\"{alts}\" size=\"{size}\" {hashes}/>";

    static string Pl(params string[] resources) => "<Payload>" + string.Concat(resources) + "</Payload>";
    static string Doc(string body) => $"<SoftwareIdentity xmlns:ds=\"{Ds}\">{body}{SigBlock}</SoftwareIdentity>";

    /// <summary>Structurally complete, but DigestValue and SignatureValue are placeholders: enough for every check before the cryptography.</summary>
    static readonly string Base = Doc(DefaultMeta + Pl(Res()));

    /// <summary>Fills DigestValue and SignatureValue the way the verifier recomputes them.</summary>
    static string Sign(string xml, ECDsa? key = null)
    {
        var root = AttestXml.Parse(xml).Root!;
        var canon = AttestXml.Canonicalize(root, new Dictionary<string, string>(StringComparer.Ordinal), root.ElementChildrenNs(Ds, "Signature")[0]);
        xml = DigestRe.Replace(xml, "<ds:DigestValue>" + Convert.ToBase64String(AttestUtil.Sha384(Encoding.UTF8.GetBytes(canon))) + "</ds:DigestValue>", 1);
        root = AttestXml.Parse(xml).Root!;
        var si = root.ElementChildrenNs(Ds, "Signature")[0].ElementChildrenNs(Ds, "SignedInfo")[0];
        var siCanon = AttestXml.Canonicalize(si, si.Parent!.Scope(), null);
        var sig = (key ?? LeafKey).SignHash(AttestUtil.Sha384(Encoding.UTF8.GetBytes(siCanon)), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return SigValueRe.Replace(xml, "<ds:SignatureValue>" + Convert.ToBase64String(sig) + "</ds:SignatureValue>", 1);
    }

    static string Rim(string product, string version, params string[] resources) =>
        Sign(Doc($"<Meta product=\"{product}\" colloquialVersion=\"{version}\"/>" + Pl(resources)));

    static string Why(string xml) => NvidiaHook.VerifyRim(xml, Pins, Now).Why;

    static string WhyRes(params string[] resources) => Why(Sign(Doc(DefaultMeta + Pl(resources))));

    static VerifiedRim Ok(string xml)
    {
        var (rim, why) = NvidiaHook.VerifyRim(xml, Pins, Now);
        Assert.Equal("", why);
        return rim!;
    }

    static string Drop(string pattern) => Regex.Replace(Base, pattern, "");

    // ---- document guards

    [Fact]
    public void TheDocumentCapIsFourMillionChars()
    {
        const string oversized = "RIM: empty or oversized document";
        Assert.Equal(oversized, Why(""));
        Assert.Equal(oversized, Why(new string('x', 4_000_001)));
        Assert.Equal("RIM: verification error (fail closed): text outside the document element", Why(new string('x', 4_000_000)));
    }

    [Fact]
    public void APinIsRequired() =>
        Assert.Equal("RIM: no pinned RIM root configured", NvidiaHook.VerifyRim(Base, Array.Empty<string>(), Now).Why);

    [Fact]
    public void AParseFailureFailsClosed() =>
        Assert.Equal("RIM: verification error (fail closed): no document element", Why(" "));

    [Fact]
    public void ProfileViolationsComeBeforeTheStructure() =>
        Assert.Equal("RIM: XML comments are not permitted", Why("<!--c-->" + Base));

    [Fact]
    public void RootAndSignaturePlacement()
    {
        Assert.Equal("RIM: root element is not SoftwareIdentity", Why("<Other/>"));
        Assert.Equal("RIM: expected exactly one Signature element", Why("<SoftwareIdentity/>"));
        Assert.Equal("RIM: the Signature must be a direct child of the root", Why($"<SoftwareIdentity xmlns:ds=\"{Ds}\"><W><ds:Signature/></W></SoftwareIdentity>"));
        Assert.Equal("RIM: expected exactly one SignedInfo", Why($"<SoftwareIdentity xmlns:ds=\"{Ds}\"><ds:Signature/></SoftwareIdentity>"));
    }

    // ---- nesting: the recursive walks must never see an overflowing document (they would end the process)

    static string Nested(int n) => string.Concat(Enumerable.Repeat("<a>", n)) + string.Concat(Enumerable.Repeat("</a>", n));

    [Fact]
    public void NestingIsCappedAtMaxDepth()
    {
        Assert.Equal(256, AttestXml.MaxDepth);
        Assert.Equal("RIM: root element is not SoftwareIdentity", Why(Nested(256)));
        Assert.Equal("RIM: verification error (fail closed): elements nested deeper than 256", Why(Nested(257)));
        // a self-closing element counts as a level too
        Assert.Equal("elements nested deeper than 256", Assert.Throws<AttestError>(() => AttestXml.Parse(string.Concat(Enumerable.Repeat("<a>", 256)) + "<b/>" + string.Concat(Enumerable.Repeat("</a>", 256)))).Message);
        Assert.NotNull(AttestXml.Parse(string.Concat(Enumerable.Repeat("<a>", 255)) + "<b/>" + string.Concat(Enumerable.Repeat("</a>", 255))).Root);
    }

    [Fact]
    public void SiblingsDoNotCountAsNesting()
    {
        var wide = "<r>" + string.Concat(Enumerable.Repeat("<a/>", 300)) + string.Concat(Enumerable.Repeat("<b></b>", 300)) + "</r>";
        Assert.Equal(600, AttestXml.Parse(wide).Root!.ElementChildren().Count);
    }

    // ---- SignedInfo

    [Fact]
    public void AlgorithmElementsMissingOrWrong()
    {
        const string c = "RIM: CanonicalizationMethod must be C14N 1.1", s = "RIM: SignatureMethod must be ECDSA-SHA384", d = "RIM: DigestMethod must be SHA-384";
        Assert.Equal(c, Why(Drop("<ds:CanonicalizationMethod[^>]*/>")));
        Assert.Equal(c, Why(Base.Replace($"<ds:CanonicalizationMethod Algorithm=\"{C14n}\"", "<ds:CanonicalizationMethod Algorithm=\"urn:x\"")));
        Assert.Equal(s, Why(Drop("<ds:SignatureMethod[^>]*/>")));
        Assert.Equal(s, Why(Base.Replace($"<ds:SignatureMethod Algorithm=\"{Ecdsa384}\"", "<ds:SignatureMethod Algorithm=\"urn:x\"")));
        Assert.Equal(d, Why(Drop("<ds:DigestMethod[^>]*/>")));
        Assert.Equal(d, Why(Base.Replace($"<ds:DigestMethod Algorithm=\"{Sha384}\"", "<ds:DigestMethod Algorithm=\"urn:x\"")));
    }

    [Fact]
    public void ExactlyOneReferenceOverTheWholeDocument()
    {
        const string one = "RIM: expected exactly one Reference";
        Assert.Equal(one, Why(Drop("<ds:Reference.*</ds:Reference>")));
        Assert.Equal(one, Why(Base.Replace("</ds:SignedInfo>", "<ds:Reference/></ds:SignedInfo>")));
        Assert.Equal("RIM: Reference URI must be \"\" (the whole document)", Why(Base.Replace("URI=\"\"", "URI=\"#x\"")));
    }

    public static IEnumerable<object[]> WrongTransforms() => new[]
    {
        new object[] { new[] { C14n, C14n } }, new object[] { new[] { Env, Env } }, new object[] { new[] { C14n, Env } }, new object[] { new[] { Env } },
        new object[] { Array.Empty<string>() }, new object[] { new[] { Env, C14n, C14n } }, new object[] { new[] { Env, C14n, Env } },
        new object[] { new[] { "urn:x", C14n } }, new object[] { new[] { Env, "urn:x" } },
    };

    [Theory]
    [MemberData(nameof(WrongTransforms))]
    public void TransformsMustBeExact(string[] algs) =>
        Assert.Equal(BadTransforms, Why(Base.Replace(TransformList(Env, C14n), TransformList(algs))));

    [Fact]
    public void TransformsMayBeDirectChildrenOfTheReference() =>
        Assert.Single(Ok(Sign(Base.Replace("<ds:Transforms>", "").Replace("</ds:Transforms>", ""))).Golden);

    // ---- values and signer chain

    [Fact]
    public void BothValuesAreRequiredOnTheirOwn()
    {
        Assert.Equal(MissingValues, Why(Base.Replace("<ds:DigestValue>x</ds:DigestValue>", "")));
        Assert.Equal(MissingValues, Why(Base.Replace("<ds:SignatureValue>x</ds:SignatureValue>", "")));
        Assert.Equal(MissingValues, Why(Base.Replace("<ds:DigestValue>x</ds:DigestValue>", "<ds:DigestValue> \n</ds:DigestValue>")));
        Assert.Equal(MissingValues, Why(Base.Replace("<ds:SignatureValue>x</ds:SignatureValue>", "<ds:SignatureValue>\t</ds:SignatureValue>")));
    }

    [Fact]
    public void SignerCertificatesMustBePresent()
    {
        Assert.Equal(NoSigners, Why(Drop("<ds:KeyInfo>.*</ds:KeyInfo>")));
        Assert.Equal(NoSigners, Why(Drop("<ds:X509Data>.*</ds:X509Data>")));
        Assert.Equal(NoSigners, Why(Regex.Replace(Base, "<ds:X509Data>.*</ds:X509Data>", "<ds:X509Data/>")));
    }

    [Fact]
    public void SignerCertificateTextMayCarryWhitespace()
    {
        var spaced = Regex.Replace(Base, "<ds:X509Certificate>([^<]{70})([^<]*)</ds:X509Certificate>", "<ds:X509Certificate>\n  $1\t\n$2 </ds:X509Certificate>");
        Assert.NotEqual(Base, spaced);
        Assert.Single(Ok(Sign(spaced)).Golden);
    }

    static string WithSignature(byte[] raw) => Base.Replace("<ds:SignatureValue>x<", "<ds:SignatureValue>" + Convert.ToBase64String(raw) + "<");

    [Theory]
    [InlineData(3)]
    [InlineData(95)]
    [InlineData(97)]
    public void TheSignatureMustBe96Bytes(int n) => Assert.Equal(BadSigLength, Why(WithSignature(new byte[n])));

    [Fact]
    public void TheSignatureMustVerifyUnderTheSigner()
    {
        Assert.Equal(BadSignature, Why(WithSignature(new byte[96])));
        Assert.Equal(BadSignature, Why(Sign(Base, Stranger)));
        Assert.Single(Ok(Sign(Base)).Golden);
    }

    // ---- extraction

    [Fact]
    public void TheFirstMetaAndPayloadAreRead()
    {
        var rim = Ok(Sign(Doc("<Meta product=\"A\" colloquialVersion=\"1\"/><Meta product=\"B\" colloquialVersion=\"2\"/>" + Pl(Res("3")) + Pl(Res("5")))));
        Assert.Equal("A", rim.Product);
        Assert.Equal("1", rim.Version);
        Assert.Equal(new[] { 3 }, rim.Golden.Keys.ToArray());
    }

    [Fact]
    public void MetaAndPayloadAreBothRequired()
    {
        Assert.Equal(MissingParts, Why(Sign(Doc(Pl(Res())))));
        Assert.Equal(MissingParts, Why(Sign(Doc(DefaultMeta))));
        Assert.Equal(MissingParts, Why(Sign(Doc("<Entity/>" + Pl(Res())))));
        Assert.Equal(MissingParts, Why(Sign(Doc(DefaultMeta + "<Entity/>"))));
    }

    [Fact]
    public void OnlyMeasurementResourcesAreRead()
    {
        var rim = Ok(Sign(Doc(DefaultMeta + Pl(Res("1"), Res("99", tag: "Other"), Res("98", type: "Other"), Res("2", active: "TRUE"), Res("7", active: "False")))));
        Assert.Equal(new[] { 1, 2, 7 }, rim.Golden.Keys.ToArray());
        Assert.True(rim.Golden[2].Active);
        Assert.False(rim.Golden[7].Active);
        Assert.Equal(new RimGolden(1, true, 1, 1, rim.Golden[1].Hashes), rim.Golden[1]);
        Assert.Equal(new[] { "aa" }, rim.Golden[1].Hashes.ToArray());
    }

    [Fact]
    public void HashesAreSortedNumericallyAndLowercased()
    {
        var order = new[] { 2, 10, 0, 1, 9, 3, 4, 5, 6, 7, 8 };
        var attrs = string.Join(" ", order.Select(k => $"Hash{k}=\"{k:X2}\"")) + " NotHash5=\"ff\" Hash1x=\"ee\" XHash7=\"dd\" hash3=\"cc\"";
        var rim = Ok(Sign(Doc(DefaultMeta + Pl(Res(alts: "11", hashes: attrs)))));
        Assert.Equal(new[] { "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a" }, rim.Golden[0].Hashes.ToArray());
    }

    [Theory]
    [InlineData("x", "1", "1")]
    [InlineData("-1", "1", "1")]
    [InlineData("1.5", "1", "1")]
    [InlineData("9000000000000000000", "1", "1")]
    [InlineData("1", "0", "1")]
    [InlineData("1", "1.5", "1")]
    [InlineData("1", "x", "1")]
    [InlineData("1", "9000000000000000000", "1")]
    [InlineData("1", "1", "0")]
    [InlineData("1", "1", "-1")]
    [InlineData("1", "1", "1.5")]
    [InlineData("1", "1", "x")]
    [InlineData("1", "1", "9000000000000000000")]
    public void MalformedResources(string index, string alts, string size) =>
        Assert.Equal(Malformed, WhyRes(Res(index, alts: alts, size: size)));

    [Theory]
    [InlineData("2", "2", "Hash0=\"aabb\"")]
    [InlineData("1", "2", "Hash0=\"aabb\" Hash1=\"ccdd\"")]
    [InlineData("2", "2", "Hash0=\"aabb\" Hash1=\"cc\"")]
    [InlineData("2", "2", "Hash0=\"cc\" Hash1=\"aabb\"")]
    [InlineData("1", "2", "Hash0=\"aabbcc\"")]
    [InlineData("1", "2", "Hash0=\"gg11\"")]
    [InlineData("1", "2", "Hash0=\"11gg\"")]
    public void InconsistentHashLists(string alts, string size, string hashes) =>
        Assert.Equal(Inconsistent, WhyRes(Res("4", alts: alts, size: size, hashes: hashes)));

    [Fact]
    public void DuplicatesAndAnEmptyPayload()
    {
        Assert.Equal("RIM: duplicate Measurement index 3", WhyRes(Res("3"), Res("3")));
        Assert.Equal("RIM: no measurements", WhyRes());
        Assert.Equal("RIM: no measurements", WhyRes(Res(type: "Other")));
    }

    // ---- firmware policy

    static List<double> V(params double[] parts) => parts.ToList();

    [Fact]
    public void ParseVersionUsesTheRadixPattern()
    {
        Assert.Null(FirmwarePolicy.ParseVersion("1a", 10));
        Assert.Equal(V(26), FirmwarePolicy.ParseVersion("1a", 16));
        Assert.Equal(V(12345), FirmwarePolicy.ParseVersion("12345", 10));
        Assert.Null(FirmwarePolicy.ParseVersion("12345", 16));
    }

    [Fact]
    public void CmpReadsAMissingComponentAsZero()
    {
        Assert.Equal(1, FirmwarePolicy.Cmp(V(1, 0, 1), V(1)));
        Assert.Equal(-1, FirmwarePolicy.Cmp(V(1), V(1, 0, 1)));
        Assert.Equal(0, FirmwarePolicy.Cmp(V(1, 0, 0), V(1)));
    }

    [Fact]
    public void AnEmptyFloorIsNoFloor()
    {
        var p = FirmwarePolicy.Compile(new JD { ["minDriverVersion"] = "", ["minVbiosVersion"] = "" });
        Assert.Null(p.MinD);
        Assert.Null(p.MinV);
        p = FirmwarePolicy.Compile(new JD { ["minDriverVersion"] = null, ["minVbiosVersion"] = null });
        Assert.Null(p.MinD);
        Assert.Null(p.MinV);
    }

    static string CompileError(string key, object? value) =>
        Assert.Throws<ArgumentException>(() => FirmwarePolicy.Compile(new JD { [key] = value })).Message;

    [Fact]
    public void MalformedVersionsRefuseTheConfiguration()
    {
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion 'x1.2'", CompileError("minDriverVersion", "x1.2"));
        Assert.Equal("nvidiaCollateralHook: malformed minVbiosVersion 'zz'", CompileError("minVbiosVersion", "zz"));
        Assert.Equal("nvidiaCollateralHook: malformed denyDriverVersions entry 'q'", CompileError("denyDriverVersions", new JL { "1.2", "q" }));
        Assert.Equal("nvidiaCollateralHook: malformed denyVbiosVersions entry 'zz'", CompileError("denyVbiosVersions", new JL { "zz" }));
    }

    /// <summary>Reference: a truthy non-string floor throws "malformed ... '5'". It must never read as no floor (that accepted any firmware).</summary>
    [Fact]
    public void ANonStringFloorRefusesTheConfiguration()
    {
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion '5'", CompileError("minDriverVersion", new Num("5")));
        Assert.Equal("nvidiaCollateralHook: malformed minVbiosVersion '5'", CompileError("minVbiosVersion", new Num("5")));
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion 'true'", CompileError("minDriverVersion", true));
        // the reference reads the falsy 0 and false as no floor (attest-nvidia-rim.ts:430-431); refused here
        Assert.Equal("nvidiaCollateralHook: malformed minDriverVersion '0'", CompileError("minDriverVersion", new Num("0")));
        Assert.Equal("nvidiaCollateralHook: malformed minVbiosVersion 'false'", CompileError("minVbiosVersion", false));
    }

    static NvidiaRimIds Fw(string driver, string vbios) => new() { DriverVersion = driver, VbiosVersion = vbios };

    [Fact]
    public void FirmwareChecksAndReasons()
    {
        var none = FirmwarePolicy.Compile(new JD());
        Assert.Equal("driver version 'x' in the GPU report is not parseable", none.Check(Fw("x", "1")));
        Assert.Equal("VBIOS version 'z' in the GPU report is not parseable", none.Check(Fw("1", "z")));

        var minV = FirmwarePolicy.Compile(new JD { ["minVbiosVersion"] = "96.00" });
        Assert.Equal("", minV.Check(Fw("1", "96.00")));
        Assert.Equal("", minV.Check(Fw("1", "96.01")));
        Assert.Equal("VBIOS 95.ff is below the minimum 96.00", minV.Check(Fw("1", "95.ff")));

        var minD = FirmwarePolicy.Compile(new JD { ["minDriverVersion"] = "2.1" });
        Assert.Equal("", minD.Check(Fw("2.1", "1")));
        Assert.Equal("driver 2.0 is below the minimum 2.1", minD.Check(Fw("2.0", "1")));

        var deny = FirmwarePolicy.Compile(new JD { ["denyDriverVersions"] = new JL { "2.1" }, ["denyVbiosVersions"] = new JL { "ab" } });
        Assert.Equal("driver 2.1.0 is on the deny list", deny.Check(Fw("2.1.0", "1")));
        Assert.Equal("VBIOS AB is on the deny list", deny.Check(Fw("1", "AB")));
    }

    // ---- hook construction

    [Fact]
    public void AtLeastOneRimRootMustBePinned()
    {
        const string m = "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root";
        Assert.Equal(m, Assert.Throws<ArgumentException>(() => NvidiaHook.Create(new JD())).Message);
        Assert.Equal(m, Assert.Throws<ArgumentException>(() => NvidiaHook.Create(new JD { ["rimRootSpkiSha256"] = new JL() })).Message);
        Assert.Equal(m, Assert.Throws<ArgumentException>(() => NvidiaHook.Create(new JD { ["rimRootSpkiSha256"] = new JL { 1d } })).Message);
    }

    // ---- RIM ids (private: the names are unused until a resolver consumes them, so the reference's naming is pinned directly)

    static byte[] A(string s) => Encoding.Latin1.GetBytes(s);

    static Dictionary<int, byte[]> Op(params (int K, byte[]? V)[] over)
    {
        var o = new Dictionary<int, byte[]> { [3] = A("1.2"), [6] = new byte[] { 0x01, 0x02 }, [17] = A("P"), [18] = A("S"), [15] = A("C") };
        foreach (var (k, v) in over)
        {
            if (v == null) o.Remove(k);
            else o[k] = v;
        }
        return o;
    }

    static NvidiaRimIds? Ids(Dictionary<int, byte[]> opaque) =>
        (NvidiaRimIds?)typeof(NvidiaHook).GetMethod("RimIdsForReport", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { new SpdmReport { Opaque = opaque } });

    [Fact]
    public void HopperIdsUpperCaseTheVbiosParts()
    {
        var plain = Ids(Op())!;
        Assert.Equal("GH100", plain.Chip);
        Assert.Equal("1.2", plain.DriverVersion);
        Assert.Equal("01.02", plain.VbiosVersion);
        Assert.Equal("NV_GPU_DRIVER_GH100_1.2", plain.Driver);
        Assert.Equal("NV_GPU_VBIOS_P_S_C_0102", plain.Vbios);

        var lower = Ids(Op((17, A("g520\0")), (18, A("ab12\0")), (15, A("x9z\0")), (6, new byte[] { 0xab, 0xcd })))!;
        Assert.Equal("ab.cd", lower.VbiosVersion);
        Assert.Equal("NV_GPU_VBIOS_G520_AB12_X9Z_ABCD", lower.Vbios);
    }

    [Fact]
    public void ChipInfoSelectsTheNaming()
    {
        var gb = Ids(Op((35, A("GB100\0\0"))))!;
        Assert.Equal("GB100", gb.Chip);
        Assert.Equal("NV_GPU_CC_DRIVER_GB100_1.2", gb.Driver);
        Assert.Equal("NV_GPU_DRIVER_GH100_1.2", Ids(Op((35, A("GH100"))))!.Driver);
        Assert.Equal("G12A34567890", Ids(Op((35, A("G12A34567890"))))!.Chip);
    }

    [Theory]
    [InlineData("gb100")]
    [InlineData("G1")]
    [InlineData("GB")]
    [InlineData("G12A345678901")]
    [InlineData("1B100")]
    [InlineData("GB-100")]
    [InlineData("GB 100")]
    [InlineData("GB100\nX")]
    [InlineData("")]
    public void AMalformedChipInfoNamesNothing(string chip) => Assert.Null(Ids(Op((35, A(chip)))));

    [Fact]
    public void OpaqueTextIsTrimmedAfterItsTrailingNuls() =>
        Assert.Equal("1.2", Ids(Op((3, A("  1.2  \0\0"))))!.DriverVersion);

    [Theory]
    [InlineData(3)]
    [InlineData(6)]
    [InlineData(17)]
    [InlineData(18)]
    [InlineData(15)]
    public void EveryRequiredFieldIsRequiredOnItsOwn(int key)
    {
        Assert.Null(Ids(Op((key, null))));
        Assert.Equal(IdsMissing, Bare().Run(new SpdmReport { Opaque = Op((key, null)) }, Chain, Now));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(17)]
    [InlineData(18)]
    [InlineData(15)]
    public void ABlankFieldIsMissing(int key) => Assert.Null(Ids(Op((key, new byte[4]))));

    // ---- the hook proper

    static NvidiaHook Hook(JD? extra = null)
    {
        var col = new JD { ["rimRootSpkiSha256"] = new JL { Pin } };
        foreach (var (k, v) in extra ?? new JD()) col[k] = v;
        return NvidiaHook.Create(col);
    }

    static NvidiaHook Bare() => Hook().WithBundle(null);

    static readonly JD NoCrl = new() { ["requireCrls"] = false };

    static SpdmReport Rep(Dictionary<int, byte[]>? opaque, params (int Index, byte Digest)[] blocks)
    {
        var r = new SpdmReport { Opaque = opaque ?? Op() };
        foreach (var (i, d) in blocks) r.Measurements.Add((i, new[] { d }));
        return r;
    }

    static string DriverXml => Rim("GH100", "1.2", Res("0"));
    static string VbiosXml => Rim("GH100", "01.02", Res("1", hashes: "Hash0=\"bb\""));
    static string InactiveVbios => Rim("GH100", "01.02", Res("9", active: "False"));

    static SpdmReport GoodRep() => Rep(null, (1, 0xaa), (2, 0xbb));

    static JD Bundle(string? driver = null, string? vbios = null, JL? crls = null, JL? ocsp = null)
    {
        var b = new JD();
        if (driver != null) b["driverRimXml"] = driver;
        if (vbios != null) b["vbiosRimXml"] = vbios;
        if (crls != null) b["crls"] = crls;
        if (ocsp != null) b["ocsp"] = ocsp;
        return b;
    }

    static string Run(JD? extra, JD bundle, SpdmReport? rep = null, List<AttCert>? chain = null) =>
        Hook(extra).WithBundle(bundle).Run(rep ?? GoodRep(), chain ?? Chain, Now);

    static string Compare(string driver, string vbios, SpdmReport rep) => Run(NoCrl, Bundle(driver, vbios), rep);

    [Fact]
    public void TheConsistentScenarioIsAccepted() => Assert.Equal("", Run(NoCrl, Bundle(DriverXml, VbiosXml)));

    static List<AttCert> LeafChain(string subject) =>
        new List<AttCert> { AttestCerts.ParseDer(Cert(subject, LeafKey, "mid", MidKey, 0x11, false)), Chain[1], Chain[2] };

    [Theory]
    [InlineData("CN=AGH100")]
    [InlineData("CN=GH100A")]
    [InlineData("CN=xGH100y")]
    [InlineData("CN=GH10")]
    public void TheLeafMustNameTheChipAsAWholeWord(string subject) =>
        Assert.Equal($"device leaf subject '{subject}' is not a GH100 device certificate (chip family mismatch)", Bare().Run(GoodRep(), LeafChain(subject), Now));

    [Theory]
    [InlineData("CN=GH100")]
    [InlineData("CN=x-GH100-y")]
    public void TheChipMayBeDelimitedByPunctuation(string subject) =>
        Assert.Equal(NoCollateral, Bare().Run(GoodRep(), LeafChain(subject), Now));

    [Fact]
    public void TheMismatchMessageRendersTheSubjectOnOneLine()
    {
        var chain = LeafChain("CN=device, O=Acme");
        var line = AttestCerts.NameText(chain[0].RawSubject);
        Assert.Contains("\n", line);
        var r = Bare().Run(GoodRep(), chain, Now);
        Assert.Equal($"device leaf subject '{line.Replace("\n", ", ")}' is not a GH100 device certificate (chip family mismatch)", r);
    }

    [Fact]
    public void ChipInfoDecidesWhichLeafIsAccepted()
    {
        var blackwell = Rep(Op((35, A("GB100\0"))));
        Assert.Equal(NoCollateral, Bare().Run(blackwell, LeafChain("CN=GB100"), Now));
        Assert.Equal("device leaf subject 'CN=GH100-leaf' is not a GB100 device certificate (chip family mismatch)", Bare().Run(blackwell, Chain, Now));
        Assert.Equal(IdsMissing, Bare().Run(Rep(Op((35, A("gb100")))), LeafChain("CN=gb100"), Now));
    }

    [Fact]
    public void AMissingDocumentIsAttributedToItsRim()
    {
        const string empty = "RIM: empty or oversized document";
        Assert.Equal("driver RIM: " + empty, Run(NoCrl, Bundle(vbios: VbiosXml)));
        Assert.Equal("VBIOS RIM: " + empty, Run(NoCrl, Bundle(driver: DriverXml)));
    }

    [Fact]
    public void ProductBinding()
    {
        Assert.Equal("driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)", Run(NoCrl, Bundle(Rim("GB100", "1.2", Res("0")), VbiosXml)));
        Assert.Equal("VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)", Run(NoCrl, Bundle(DriverXml, Rim("GB100", "01.02", Res("1", hashes: "Hash0=\"bb\"")))));
    }

    // ---- golden comparison

    /// <summary>Reference order: the VBIOS Map iterates in document order, so the first conflict in the document is the one reported.</summary>
    [Fact]
    public void AConflictIsReportedInVbiosDocumentOrder()
    {
        var driver = Rim("GH100", "1.2", Res("1"), Res("2"));
        Assert.Equal("driver and VBIOS RIMs both have an active measurement at index 2", Compare(driver, Rim("GH100", "01.02", Res("2"), Res("1")), GoodRep()));
        Assert.Equal("driver and VBIOS RIMs both have an active measurement at index 1", Compare(driver, Rim("GH100", "01.02", Res("1"), Res("2")), GoodRep()));
    }

    [Fact]
    public void AnInactiveDriverEntryDoesNotConflict() =>
        Assert.Equal("", Compare(Rim("GH100", "1.2", Res("1", active: "False")), Rim("GH100", "01.02", Res("0"), Res("1", hashes: "Hash0=\"bb\"")), GoodRep()));

    [Fact]
    public void NoActiveMeasurements() =>
        Assert.Equal("RIMs carry no active golden measurements", Compare(Rim("GH100", "1.2", Res("0", active: "False")), InactiveVbios, GoodRep()));

    [Fact]
    public void TheReportMustCarryAsManyMeasurementsAsTheRimsList()
    {
        var two = Rim("GH100", "1.2", Res("0"), Res("1", hashes: "Hash0=\"bb\""));
        Assert.Equal("RIMs list more active measurements than the report carries", Compare(two, InactiveVbios, Rep(null, (1, 0xaa))));
        Assert.Equal("", Compare(two, InactiveVbios, GoodRep()));
    }

    [Fact]
    public void AnAbsentBlockIsAMismatch() =>
        Assert.Equal("runtime measurements differ from the golden RIM values at 1 index(es)", Compare(DriverXml, InactiveVbios, Rep(null, (5, 0xaa))));

    [Fact]
    public void AWrongDigestIsAMismatchAndEveryOneIsCounted()
    {
        Assert.Equal("runtime measurements differ from the golden RIM values at 1 index(es)", Compare(DriverXml, InactiveVbios, Rep(null, (1, 0xcc))));
        Assert.Equal("runtime measurements differ from the golden RIM values at 2 index(es)", Compare(DriverXml, VbiosXml, Rep(null, (1, 0xcc), (2, 0xcc))));
    }

    static string NvdecDriver => Rim("GH100", "1.2", Res("34"), Res("0", hashes: "Hash0=\"bb\""));

    static SpdmReport NvdecRep(byte[]? status) => Rep(status == null ? Op() : Op((11, status)), (1, 0xbb), (35, 0x00));

    [Fact]
    public void Block35IsExemptOnlyWhenNvdecByteZeroIsDisabled()
    {
        const string one = "runtime measurements differ from the golden RIM values at 1 index(es)";
        Assert.Equal("", Compare(NvdecDriver, InactiveVbios, NvdecRep(new byte[] { 0x55 })));
        Assert.Equal("", Compare(NvdecDriver, InactiveVbios, NvdecRep(new byte[] { 0x55, 0x01 })));
        Assert.Equal(one, Compare(NvdecDriver, InactiveVbios, NvdecRep(new byte[] { 0xaa })));
        Assert.Equal(one, Compare(NvdecDriver, InactiveVbios, NvdecRep(new byte[] { 0x00, 0x55 })));
        Assert.Equal(one, Compare(NvdecDriver, InactiveVbios, NvdecRep(Array.Empty<byte>())));
        Assert.Equal(one, Compare(NvdecDriver, InactiveVbios, NvdecRep(null)));
    }

    [Fact]
    public void TheNvdecExemptionCoversBlock35Only()
    {
        var other = Rim("GH100", "1.2", Res("36"), Res("0", hashes: "Hash0=\"bb\""));
        Assert.Equal("runtime measurements differ from the golden RIM values at 1 index(es)", Compare(other, InactiveVbios, Rep(Op((11, new byte[] { 0x55 })), (1, 0xbb), (37, 0x00))));
    }

    // ---- revocation

    static readonly byte[] AlgEcdsaSha256 = Convert.FromHexString("300A06082A8648CE3D040302");

    /// <summary>A base64 DER CRL (ecdsa-with-SHA256), valid until the given number of days from now.</summary>
    static string Crl(ECDsa signer, int nextDays, params byte[] revokedSerials)
    {
        var now = DateTimeOffset.UtcNow;
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteEncodedValue(AlgEcdsaSha256);
            using (w.PushSequence()) { w.WriteNull(); } // the issuer name is not read: the signature decides
            w.WriteUtcTime(now.AddDays(-2));
            w.WriteUtcTime(now.AddDays(nextDays));
            if (revokedSerials.Length > 0)
            {
                using (w.PushSequence())
                {
                    foreach (var s in revokedSerials)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteInteger((long)s);
                            w.WriteUtcTime(now.AddDays(-2));
                        }
                    }
                }
            }
        }
        var tbs = w.Encode();
        var o = new AsnWriter(AsnEncodingRules.DER);
        using (o.PushSequence())
        {
            o.WriteEncodedValue(tbs);
            o.WriteEncodedValue(AlgEcdsaSha256);
            o.WriteBitString(signer.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
        return Convert.ToBase64String(o.Encode());
    }

    static string WithCrls(JD? extra, List<AttCert>? chain, params string[] crls)
    {
        var l = new JL();
        foreach (var c in crls) l.Add(c);
        return Run(extra, Bundle(DriverXml, VbiosXml, crls: l), chain: chain);
    }

    [Fact]
    public void ACrlRevokesOnlyWhatItsIssuerIssued()
    {
        Assert.Equal("", WithCrls(null, null, Crl(MidKey, 1)));
        Assert.Equal("revocation: chain certificate 'CN=GH100-leaf' is revoked", WithCrls(null, null, Crl(MidKey, 1, 0x11)));
        Assert.Equal("revocation: chain certificate 'CN=mid' is revoked", WithCrls(null, null, Crl(RootKey, 1, 0x22)));
        Assert.Equal("", WithCrls(null, null, Crl(RootKey, 1, 0x11)));
        // issued by the leaf (index 0): it verifies, and nothing in the chain is below it
        Assert.Equal("", WithCrls(null, null, Crl(LeafKey, 1, 0x11)));
    }

    [Fact]
    public void ARejectedCrlIsNamedByItsPosition()
    {
        Assert.Equal("revocation: CRL #0 rejected: CRL signature does not verify under the issuer", WithCrls(null, null, Crl(Stranger, 1)));
        Assert.Equal("revocation: CRL #1 rejected: CRL signature does not verify under the issuer", WithCrls(null, null, Crl(MidKey, 1), Crl(Stranger, 1)));
    }

    /// <summary>Two chain certificates share a key: the first that verifies the CRL is its issuer, so the leaf is not below it.</summary>
    [Fact]
    public void TheFirstVerifyingCertificateIsTheIssuer()
    {
        var chain = new List<AttCert> { AttestCerts.ParseDer(Cert("CN=GH100-a", MidKey, "b", MidKey, 0x44, false)), AttestCerts.ParseDer(Cert("CN=b", MidKey, "root", RootKey, 0x55, true)), Chain[2] };
        Assert.Equal("", WithCrls(null, chain, Crl(MidKey, 1, 0x44)));
    }

    [Fact]
    public void SuppliedCrlsAreEnforcedEvenWhenNotRequired() =>
        Assert.Equal("revocation: CRL #0 rejected: CRL is stale (nextUpdate passed)", WithCrls(NoCrl, null, Crl(MidKey, -1)));

    [Fact]
    public void SuppliedOcspIsEnforcedEvenWhenNotRequired()
    {
        var want = NvidiaOcsp.CheckChain(Chain, new List<byte[]> { new byte[] { 1, 2, 3 } }, Now);
        Assert.NotEqual("", want);
        Assert.Equal("revocation (OCSP): " + want, Run(NoCrl, Bundle(DriverXml, VbiosXml, ocsp: new JL { "AQID" })));
    }

    [Fact]
    public void RevocationModes()
    {
        var noEvidence = Bundle(DriverXml, VbiosXml);
        const string noOcsp = "revocation (OCSP): no OCSP responses supplied";
        Assert.Equal(NoCrls, Run(null, noEvidence));
        Assert.Equal(NoCrls, Run(new JD { ["requireCrls"] = true }, noEvidence));
        Assert.Equal("", Run(NoCrl, noEvidence));
        // revocation wins over the legacy switch, in both directions
        Assert.Equal(NoCrls, Run(new JD { ["revocation"] = "crl", ["requireCrls"] = false }, noEvidence));
        Assert.Equal(NoCrls, Run(new JD { ["revocation"] = "both", ["requireCrls"] = false }, noEvidence));
        Assert.Equal(noOcsp, Run(new JD { ["revocation"] = "ocsp" }, noEvidence));
        Assert.Equal(noOcsp, Run(new JD { ["revocation"] = "both" }, Bundle(DriverXml, VbiosXml, crls: new JL { Crl(MidKey, 1) })));
    }

    // ---- CRL coverage (requireCrlFor): every non-root certificate that names a CRL distribution point needs a verified CRL from its issuer

    /// <summary>cRLDistributionPoints (2.5.29.31) naming one URI: SEQUENCE { SEQUENCE { [0] { [0] { [6] uri } } } }.</summary>
    static X509Extension CdpExt()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        using (w.PushSequence())
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            w.WriteCharacterString(UniversalTagNumber.IA5String, "http://crl.example/c.crl", new Asn1Tag(TagClass.ContextSpecific, 6, false));
        return new X509Extension(new Oid("2.5.29.31"), w.Encode(), false);
    }

    static byte[] CertCdp(string subject, ECDsa key, string issuerCn, ECDsa signer, byte serial, bool ca, bool cdp)
    {
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA384);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        if (ca) req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        if (cdp) req.CertificateExtensions.Add(CdpExt());
        return req.Create(new X500DistinguishedName("CN=" + issuerCn), X509SignatureGenerator.CreateForECDsa(signer),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new[] { serial }).RawData;
    }

    /// <summary>leaf <- mid <- root, the leaf and (optionally) the intermediate naming a CRL distribution point.</summary>
    static List<AttCert> CdpChain(bool leafCdp = true, bool midCdp = true) => new()
    {
        AttestCerts.ParseDer(CertCdp("CN=GH100-leaf", LeafKey, "mid", MidKey, 0x11, false, leafCdp)),
        AttestCerts.ParseDer(CertCdp("CN=mid", MidKey, "root", RootKey, 0x22, true, midCdp)),
        Chain[2],
    };

    const string NoLeafCrl = "revocation: no verified CRL from the issuer of chain certificate 'CN=GH100-leaf'";
    const string NoMidCrl = "revocation: no verified CRL from the issuer of chain certificate 'CN=mid'";

    [Fact]
    public void ARootCrlAloneDoesNotCoverACertificateThatNamesACrlDistributionPoint()
    {
        // before the fix any one fresh CRL satisfied the check: the leaf was never looked at
        Assert.Equal(NoLeafCrl, WithCrls(null, CdpChain(), Crl(RootKey, 1)));
        Assert.Equal(NoLeafCrl, WithCrls(new JD { ["requireCrlFor"] = "cdp" }, CdpChain(), Crl(RootKey, 1)));
        // the intermediate's issuer is the root: that CRL covers index 1, the leaf's issuer (the intermediate) has none
        Assert.Equal(NoLeafCrl, WithCrls(null, CdpChain(midCdp: false), Crl(RootKey, 1)));
    }

    [Fact]
    public void EachRequiredCertificateIsCoveredByItsOwnIssuer()
    {
        Assert.Equal("", WithCrls(null, CdpChain(), Crl(MidKey, 1), Crl(RootKey, 1)));
        // the leaf is covered by the intermediate's CRL, but the intermediate (CDP too) has no CRL from the root
        Assert.Equal(NoMidCrl, WithCrls(null, CdpChain(), Crl(MidKey, 1)));
        // only the leaf names a CDP: the intermediate's CRL is all it needs
        Assert.Equal("", WithCrls(null, CdpChain(midCdp: false), Crl(MidKey, 1)));
        // a certificate without a CDP demands nothing
        Assert.Equal("", WithCrls(null, CdpChain(false, false), Crl(RootKey, 1)));
    }

    [Fact]
    public void ARevokedCertificateStillFailsAsRevoked()
    {
        Assert.Equal("revocation: chain certificate 'CN=GH100-leaf' is revoked", WithCrls(null, CdpChain(), Crl(MidKey, 1, 0x11), Crl(RootKey, 1)));
        Assert.Equal("revocation: chain certificate 'CN=mid' is revoked", WithCrls(null, CdpChain(), Crl(MidKey, 1), Crl(RootKey, 1, 0x22)));
    }

    /// <summary>Fail closed: a certificate whose DER cannot be re-read (so its extensions cannot be searched) counts as requiring a CRL.</summary>
    [Fact]
    public void ACertificateWhoseExtensionsCannotBeParsedRequiresACrl()
    {
        var chain = CdpChain(false, false);
        Assert.Equal("", WithCrls(null, chain, Crl(RootKey, 1))); // control: no CDP, nothing demanded
        chain = CdpChain(false, false);
        chain[0].Raw = new byte[] { 0x30, 0x03, 0x01, 0x01, 0x00 }; // no CDP OID bytes, and not a certificate
        Assert.Equal(NoLeafCrl, WithCrls(null, chain, Crl(RootKey, 1)));
        chain = CdpChain(false, false);
        chain[0].Raw = new byte[] { 0x30, 0x03, 0x01, 0x01, 0x00 };
        Assert.Equal("", WithCrls(null, chain, Crl(MidKey, 1), Crl(RootKey, 1)));
    }

    /// <summary>The parsed extension list is consulted as well as the byte scan.</summary>
    [Fact]
    public void AParsedCrlDistributionPointExtensionRequiresACrl()
    {
        var chain = CdpChain(false, false);
        chain[0].Exts.Add(new LenientExt("2.5.29.31", false, new byte[] { 0x30, 0x00 }));
        Assert.Equal(NoLeafCrl, WithCrls(null, chain, Crl(RootKey, 1)));
    }

    [Fact]
    public void AllDemandsACrlForEveryNonRootCertificate()
    {
        var all = new JD { ["requireCrlFor"] = "all" };
        // no CDP anywhere, a root CRL only: the leaf has no CRL from its issuer
        Assert.Equal(NoLeafCrl, WithCrls(all, CdpChain(false, false), Crl(RootKey, 1)));
        Assert.Equal("", WithCrls(null, CdpChain(false, false), Crl(RootKey, 1)));
        Assert.Equal("", WithCrls(all, CdpChain(false, false), Crl(MidKey, 1), Crl(RootKey, 1)));
    }

    [Fact]
    public void AnIndexListDemandsExactlyThoseCertificates()
    {
        JD Idx(params string[] n) => new() { ["requireCrlFor"] = new JL(n.Select(x => (object?)new Num(x))) };
        Assert.Equal("", WithCrls(Idx(), CdpChain(), Crl(RootKey, 1)));                        // an empty list demands nothing
        Assert.Equal(NoLeafCrl, WithCrls(Idx("0"), CdpChain(false, false), Crl(RootKey, 1)));
        Assert.Equal(NoMidCrl, WithCrls(Idx("1"), CdpChain(false, false), Crl(MidKey, 1)));
        Assert.Equal("", WithCrls(Idx("1"), CdpChain(false, false), Crl(RootKey, 1)));
        // the root (index 2 of 3) and anything beyond is not a non-root certificate
        Assert.Equal("revocation: requireCrlFor index 2 is not a non-root chain certificate", WithCrls(Idx("2"), CdpChain(), Crl(MidKey, 1), Crl(RootKey, 1)));
        Assert.Equal("revocation: requireCrlFor index 7 is not a non-root chain certificate", WithCrls(Idx("0", "7"), CdpChain(), Crl(MidKey, 1), Crl(RootKey, 1)));
    }

    [Fact]
    public void AMalformedPolicyIsRefusedAtConstruction()
    {
        foreach (var bad in new object?[] { "none", "CDP", true, new Num("1"), new JL { new Num("-1") }, new JL { new Num("1.5") }, new JL { "0" }, new JL { true } })
        {
            var e = Assert.Throws<ArgumentException>(() => Hook(new JD { ["requireCrlFor"] = bad }));
            Assert.StartsWith("nvidiaCollateralHook: malformed requireCrlFor '", e.Message);
        }
        Assert.Equal("nvidiaCollateralHook: malformed requireCrlFor 'none'", Assert.Throws<ArgumentException>(() => Hook(new JD { ["requireCrlFor"] = "none" })).Message);
        Hook(new JD { ["requireCrlFor"] = "all" });
        Hook(new JD { ["requireCrlFor"] = new JL { new Num("0"), new Num("1") } });
    }

    [Fact]
    public void OcspOnlyModeMakesNoCoverageDemand()
    {
        // CRLs supplied but not required: they are enforced (they verify here) and nothing more is demanded
        var ocspOnly = new JD { ["revocation"] = "ocsp" };
        var r = Run(ocspOnly, Bundle(DriverXml, VbiosXml, crls: new JL { Crl(RootKey, 1) }), chain: CdpChain());
        Assert.DoesNotContain("no verified CRL from the issuer", r);
        var legacy = Run(NoCrl, Bundle(DriverXml, VbiosXml, crls: new JL { Crl(RootKey, 1) }), chain: CdpChain());
        Assert.Equal("", legacy);
        // required (crl or both): the demand applies
        Assert.Equal(NoLeafCrl, Run(new JD { ["revocation"] = "both" }, Bundle(DriverXml, VbiosXml, crls: new JL { Crl(RootKey, 1) }), chain: CdpChain()));
    }
}
