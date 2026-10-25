using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.Corpus.Tests.IntentV2KillTests;

namespace AtlasPca.Corpus.Tests;

/// <summary>Round-r9 mutation kills (Stryker.NET survivors that survived the oracles): small, targeted assertions.</summary>
public class R9KillTests
{
    // ---- SafeRegex ---------------------------------------------------------------------------------------------------

    [Fact]
    public void HexEscapeOperandsAcceptOnlyHexDigitsEvenWhenTheNumberParserWould()
    {
        // Convert.ToInt32(s, 16) alone accepts a sign / blanks in some positions; the explicit digit check must refuse them
        foreach (var bad in new[] { "\\x+1", "\\x-1", "\\x 1", "\\x1 ", "\\x\t1", "\\x1+", "\\u+041", "\\u 041", "\\u004 ", "\\u-041", "\\u0x41" })
            Assert.Null(SafeRegex.Compile(bad));
    }

    // ---- IntentJs.Shortest ---------------------------------------------------------------------------------------------

    [Fact]
    public void ShortestExpandsExponentFormsWithoutDroppingOrAddingAPoint()
    {
        Assert.Equal("1234567890123456", IntentJs.Shortest(1234567890123456.0));      // digits == integer length: no point
        Assert.Equal("1234567890123456.5", IntentJs.Shortest(1234567890123456.5));    // point inside the digits
        Assert.Equal("1000000000000000000000", IntentJs.Shortest(1e21));
        Assert.Equal("0.00000025", IntentJs.Shortest(2.5e-7));
        Assert.Equal("-0.00000025", IntentJs.Shortest(-2.5e-7));
        Assert.Equal("0.000001234", IntentJs.Shortest(1.234e-6));
        Assert.Equal("1500000000000000000000", IntentJs.Shortest(1.5e21));
        Assert.Equal("0.5", IntentJs.Shortest(0.5));
    }

    // ---- IntentAcc.DistinctKey -----------------------------------------------------------------------------------------

    [Fact]
    public void DistinctKeyOfANonCanonicalStringIsNullNotAnError()
    {
        Assert.Equal("\"a\"", IntentAcc.DistinctKey("a"));
        Assert.Null(IntentAcc.DistinctKey("\uD800"));   // a lone surrogate has no canonical form: refused, never thrown
        Assert.Null(IntentAcc.DistinctKey(true));
    }

    // ---- IntentClassifier / entry points -------------------------------------------------------------------------------

    [Fact]
    public void ClassifierEntryPointFailsClosedWithTheExceptionType()
    {
        var r = IntentClassifier.Decide("not an object");
        Assert.False(r.Ok);
        Assert.Equal("classes: evaluation error (fail closed): InvalidCastException", r.Reason);
    }

    // ---- IntentSession.VerifyRoot: a fault after the shape check carries its message ------------------------------------

    sealed class NthTouch : IEqualityComparer<string>
    {
        readonly string key; readonly int nth; int n; public bool Armed;
        public NthTouch(string key, int nth) { this.key = key; this.nth = nth; }
        void Touch(string s) { if (Armed && s == key && ++n == nth) throw new InvalidOperationException("boom"); }
        public bool Equals(string? a, string? b) { Touch(a!); return a == b; }
        public int GetHashCode(string s) { Touch(s); return s.GetHashCode(); }
    }

    [Fact]
    public void SessionRootFaultsAfterTheShapeCheckAreReportedWithTheirMessage()
    {
        var seen = new HashSet<string?>();
        for (int nth = 1; nth <= 40; nth++)
        {
            var c = new NthTouch("sig", nth);
            var d = new D(c);
            foreach (var (k, v) in S) d[k] = v;
            c.Armed = true;
            seen.Add(IntentSession.VerifyRoot(d));
        }
        // every touch either lets the root verify or fails closed with the exact message
        Assert.All(seen, r => Assert.True(r == null || r == "malformed session root: boom", r));
        Assert.Contains("malformed session root: boom", seen);
    }

    // ---- LessNative.Candidates ------------------------------------------------------------------------------------------

    [Fact]
    public void CandidatesStopAtTheNearestBuildDirectoryAndSkipMissingOnes()
    {
        var old = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBLESS");
        var baseDir = new DirectoryInfo(AppContext.BaseDirectory);
        var parent = baseDir.Parent!;
        string Build(DirectoryInfo at) => Path.Combine(at.FullName, "sdks", "pca-less-c", "build");
        void Make(DirectoryInfo at) => Directory.CreateDirectory(Build(at));
        void Prune(DirectoryInfo at)
        {
            foreach (var d in new[] { Build(at), Path.Combine(at.FullName, "sdks", "pca-less-c"), Path.Combine(at.FullName, "sdks") })
                try { if (Directory.Exists(d) && !Directory.EnumerateFileSystemEntries(d).Any()) Directory.Delete(d); } catch { }
        }
        string[] Names(DirectoryInfo at) => new[] { "libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll" }.Select(n => Path.Combine(Build(at), n)).ToArray();
        try
        {
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", null);
            Make(parent);   // only an ancestor has a build directory: the (missing) one next to the binaries is skipped
            Assert.Equal(Names(parent), LessNative.Candidates().Take(3).ToArray());
            Make(baseDir);  // now the nearest one wins and the search stops there
            var both = LessNative.Candidates().ToArray();
            Assert.Equal(Names(baseDir), both.Take(3).ToArray());
            Assert.Equal(3, both.Length);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", old);
            Prune(baseDir); Prune(parent);
        }
    }

    // ---- IntentMap.Decide: absent params are {} ------------------------------------------------------------------------

    static string ConfDir()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var c = Path.Combine(d.FullName, "packages", "pca", "conformance");
            if (File.Exists(Path.Combine(c, "vectors.json"))) return c;
        }
        throw new InvalidOperationException("conformance dir not found");
    }
    static D Primitive(string kind, string name) =>
        (D)IntentJs.Normalize(((L)((D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!)[kind]!).Cast<D>()
            .First(e => (string)e["name"]! == name)["input"])!;

    [Fact]
    public void MapDecisionTreatsAbsentParamsAsAnEmptyObject()
    {
        var ok = Primitive("intent_map", "ok");
        var action = new D((D)ok["action"]!); action["params_digest"] = Pca.ParamsDigest(new D());
        var d = IntentMap.Decide(ok["map_commit"], action, false, null, ok["disclosure"], null);
        Assert.False(d.Ok);
        // the empty params hash to the digest; the failure is the missing cell value, not a digest mismatch or a fault
        Assert.Equal("the action's value lies outside the committed map's dimension", d.Reason);
    }

    // ---- IntentPrimitives intent_schema: an absent verb is the empty verb ------------------------------------------------

    [Fact]
    public void SchemaPrimitiveWithoutAVerbNamesNoVerb()
    {
        var entry = Primitive("intent_schema", ((L)((D)((D)Pca.ParseJson(File.ReadAllText(Path.Combine(ConfDir(), "vectors.json")))!)["primitives"]!)["intent_schema"]!).Cast<D>().Select(e => (string)e["name"]!).First());
        var schema = (D)entry["schema"]!;
        var verbs = new L((L)schema["verbs"]!) { new D { ["verb"] = "Stryker was here!", ["kind"] = "read", ["params"] = new D() } };
        var s2 = new D(schema) { ["verbs"] = verbs };
        var input = new D { ["schema"] = s2, ["keys"] = entry["keys"], ["params"] = new D() };
        var r = IntentPrimitives.Result("intent_schema", input)!;
        var conform = (D)r["conform"]!;
        Assert.Equal(false, conform["ok"]);
        Assert.Equal("unknown_verb", conform["code"]);
    }

    // ---- ParamProvenance wire ------------------------------------------------------------------------------------------

    [Fact]
    public void LabelReceiptMustBeAnObject()
    {
        Assert.Equal("label receipt must be an object", ParamProvenance.ValidateLabelsWire("x"));
        Assert.Equal("label receipt must be an object", ParamProvenance.ValidateLabelsWire(null));
    }

    // ---- LessNative.Load: a library only counts when it reports exactly the less-252-45 sizes and exports verify ---------------

    /// <summary>GATED (run once on the box, see tools/pca-audit/native-mutation-equivalents.json: LessNative.cs:53): it needs the
    /// directory of fake libraries built by sdks/dotnet-pca/AtlasPca.Corpus.Tests/test-data/fake-less/build.sh, exported as
    /// ATLAS_PCA_FAKELESS_DIR; without it the test returns immediately (CI has no fake libraries).</summary>
    [Fact]
    public void LoadRefusesALibraryWithOtherSizesOrNoVerifyExport()
    {
        var dir = Environment.GetEnvironmentVariable("ATLAS_PCA_FAKELESS_DIR");
        if (string.IsNullOrEmpty(dir)) return;
        var load = typeof(LessNative).GetMethod("Load", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var old = Environment.GetEnvironmentVariable("ATLAS_PCA_LIBLESS");
        try
        {
            foreach (var (name, loads) in new[] { ("ok", true), ("badpk", false), ("badmin", false), ("badmax", false), ("noverify", false) })
            {
                Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", Path.Combine(dir, "libfake_" + name + ".so"));
                Assert.Equal(loads, load.Invoke(null, null) != null);
            }
        }
        finally { Environment.SetEnvironmentVariable("ATLAS_PCA_LIBLESS", old); }
    }

    // ---- Pq.Verify: exact-length keys and signatures --------------------------------------------------------------------

    static void PqLengthChecks(Pq.Prim prim, byte[] pk, byte[] sig, byte[] msg)
    {
        Assert.True(Pq.Verify(prim, pk, msg, sig));
        foreach (var n in new[] { 0, 1, pk.Length - 1, pk.Length + 1, pk.Length * 2 })
        {
            var bad = new byte[n];
            Array.Copy(pk, bad, Math.Min(n, pk.Length));
            Assert.False(Pq.Verify(prim, bad, msg, sig), $"pk length {n}");
        }
        foreach (var n in new[] { 0, 1, sig.Length - 1, sig.Length + 1, sig.Length * 2 })
        {
            var bad = new byte[n];
            Array.Copy(sig, bad, Math.Min(n, sig.Length));
            Assert.False(Pq.Verify(prim, pk, msg, bad), $"sig length {n}");
        }
    }

    [Fact]
    public void MlDsaVerifyRequiresTheExactKeyAndSignatureLengths()
    {
        var msg = Encoding.UTF8.GetBytes("r9 pq lengths");
        foreach (var (prim, ps) in new[] { (Pq.Prim.MlDsa65, MLDsaParameters.ml_dsa_65), (Pq.Prim.MlDsa87, MLDsaParameters.ml_dsa_87) })
        {
            var g = new MLDsaKeyPairGenerator(); g.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), ps));
            var kp = g.GenerateKeyPair();
            var s = new MLDsaSigner(ps, false); s.Init(true, kp.Private); s.BlockUpdate(msg, 0, msg.Length);
            PqLengthChecks(prim, ((MLDsaPublicKeyParameters)kp.Public).GetEncoded(), s.GenerateSignature(), msg);
        }
    }

    [Fact]
    public void SlhDsaVerifyRequiresTheExactKeyAndSignatureLengths()
    {
        var msg = Encoding.UTF8.GetBytes("r9 pq lengths");
        var ps = SlhDsaParameters.slh_dsa_sha2_128f;
        var g = new SlhDsaKeyPairGenerator(); g.Init(new SlhDsaKeyGenerationParameters(new SecureRandom(), ps));
        var kp = g.GenerateKeyPair();
        var s = new SlhDsaSigner(ps, false); s.Init(true, kp.Private); s.BlockUpdate(msg, 0, msg.Length);
        PqLengthChecks(Pq.Prim.Slh128f, ((SlhDsaPublicKeyParameters)kp.Public).GetEncoded(), s.GenerateSignature(), msg);
    }

    // ---- IntentMap.Opens: a fault while opening a disclosed leaf fails closed (fault injection) -------------------------------

    [Fact]
    public void MapLeafOpeningFaultsFailClosedAsNotOpening()
    {
        var ok = Primitive("intent_map", "ok");
        var reasons = new HashSet<string?>();
        foreach (var entry in new[] { "header", "cell", "metrics" })
            foreach (var key in new[] { "salt", "leaf", "path", "index" })
                for (int nth = 1; nth <= 12; nth++)
                {
                    var dis = (D)IntentJs.Normalize(ok["disclosure"])!;
                    var c = new NthTouch(key, nth);
                    var e = new D(c);
                    foreach (var (k, v) in (D)dis[entry]!) e[k] = v;
                    c.Armed = true;
                    dis[entry] = e;
                    var d = IntentMap.Decide(ok["map_commit"], ok["action"], true, ok["params"], dis, null);
                    reasons.Add(d.Reason);
                    // a fault never lets the leaf count as opened
                    Assert.True(d.Reason == null || !d.Ok);
                    if (!d.Ok) Assert.NotNull(d.Reason);
                }
        Assert.Contains("the header leaf does not open the map commitment", reasons);
        Assert.Contains("the cell leaf does not open the map commitment", reasons);
        Assert.Contains("the metrics leaf does not open the map commitment", reasons);
    }

    // ---- contracts the ledgered equivalences rely on (r10) ----------------------------------------------------------------

    [Fact]
    public void BouncyCastleRejectsWrongLengthPublicKeysAndSignaturesItself()
    {
        // Pq.Verify's early length guard is redundant with these (Pca.cs:101 equivalence): wrong lengths throw or verify false
        var msg = Encoding.UTF8.GetBytes("r10");
        foreach (var ps in new[] { MLDsaParameters.ml_dsa_65, MLDsaParameters.ml_dsa_87 })
        {
            var g = new MLDsaKeyPairGenerator(); g.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), ps));
            var kp = g.GenerateKeyPair();
            var pk = ((MLDsaPublicKeyParameters)kp.Public).GetEncoded();
            var sg = new MLDsaSigner(ps, false); sg.Init(true, kp.Private); sg.BlockUpdate(msg, 0, msg.Length);
            var sig = sg.GenerateSignature();
            foreach (var n in new[] { 0, 1, pk.Length - 1, pk.Length + 1 })
                Assert.ThrowsAny<Exception>(() => MLDsaPublicKeyParameters.FromEncoding(ps, new byte[n]));
            foreach (var n in new[] { 0, 1, sig.Length - 1, sig.Length + 1 })
            {
                var v = new MLDsaSigner(ps, false); v.Init(false, MLDsaPublicKeyParameters.FromEncoding(ps, pk)); v.BlockUpdate(msg, 0, msg.Length);
                bool ok; try { ok = v.VerifySignature(new byte[n]); } catch { ok = false; }
                Assert.False(ok);
            }
        }
        foreach (var ps in new[] { SlhDsaParameters.slh_dsa_sha2_128f, SlhDsaParameters.slh_dsa_sha2_256s })
        {
            var g = new SlhDsaKeyPairGenerator(); g.Init(new SlhDsaKeyGenerationParameters(new SecureRandom(), ps));
            var pk = ((SlhDsaPublicKeyParameters)g.GenerateKeyPair().Public).GetEncoded();
            foreach (var n in new[] { 0, 1, pk.Length - 1, pk.Length + 1 })
                Assert.ThrowsAny<Exception>(() => SlhDsaPublicKeyParameters.FromEncoding(ps, new byte[n]));
        }
    }

    [Fact]
    public void LargeExponentFormsAlwaysHaveMoreIntegerDigitsThanSignificantDigits()
    {
        // IntentJs.Shortest equivalences (196/197): a large double printed with an exponent has intLen = 1 + exp > digits (<= 17)
        int seen = 0;
        for (int e = 10; e <= 308; e++)
            foreach (var m in new[] { 1.0, 1.5, 1.2345678901234567, 9.999999999999998, 5e-324 + 1 })
            {
                var d = m * Math.Pow(10, e);
                if (double.IsInfinity(d)) continue;
                var r = d.ToString("R", System.Globalization.CultureInfo.InvariantCulture);
                if (!r.Contains("E+")) continue;
                seen++;
                var parts = r.Split('E');
                var digits = parts[0].Replace(".", "");
                Assert.True(digits.Length <= 17 && 1 + int.Parse(parts[1]) > digits.Length, r);
            }
        Assert.True(seen > 100);
        Assert.Null(SafeRegex.Compile("[a-"));
    }
}
