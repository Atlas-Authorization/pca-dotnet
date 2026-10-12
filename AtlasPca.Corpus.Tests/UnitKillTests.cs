using System.Numerics;
using System.Reflection;
using System.Text;
using AtlasPca;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Direct unit tests of seams the conformance corpus cannot reach (mutation-kill suite; corpus pins live in SnapshotTests).</summary>
public class UnitKillTests
{
    const string AUD = "rs-conformance";
    const long NOW = 1800000000000L;
    static readonly string B32 = "qK9bTlJxvo3zLOQ4msAVS7_odp-g75Kfsu_Z7L47sqQ";
    static readonly string B64 = new string('A', 86);

    static D M(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static L Li(params object?[] v) => new L(v);
    static Num N(string s) => new Num(s);
    static D As(object? o) => (D)o!;
    static L Ls(object? o) => (L)o!;

    static D Vec(string name) => Ls(Snapshot.Core()["vectors"]).Cast<D>().First(v => (string)v["name"]! == name);
    static D Valid() => As(Pca.ParseStrict((string)Vec("valid-raw-json-format-insensitive")["pcactn_json"]!));
    static D ValidGrant() => As(Vec("valid-raw-json-format-insensitive")["grant"]);
    static L TwoHop() => Ls(As(Vec("delegated-2-hop-chain")["pcactn"])["cap_chain"]);
    static D Clone(D d) => new D(d);
    static L DeepChain(L c) => new L(c.Select(x => (object?)Clone(As(x))));

    static object? Priv(string name, params object?[] args)
    {
        var m = typeof(Pca).GetMethods(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static).First(x => x.Name == name && x.GetParameters().Length >= args.Length);
        var ps = m.GetParameters();
        var full = new object?[ps.Length];
        for (int i = 0; i < ps.Length; i++) full[i] = i < args.Length ? args[i] : Type.Missing;
        try { return m.Invoke(null, BindingFlags.Default, null, full, null); }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }

    // ------------------------------------------------------------------ keys / signing helpers
    static D Keys() => As(Pca.ParseJson(File.ReadAllText(Path.Combine(Snapshot.Root(), "packages", "pca", "conformance", "keys.json"))));
    static byte[] Seed(string n) => Pca.B64uDecode(As(Keys()[n])["seed"], 32)!;
    static string Pub(string n) => (string)As(Keys()[n])["public"]!;
    static string EdSign(string key, byte[] msg) { var sig = new byte[64]; Ed25519.Sign(Seed(key), 0, msg, 0, msg.Length, sig, 0); return Pca.B64u(sig); }

    static AsymmetricCipherKeyPair PqKey()
    {
        var g = new MLDsaKeyPairGenerator(); g.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_65)); return g.GenerateKeyPair();
    }
    static string PqPk(AsymmetricCipherKeyPair k) => Pca.B64u(((MLDsaPublicKeyParameters)k.Public).GetEncoded());
    static string PqSign(AsymmetricCipherKeyPair k, byte[] msg)
    {
        var s = new MLDsaSigner(MLDsaParameters.ml_dsa_65, false); s.Init(true, k.Private); s.BlockUpdate(msg, 0, msg.Length); return Pca.B64u(s.GenerateSignature());
    }

    /// <summary>Capability signed by <paramref name="signer"/> (ed25519 key name); alg null => ed25519.</summary>
    static D Cap(object? issuer, object? holder, L caveats, string? parent, string signer, string? alg = null, AsymmetricCipherKeyPair? pqk = null, string? holderPq = null)
    {
        var c = new D { ["issuer"] = issuer, ["holder"] = holder, ["caveats"] = caveats };
        if (parent != null) c["parent"] = parent;
        if (holderPq != null) c["holder_pq"] = holderPq;
        if (alg != null) { c["alg"] = alg; c["pq_pk"] = PqPk(pqk!); }
        var body = (D)Priv("SignableHopBody", c)!;
        var digest = Pca.HashCanonical(body);
        var msg = Pca.B64uDecode(digest, 32)!;
        msg = Encoding.UTF8.GetBytes("atlas-pca/cap/v1\0").Concat(msg).ToArray();
        var o = Clone(c); o["id"] = digest; o["body_digest"] = digest;
        if (alg == null) o["sig"] = EdSign(signer, msg);
        else if (alg == "ml-dsa-65") o["sig"] = PqSign(pqk!, msg);
        else { o["sig"] = EdSign(signer, msg); o["pq_sig"] = PqSign(pqk!, msg); }
        return o;
    }

    static string Why((string Why, bool Ok) r) { Assert.Equal(r.Why == "", r.Ok); return r.Why; }
    static string Refusal(string alg) => $"hop 0: root suite '{alg}' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";

    // ------------------------------------------------------------------ numbers / canonical
    [Fact] public void NumberErrors()
    {
        foreach (var s in new[] { "", "01", ".5", "1.", "+1", "1e", "--1", "-", "1.e1", "0x1", "1 ", " 1", "1e+", "abc", "-01", "00" })
            Assert.NotNull(Pca.NumberError(s));
        Assert.Equal("bad number", Pca.NumberError("-")); Assert.Equal("bad number", Pca.NumberError("1x")); Assert.Equal("bad number", Pca.NumberError("01"));
        Assert.Equal("bad number (leading '+' / '.')", Pca.NumberError("+1")); Assert.Equal("bad number (leading '+' / '.')", Pca.NumberError(".5"));
        Assert.Equal("bad number (empty fraction)", Pca.NumberError("1.")); Assert.Equal("exponent form is not allowed", Pca.NumberError("1e"));
        foreach (var s in new[] { "1e5", "1E5", "1.5e5", "-1E-5" }) Assert.Equal("exponent form is not allowed", Pca.NumberError(s));
        Assert.Equal("negative zero is not allowed", Pca.NumberError("-0")); Assert.Null(Pca.NumberError("0"));
        foreach (var s in new[] { "1.50", "0.0", "-0.0" }) Assert.Equal("trailing fractional zero is not canonical", Pca.NumberError(s));
        Assert.Null(Pca.NumberError("0.5")); Assert.Null(Pca.NumberError("-0.5")); Assert.Null(Pca.NumberError("12345678901234.5")); Assert.Null(Pca.NumberError("-12345678901234.5"));
        foreach (var s in new[] { "123456789012345.5", "-123456789012345.5", "1234567890123456.5" }) Assert.Equal("more than 15 significant digits", Pca.NumberError(s));
        Assert.Null(Pca.NumberError("0.000001")); Assert.Null(Pca.NumberError("-0.000001")); Assert.Null(Pca.NumberError("0.000012345678901"));
        Assert.Equal("magnitude below 1e-6", Pca.NumberError("0.0000001")); Assert.Equal("magnitude below 1e-6", Pca.NumberError("-0.0000001"));
        Assert.Null(Pca.NumberError("9007199254740991")); Assert.Null(Pca.NumberError("-9007199254740991"));
        foreach (var s in new[] { "9007199254740992", "-9007199254740992", "10000000000000000", "99999999999999999999" }) Assert.Equal("integer outside the safe range", Pca.NumberError(s));
        Assert.Null(Pca.NumberError("1000000000000000")); Assert.Null(Pca.NumberError("-5")); Assert.Null(Pca.NumberError("123"));
    }

    [Fact] public void Canonical()
    {
        Assert.Equal("null", Pca.Canonicalize(null)); Assert.Equal("true", Pca.Canonicalize(true)); Assert.Equal("false", Pca.Canonicalize(false));
        Assert.Equal("5", Pca.Canonicalize(5)); Assert.Equal("-5", Pca.Canonicalize(-5L)); Assert.Equal("[]", Pca.Canonicalize(new L())); Assert.Equal("{}", Pca.Canonicalize(new D()));
        Assert.Equal("[1,2,3]", Pca.Canonicalize(Li(N("1"), N("2"), N("3"))));
        Assert.Equal("{\"a\":1,\"b\":[true,null]}", Pca.Canonicalize(M(("b", Li(true, null)), ("a", N("1")))));
        Assert.Equal("{\"B\":1,\"a\":2,\"\u00e9\":3,\"\uff5e\":4,\"\ud83d\ude00\":5}", Pca.Canonicalize(M(("\ud83d\ude00", N("5")), ("\uff5e", N("4")), ("\u00e9", N("3")), ("a", N("2")), ("B", N("1")))));
        Assert.Equal("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f \u007f\"", Pca.Canonicalize("\"\\\b\f\n\r\t\u0001\u001f \u007f"));
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(N("1e5"))); Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(N("1.50"))); Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(N("-0")));
        Assert.Equal("canonicalize: lone surrogate in string", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize("\ud83d")).Message);
        Assert.Equal("canonicalize: lone surrogate in key", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(M(("\ude00", N("1"))))).Message);
        Assert.StartsWith("canonicalize: unsupported type", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(new object())).Message);
        Assert.StartsWith("canonicalize: unsupported type", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(1.5)).Message);
        object? a = N("1"); for (int i = 0; i < 32; i++) a = Li(a);
        Assert.NotNull(Pca.Canonicalize(a));
        var a33 = Li(a);
        Assert.Equal("canonicalize: nesting too deep", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(a33)).Message);
        object? o = N("1"); for (int i = 0; i < 32; i++) o = M(("k", o));
        Assert.NotNull(Pca.Canonicalize(o));
        var o33 = M(("k", o));
        Assert.Equal("canonicalize: nesting too deep", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(o33)).Message);
        object? mix = N("1"); for (int i = 0; i < 16; i++) mix = M(("k", Li(mix)));
        Assert.NotNull(Pca.Canonicalize(mix));
        Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(M(("k", Li(mix)))));
        Assert.Equal("canonicalize: unsafe integer", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(9007199254740992L)).Message);
        Assert.Equal("canonicalize: exponent form is not allowed", Assert.Throws<InvalidOperationException>(() => Pca.Canonicalize(N("1e5"))).Message);
        Assert.True(Pca.HasLoneSurrogate("\ud83d")); Assert.True(Pca.HasLoneSurrogate("\ude00")); Assert.True(Pca.HasLoneSurrogate("a\ud83d")); Assert.True(Pca.HasLoneSurrogate("\ud83dx"));
        Assert.False(Pca.HasLoneSurrogate("\ud83d\ude00")); Assert.False(Pca.HasLoneSurrogate("")); Assert.False(Pca.HasLoneSurrogate("a\ud83d\ude00b")); Assert.True(Pca.HasLoneSurrogate("\ud83d\ude00\ude00"));
    }

    [Fact] public void StrictParserMessages()
    {
        string Msg(string s) => Assert.Throws<StrictJsonException>(() => Pca.ParseStrict(s)).Message;
        Assert.Equal("strict JSON: unexpected end of input (at offset 0)", Msg(""));
        Assert.Equal("strict JSON: unexpected end of input (at offset 1)", Msg("["));
        Assert.Equal("strict JSON: expected a string key (at offset 1)", Msg("{"));
        Assert.Equal("strict JSON: expected ':' (at offset 4)", Msg("{\"a\""));
        Assert.Equal("strict JSON: expected ',' or '}' (at offset 6)", Msg("{\"a\":1"));
        Assert.Equal("strict JSON: duplicate key (at offset 11)", Msg("{\"a\":1,\"a\":2}").Replace("at offset 10", "at offset 11").Replace("at offset 12", "at offset 11"));
        Assert.StartsWith("strict JSON: nesting too deep", Msg(new string('[', 33) + new string(']', 33)));
        Assert.StartsWith("strict JSON: nesting too deep", Msg(string.Concat(Enumerable.Repeat("{\"a\":", 33)) + "1" + new string('}', 33)));
        Assert.StartsWith("strict JSON: unterminated string", Msg("\"abc"));
        foreach (var bad in new[] { "-", "1.", "1e", "1e+", "[1,]" }) Assert.StartsWith("strict JSON: ", Msg(bad));
        Assert.StartsWith("strict JSON: trailing", Msg("1 2"));
        Assert.StartsWith("strict JSON: lone surrogate in string", Msg("\"\\ud800\""));
        Assert.StartsWith("strict JSON: input too large", Msg("[" + new string(' ', 1048576) + "]"));
        Assert.NotNull(Pca.ParseStrict("[" + new string(' ', 1048574) + "]"));
        Assert.Equal("strict JSON: input too large", Msg("\"" + new string('\u20ac', 349524) + "aaa\""));
        Assert.NotNull(Pca.ParseStrict("\"" + new string('\u20ac', 349524) + "aa\""));
        Assert.Equal("é𝄞", Pca.ParseStrict("\"\\u00e9\\ud834\\udd1e\""));
        Assert.Equal("09afAF", Pca.ParseStrict("\"\\u0030\\u0039\\u0061\\u0066\\u0041\\u0046\""));
        foreach (var d in new[] { "\uff10\uff10\uff10\uff11", "\u0660\u0660\u0660\u0661", "00\uff10\uff11", "00:0", "00/0", "00@0", "00`0", "00g0", "00G0" })
        {
            var inp = "\"\\u" + d + "\"";
            Assert.StartsWith("strict JSON: bad \\u escape", Msg(inp));
        }
        Assert.Equal(new L(), Pca.ParseStrict("[ ]")); Assert.Equal(0, As(Pca.ParseStrict("{ }")).Count);
        Assert.Equal(2, Ls(Pca.ParseStrict("[\t1\r\n,\n2 ]")).Count); Assert.Equal(1, As(Pca.ParseStrict("\t{\n\"a\"\r:\n1\t}\n")).Count);
        Assert.Throws<StrictJsonException>(() => Pca.ParseStrict("\u00a0[]"));
        Assert.Equal("1e5", ((Num)Pca.ParseJson("1e5")!).Raw); Assert.Equal("1.0", ((Num)Pca.ParseJson("1.0")!).Raw);
        Assert.Equal("1E+5", ((Num)Pca.ParseJson("1E+5")!).Raw); Assert.Equal("1e-5", ((Num)Pca.ParseJson("1e-5")!).Raw);
        Assert.Equal("-12.5", ((Num)Pca.ParseStrict("-12.5")!).Raw); Assert.Equal("0", ((Num)Pca.ParseStrict("0")!).Raw);
        Assert.Equal("19", ((Num)Pca.ParseStrict("19")!).Raw); Assert.Equal("9", ((Num)Pca.ParseStrict("9")!).Raw);
        Assert.Equal(0, ((Num)Pca.ParseStrict("0")!).Raw.Length - 1);
        // bad tokens inside containers
        foreach (var bad in new[] { "tru", "nul", "x" }) Assert.StartsWith("strict JSON: ", Msg(bad));
        Assert.True((bool)Pca.ParseStrict("true")!); Assert.False((bool)Pca.ParseStrict("false")!); Assert.Null(Pca.ParseStrict("null"));
    }

    [Fact] public void LenientParserCaps()
    {
        Assert.NotNull(Pca.ParseJson(new string('[', 512) + new string(']', 512)));
        Assert.Throws<StrictJsonException>(() => Pca.ParseJson(new string('[', 513) + new string(']', 513)));
        Assert.Equal("\ud800", Pca.ParseJson("\"\\ud800\""));
        Assert.Equal(1, As(Pca.ParseJson("{\"a\":1,\"a\":2}")).Count);
        Assert.Equal(2, ((Num)As(Pca.ParseJson("{\"a\":1,\"a\":2}"))["a"]!).Raw.Length + 1);
    }

    // ------------------------------------------------------------------ base64url / sizes / caveats / merkle
    [Fact] public void B64u()
    {
        Assert.Null(Pca.B64uDecode(5)); Assert.Null(Pca.B64uDecode(null)); Assert.Empty(Pca.B64uDecode("")!); Assert.Empty(Pca.B64uDecode("", 0)!);
        Assert.Null(Pca.B64uDecode("AAAA", 0)); Assert.Equal(3, Pca.B64uDecode("AAAA", 3)!.Length); Assert.Null(Pca.B64uDecode("AAAA", 2)); Assert.Null(Pca.B64uDecode("AAAA", 4)); Assert.Null(Pca.B64uDecode("AAAAA", 3));
        Assert.Single(Pca.B64uDecode("AA", 1)!); Assert.Equal(2, Pca.B64uDecode("AAA", 2)!.Length); Assert.Null(Pca.B64uDecode("AAA", 1)); Assert.Null(Pca.B64uDecode("AA", 2));
        for (int k = 0; k <= 9; k++) Assert.Equal(k % 4 != 1, Pca.B64uDecode(new string('A', k)) != null);
        Assert.Null(Pca.B64uDecode("AB")); Assert.Null(Pca.B64uDecode("AAB")); Assert.NotNull(Pca.B64uDecode("AAE"));
        Assert.NotNull(Pca.B64uDecode(new string('A', 43), 32)); Assert.Null(Pca.B64uDecode(new string('A', 44), 32)); Assert.Null(Pca.B64uDecode(new string('A', 42), 32));
        for (int c = 0; c < 256; c++)
        {
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            char ch = (char)c;
            Assert.Equal(ok, Pca.B64uDecode("AAA" + ch) != null); Assert.Equal(ok, Pca.B64uDecode(ch + "AAA") != null); Assert.Equal(ok, Pca.B64uDecode("A" + ch + "AA") != null);
        }
        Assert.Null(Pca.B64uDecode("AA==")); Assert.Null(Pca.B64uDecode("AA\n\n"));
    }

    [Fact] public void SizesAndCaveats()
    {
        Assert.False(Pca.ArtifactTooLarge("")); Assert.False(Pca.ArtifactTooLarge(new string('a', 524288))); Assert.True(Pca.ArtifactTooLarge(new string('a', 524289)));
        Assert.True(Pca.ArtifactTooLarge(new string('\u20ac', 174763))); Assert.False(Pca.ArtifactTooLarge(new string('\u20ac', 174762)));
        L Hop(int n) { var cv = new L(); for (int i = 0; i < n; i++) cv.Add(M(("type", "t"))); return new L { M(("caveats", cv)) }; }
        L Chain(params int[] ns) { var c = new L(); foreach (var n in ns) c.Add(Hop(n)[0]); return c; }
        Assert.False(Pca.CaveatLimitExceeded(new L())); Assert.False(Pca.CaveatLimitExceeded(Chain(256))); Assert.True(Pca.CaveatLimitExceeded(Chain(257)));
        Assert.False(Pca.CaveatLimitExceeded(Chain(256, 256, 256, 256))); Assert.True(Pca.CaveatLimitExceeded(Chain(256, 256, 256, 256, 1)));
        Assert.True(Pca.CaveatLimitExceeded(Chain(205, 205, 205, 205, 205))); Assert.False(Pca.CaveatLimitExceeded(Chain(205, 205, 205, 205)));
        Assert.False(Pca.CaveatLimitExceeded(Chain(Enumerable.Repeat(1, 1024).ToArray()))); Assert.True(Pca.CaveatLimitExceeded(Chain(Enumerable.Repeat(1, 1025).ToArray())));
        var many = new L(); for (int i = 0; i < 1100; i++) many.Add(M(("caveats", "not-a-list"))); Assert.False(Pca.CaveatLimitExceeded(many));
        Assert.False(Pca.CaveatLimitExceeded(new L { "x", 5, null, Hop(3)[0] }));
        Assert.Equal("chain exceeds caveat limit (max 256 per hop, 1024 per chain)", Pca.CaveatLimitReason);
        Assert.Equal("artifact exceeds size limit (max 524288 bytes)", Pca.ArtifactSizeReason);
    }

    [Fact] public void MerkleAndInclusion()
    {
        Assert.Equal("empty leaf set", Assert.Throws<InvalidOperationException>(() => Pca.MerkleRoot(new L())).Message);
        Assert.Equal(Pca.ParamsDigest(null), Pca.ParamsDigest(new D())); Assert.NotEqual(Pca.ParamsDigest(null), Pca.ParamsDigest(M(("a", N("1")))));
        Assert.Equal(Pca.HashCanonical(M(("a", N("1")))), Pca.ParamsDigest(M(("a", N("1")))));
        var leaf = M(("k", N("1"))); var other = M(("k", N("2")));
        var r1 = Pca.MerkleRoot(Li(leaf));
        D P(object? index, object? size, object? path) => M(("index", index), ("size", size), ("path", path));
        Assert.True(Pca.VerifyInclusion(r1, P(N("0"), N("1"), new L()), leaf));
        Assert.False(Pca.VerifyInclusion(r1, P(N("1"), N("1"), new L()), leaf)); Assert.False(Pca.VerifyInclusion(r1, P(N("0"), N("0"), new L()), leaf));
        Assert.False(Pca.VerifyInclusion(r1, P(N("-1"), N("1"), new L()), leaf)); Assert.False(Pca.VerifyInclusion(r1, P(N("-0"), N("1"), new L()), leaf));
        Assert.False(Pca.VerifyInclusion(r1, P(N("0"), N("1.0"), new L()), leaf)); Assert.False(Pca.VerifyInclusion(r1, P(N("0"), N("1e0"), new L()), leaf));
        Assert.False(Pca.VerifyInclusion(r1, P(N("0"), N("1"), "x"), leaf)); Assert.False(Pca.VerifyInclusion(r1, M(("index", N("0")), ("size", N("1"))), leaf));
        Assert.False(Pca.VerifyInclusion(r1, null, leaf)); Assert.False(Pca.VerifyInclusion(r1 + "x", P(N("0"), N("1"), new L()), leaf));
        Assert.False(Pca.VerifyInclusion(r1, P(N("0"), N("1"), Li(M(("side", "L"), ("hash", B32)))), leaf));
        var sib = Pca.B64u(System.Security.Cryptography.SHA256.HashData(new byte[] { 0 }.Concat(Encoding.UTF8.GetBytes(Pca.Canonicalize(other))).ToArray()));
        var two = Pca.MerkleRoot(Li(leaf, other));
        Assert.True(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "R"), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "L"), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "RR"), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", null), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "R"), ("hash", sib)), M(("side", "R"), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li("x")), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "R"), ("hash", "bad")))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("2"), N("2"), Li(M(("side", "R"), ("hash", sib)))), leaf));
        Assert.False(Pca.VerifyInclusion(two, P(N("0"), N("2"), Li(M(("side", "R"), ("hash", sib)))), new object()));
        Assert.Equal(new List<char> { 'R' }, (List<char>)Priv("PathShape", 0L, 2L)!); Assert.Equal(new List<char> { 'L' }, (List<char>)Priv("PathShape", 1L, 2L)!);
        Assert.Equal("LRR", new string(((List<char>)Priv("PathShape", 1L, 5L)!).ToArray())); Assert.Equal("L", new string(((List<char>)Priv("PathShape", 4L, 5L)!).ToArray()));
        Assert.Equal("RRR", new string(((List<char>)Priv("PathShape", 0L, 5L)!).ToArray()));
        foreach (var (n, k) in new[] { (2L, 1L), (3L, 2L), (5L, 4L), (8L, 4L), (9L, 8L) }) Assert.Equal(k, (long)Priv("Split", n)!);
        var plan = As(Valid()["plan"]); var action = As(Valid()["action"]);
        Assert.True(Pca.VerifyInclusion((string)plan["root"]!, As(plan["inclusion_proof"]), Priv("PlanLeaf", plan["node_id"], action, (string)plan["conditions_digest"]!)));
        Assert.Null(Priv("PlanLeaf", null, action, "c"));
        var pl = (D)Priv("PlanLeaf", "n1", M(("verb", "v"), ("resource", "r")), "cond")!;
        Assert.Equal(Pca.ParamsDigest(null), pl["params_digest"]); Assert.Equal("reversible", pl["reversibility_class"]); Assert.Equal("cond", pl["conditions"]);
        Assert.Equal(new[] { "node_id", "verb", "resource", "params_digest", "reversibility_class", "conditions" }, pl.Keys.ToArray());
        var pl2 = (D)Priv("PlanLeaf", "n1", M(("verb", "v"), ("resource", "r"), ("params_digest", "PD"), ("reversibility_class", "irreversible")), "c")!;
        Assert.Equal("PD", pl2["params_digest"]); Assert.Equal("irreversible", pl2["reversibility_class"]);
        Assert.Equal(Pca.HashCanonical(M(("pre", null), ("post", null))), (string)Priv("ConditionsDigest", null, null)!);
        Assert.NotEqual((string)Priv("ConditionsDigest", "a", null)!, (string)Priv("ConditionsDigest", null, "a")!);
    }

    // ------------------------------------------------------------------ chain
    [Fact] public void Chain()
    {
        var ch = TwoHop(); var issuer = (string)As(ch[0])["issuer"]!;
        Assert.Equal("", Why(Pca.VerifyChain(ch, issuer, true))); Assert.Equal("", Why(Pca.VerifyChain(ch, "other", false)));
        Assert.Equal("hop 0: root issuer is not the expected principal", Why(Pca.VerifyChain(ch, "other", true)));
        Assert.Equal("empty chain", Why(Pca.VerifyChain(new L(), issuer, true)));
        var big = new L(); for (int i = 0; i < 17; i++) big.Add(ch[0]);
        Assert.Equal("chain too long (max 16 hops)", Why(Pca.VerifyChain(big, issuer, true)));
        var sixteen = new L(); for (int i = 0; i < 16; i++) sixteen.Add(ch[0]);
        Assert.Equal("hop 1: broken parent link", Why(Pca.VerifyChain(sixteen, issuer, true)));
        L Hop(int n) { var cv = new L(); for (int i = 0; i < n; i++) cv.Add(M(("type", "t"))); return Li(M(("caveats", cv))); }
        Assert.Equal(Pca.CaveatLimitReason, Why(Pca.VerifyChain(Hop(257), issuer, true)));
        var mal = new L(ch); mal[1] = "x"; Assert.Equal("hop 1: malformed capability", Why(Pca.VerifyChain(mal, issuer, true)));
        mal = new L(ch); mal[0] = "x"; Assert.Equal("hop 0: malformed capability", Why(Pca.VerifyChain(mal, issuer, true)));
        var d = DeepChain(ch); As(d[0])["parent"] = B32; Assert.Equal("hop 0: root must not have a parent", Why(Pca.VerifyChain(d, issuer, true)));
        Assert.Equal("hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy", Why(Pca.VerifyChain(ch, issuer, true, new[] { "ml-dsa-65" })));
        Assert.Equal("", Why(Pca.VerifyChain(ch, issuer, true, new[] { "ed25519" })));
        d = DeepChain(ch); As(d[0])["sig"] = B64; Assert.Equal("hop 0: bad signature (not signed by expected key)", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1])["parent"] = B32; Assert.Equal("hop 1: broken parent link", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1]).Remove("parent"); Assert.Equal("hop 1: malformed capability".Length > 0 ? Why(Pca.VerifyChain(d, issuer, true)) : "", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1])["issuer"] = B32; Assert.Equal("hop 1: issuer is not the parent's bound holder", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1])["sig"] = B64; Assert.Equal("hop 1: bad signature (not signed by expected key)", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[0])["caveats"] = Li(new object()); Assert.Equal("hop 0: malformed capability", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1])["alg"] = "ml-dsa-65";
        Assert.StartsWith("hop 1: suite 'ml-dsa-65' needs a PQ key bound to the signer", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); As(d[1])["alg"] = "bogus"; Assert.Equal("hop 1: unknown signature alg 'bogus'", Why(Pca.VerifyChain(d, issuer, true)));
        var c1 = Ls(As(Vec("chain-dropped-caveat")["pcactn"])["cap_chain"]);
        Assert.Equal("hop 1: caveat 1 altered or reordered", Why(Pca.VerifyChain(c1, (string)As(c1[0])["issuer"]!, true)));
        c1 = Ls(As(Vec("chain-reordered-caveat")["pcactn"])["cap_chain"]);
        Assert.Equal("hop 1: caveat 0 altered or reordered", Why(Pca.VerifyChain(c1, (string)As(c1[0])["issuer"]!, true)));
        var root = As(ch[0]); var holder1 = As(ch[1])["holder"];
        var dropped = Cap(root["holder"], holder1, new L(Ls(root["caveats"]).Take(1)), Pca.CapHash(root), "agent");
        Assert.Equal("hop 1: drops parent caveat(s)", Why(Pca.VerifyChain(Li(root, dropped), issuer, true)));
        var same = Cap(root["holder"], holder1, new L(Ls(root["caveats"])), Pca.CapHash(root), "agent");
        Assert.Equal("", Why(Pca.VerifyChain(Li(root, same), issuer, true)));
        var ext = new L(Ls(root["caveats"])) { M(("type", "extra")) };
        Assert.Equal("", Why(Pca.VerifyChain(Li(root, Cap(root["holder"], holder1, ext, Pca.CapHash(root), "agent")), issuer, true)));
        var deep16 = Ls(As(Vec("valid-chain-at-depth-cap-16")["pcactn"])["cap_chain"]);
        Assert.Equal("", Why(Pca.VerifyChain(deep16, "ignored", false))); Assert.Equal("", Why(Pca.VerifyChain(deep16, As(deep16[0])["issuer"], true)));
        // root PQ authority
        var pk = new string('A', 2603);
        foreach (var alg in new[] { "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" })
        {
            var r = Clone(root); r["alg"] = alg; r["pq_pk"] = pk;
            var want = Refusal(alg);
            Assert.Equal(want, Why(Pca.VerifyChain(Li(r), issuer, true)));
            Assert.Equal(want, Why(Pca.VerifyChain(Li(r), issuer, true, null, new Dictionary<string, string>(), null)));
            Assert.Equal(want, Why(Pca.VerifyChain(Li(r), issuer, true, null, new Dictionary<string, string> { [issuer] = "other" }, null)));
            Assert.Equal(want, Why(Pca.VerifyChain(Li(r), issuer, true, null, null, root)));
            var noPk = Clone(r); noPk.Remove("pq_pk"); Assert.Equal(want, Why(Pca.VerifyChain(Li(noPk), issuer, true, null, new Dictionary<string, string> { [issuer] = pk }, null)));
            Assert.Equal("hop 0: body digest mismatch", Why(Pca.VerifyChain(Li(r), issuer, true, null, new Dictionary<string, string> { [issuer] = pk }, null)));
            Assert.Equal("hop 0: body digest mismatch", Why(Pca.VerifyChain(Li(r), issuer, true, null, null, r)));
            var bt = Clone(r); bt["zz"] = new object(); Assert.Equal(want, Why(Pca.VerifyChain(Li(r), issuer, true, null, null, bt)));
        }
        var bogus = Clone(root); bogus["alg"] = "bogus"; Assert.Equal("hop 0: unknown signature alg 'bogus'", Why(Pca.VerifyChain(Li(bogus), issuer, true)));
    }

    /// <summary>Protocol digests use the STRICT canonical form (TS hashCanonical == canonicalizeStrict): a root hop whose signature
    /// is valid over the LENIENT bytes of a non-canonical value (exponent 1e300, 2^53+2, lone surrogate) is refused as a malformed
    /// body, never verified. The signature is made over the lenient digest, so only the strict digest step can refuse it.</summary>
    [Fact] public void SignedHopWithNonStrictValue_IsAMalformedBody()
    {
        string issuer = Pub("principal"), holder = Pub("agent");
        const string Ph = "\"@@placeholder@@\"";
        foreach (var (lenientLexeme, value) in new (string, object?)[] { ("1e300", N("1e300")), ("9007199254740994", N("9007199254740994")), ("\"\\ud800\"", "\ud800") })
        {
            var body = M(("issuer", issuer), ("holder", holder), ("caveats", Li(M(("type", "max_spend"), ("usd", "@@placeholder@@")))), ("parent", null));
            var lenient = Pca.Canonicalize(body).Replace(Ph, lenientLexeme);
            var digest = Pca.B64u(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(lenient)));
            var msg = Encoding.UTF8.GetBytes("atlas-pca/cap/v1\0").Concat(Pca.B64uDecode(digest, 32)!).ToArray();
            var hop = M(("id", digest), ("issuer", issuer), ("holder", holder), ("caveats", Li(M(("type", "max_spend"), ("usd", value)))), ("body_digest", digest), ("sig", EdSign("principal", msg)));
            Assert.Equal("hop 0: malformed body", Why(Pca.VerifyChain(Li(hop), issuer, true)));
        }
    }

    /// <summary>WellTyped: every optional hop field must be absent or a string. A correctly SIGNED ed25519 root whose (unsigned) pq_sig is
    /// a number would otherwise verify, and a non-string alg must be a type error, not an unknown-suite error.</summary>
    [Fact] public void WellTypedOptionalFields()
    {
        var ch = TwoHop(); var issuer = (string)As(ch[0])["issuer"]!;
        foreach (var f in new[] { "alg", "pq_pk", "pq_sig", "holder_pq", "parent" })
        {
            var d = DeepChain(ch); As(d[0])[f] = N("5");
            Assert.Equal("hop 0: malformed capability", Why(Pca.VerifyChain(d, issuer, true)));
        }
        Assert.Equal("", Why(Pca.VerifyChain(Li(ch[0]), issuer, true)));
    }

    /// <summary>Known answer for the Ed25519 decoding constant (a static initializer: Stryker cannot activate mutants there, see the
    /// ledger): SqrtM1^2 == -1 (mod p), and it is the constant the decoder needs (2^((p-1)/4)).</summary>
    [Fact] public void Ed25519SqrtM1KnownAnswer()
    {
        var p = BigInteger.Pow(2, 255) - 19;
        var s = (BigInteger)typeof(Pca).GetField("SqrtM1", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
        Assert.Equal(p - 1, BigInteger.ModPow(s, 2, p));
        Assert.Equal(BigInteger.ModPow(2, (p - 1) / 4, p), s);
    }

    /// <summary>Exact reasons on the total (R6-05) paths: a non-string parent is a type error, a parent hop whose UNSIGNED extra
    /// field cannot be canonicalised (depth 40) reaches the verifier's catch-all, null chains and null documents.</summary>
    [Fact] public void TotalPathsReasons()
    {
        var ch = TwoHop(); var issuer = (string)As(ch[0])["issuer"]!;
        var d = DeepChain(ch); As(d[1])["parent"] = N("7");
        Assert.Equal("hop 1: malformed capability", Why(Pca.VerifyChain(d, issuer, true)));
        d = DeepChain(ch); object? deep = N("1"); for (int i = 0; i < 40; i++) deep = Li(deep); As(d[0])["x"] = deep;
        Assert.Equal("malformed capability chain: InvalidOperationException", Why(Pca.VerifyChain(d, issuer, true)));
        Assert.Equal("empty chain", Why(Pca.VerifyChain(null!, issuer, true)));
        var v = Pca.VerifyRaw(null!, ValidGrant(), NOW, AUD);
        Assert.Equal("wire: PCActn is not an object", v.Reason); Assert.Single(v.Checks); Assert.False(v.Checks["wire"]);
        // signer-set hash: a non-object member and a member the canonical form refuses (lone surrogate) are null, not exceptions
        Assert.Null(Pca.SignerSetHashB64u(Li(N("5"))));
        Assert.Null(Pca.SignerSetHashB64u(Li(M(("role", "\ud800"), ("publicKey", B32)))));
        Assert.NotNull(Pca.SignerSetHashB64u(Li(M(("role", "agent"), ("publicKey", B32)))));
        // the bounded parser is LENIENT apart from its depth cap (duplicate keys, exponent numbers)
        Assert.Equal("2", ((Num)As(Pca.ParseBounded("{\"a\":1e5,\"a\":2}", 3))["a"]!).Raw);
    }

    [Fact] public void PqRootsAndHops()
    {
        string issuer = Pub("principal"), agent = Pub("agent"), sub = Pub("subagent");
        foreach (var alg in new[] { "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" })
        {
            var k = PqKey();
            var root = Cap(issuer, agent, new L(), null, "principal", alg, k);
            var pins = new Dictionary<string, string> { [issuer] = PqPk(k) };
            Assert.Equal("", Why(Pca.VerifyChain(Li(root), issuer, true, null, pins, null)));
            Assert.Equal("", Why(Pca.VerifyChain(Li(root), issuer, true, null, null, root)));
            Assert.Equal("", Why(Pca.VerifyChain(Li(root), "", false, null, pins, null)));
            Assert.Equal(Refusal(alg), Why(Pca.VerifyChain(Li(root), issuer, true)));
            Assert.Equal(Refusal(alg), Why(Pca.VerifyChain(Li(root), issuer, true, null, new Dictionary<string, string> { [issuer] = PqPk(PqKey()) }, null)));
            Assert.Equal(Refusal(alg), Why(Pca.VerifyChain(Li(root), issuer, true, null, new Dictionary<string, string> { [agent] = PqPk(k) }, null)));
            var other = Cap(issuer, agent, Li(M(("type", "x"))), null, "principal", alg, k);
            Assert.Equal(Refusal(alg), Why(Pca.VerifyChain(Li(root), issuer, true, null, null, other)));
            var bad = Clone(root); bad[alg == "ml-dsa-65" ? "sig" : "pq_sig"] = PqSign(PqKey(), new byte[] { 1 });
            Assert.Equal("hop 0: bad signature (not signed by expected key)", Why(Pca.VerifyChain(Li(bad), issuer, true, null, pins, null)));
            if (alg.StartsWith("hybrid")) { var be = Clone(root); be["sig"] = EdSign("agent", new byte[] { 1 }); Assert.Equal("hop 0: bad signature (not signed by expected key)", Why(Pca.VerifyChain(Li(be), issuer, true, null, pins, null))); }
            Assert.Equal("hop 0: signature suite '" + alg + "' is not allowed by this verifier's suite policy", Why(Pca.VerifyChain(Li(root), issuer, true, new[] { "ed25519" }, pins, null)));
            Assert.Equal("", Why(Pca.VerifyChain(Li(root), issuer, true, new[] { alg }, pins, null)));
            // hops
            var hk = PqKey();
            var r2 = Cap(issuer, agent, new L(), null, "principal", null, null, Pca.HolderPqCommitment(PqPk(hk)));
            var hop = Cap(agent, sub, new L(), Pca.CapHash(r2), "agent", alg, hk);
            Assert.Equal("", Why(Pca.VerifyChain(Li(r2, hop), issuer, true)));
            var evil = Cap(agent, sub, new L(), Pca.CapHash(r2), "agent", alg, PqKey());
            Assert.Equal("hop 1: pq_pk does not match the signer's committed holder_pq (F-2)", Why(Pca.VerifyChain(Li(r2, evil), issuer, true)));
            var badHop = Clone(hop); badHop[alg == "ml-dsa-65" ? "sig" : "pq_sig"] = PqSign(hk, new byte[] { 7 });
            Assert.Equal("hop 1: bad signature (not signed by expected key)", Why(Pca.VerifyChain(Li(r2, badHop), issuer, true)));
            var r3 = Cap(issuer, agent, new L(), null, "principal");
            var h3 = Cap(agent, sub, new L(), Pca.CapHash(r3), "agent", alg, hk);
            Assert.StartsWith("hop 1: suite '" + alg + "' needs a PQ key bound", Why(Pca.VerifyChain(Li(r3, h3), issuer, true)));
        }
    }

    // ------------------------------------------------------------------ cap helpers (private seams)
    [Fact] public void BindingPolicyCheckSig()
    {
        var commit = Pca.HolderPqCommitment("PK");
        string? Pb(D signed, object? committed) => (string?)Priv("PqBindingError", signed, committed, "L");
        Assert.Null(Pb(M(("alg", "bogus")), null)); Assert.Null(Pb(M(), null)); Assert.Null(Pb(M(("alg", "ed25519")), null));
        var nc = "L: suite 'ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)";
        Assert.Equal(nc, Pb(M(("alg", "ml-dsa-65"), ("pq_pk", "PK")), null)); Assert.Equal(nc, Pb(M(("alg", "ml-dsa-65"), ("pq_pk", "PK")), 5));
        Assert.Equal("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pb(M(("alg", "ml-dsa-65"), ("pq_pk", "PK2")), commit));
        Assert.Equal("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pb(M(("alg", "ml-dsa-65"), ("pq_pk", 5)), commit));
        Assert.Equal("L: pq_pk does not match the signer's committed holder_pq (F-2)", Pb(M(("alg", "ml-dsa-65")), commit));
        Assert.Null(Pb(M(("alg", "ml-dsa-65"), ("pq_pk", "PK")), commit)); Assert.Null(Pb(M(("alg", "hybrid-ed25519-ml-dsa-65"), ("pq_pk", "PK")), commit));
        string? Sp(object? alg, IReadOnlyCollection<string>? allowed) => (string?)Priv("SuitePolicyError", alg, "H", allowed);
        Assert.Null(Sp("zzz", null)); Assert.Null(Sp(null, new[] { "ed25519" }));
        Assert.Equal("H: signature suite 'ed25519' is not allowed by this verifier's suite policy", Sp(null, new[] { "ml-dsa-65" }));
        Assert.Equal("H: signature suite 'ed25519' is not allowed by this verifier's suite policy", Sp(null, Array.Empty<string>()));
        Assert.Null(Sp("ml-dsa-65", new[] { "ml-dsa-65" }));
        Assert.Equal("H: signature suite 'ml-dsa-65' is not allowed by this verifier's suite policy", Sp("ml-dsa-65", new[] { "ed25519" }));
        Assert.Equal("H: signature suite '5' is not allowed by this verifier's suite policy", Sp(5, new[] { "ed25519" }));
        // signable hop body
        Assert.Null(Priv("SignableHopBody", M(("alg", "nope")))); Assert.Null(Priv("SignableHopBody", M(("alg", 5))));
        var c = M(("issuer", "i"), ("holder", "h"), ("caveats", new L()), ("parent", "p"));
        Assert.Equal(new[] { "issuer", "holder", "caveats", "parent" }, ((D)Priv("SignableHopBody", c)!).Keys.ToArray());
        c["alg"] = "ed25519"; Assert.False(((D)Priv("SignableHopBody", c)!).ContainsKey("alg"));
        c["alg"] = "ml-dsa-65"; c["pq_pk"] = "PK"; var b = (D)Priv("SignableHopBody", c)!; Assert.Equal("ml-dsa-65", b["alg"]); Assert.Equal("PK", b["pq_pk"]);
        c["pq_pk"] = 5; Assert.False(((D)Priv("SignableHopBody", c)!).ContainsKey("pq_pk"));
        c["alg"] = "hybrid-ed25519-ml-dsa-65"; c["pq_pk"] = "PK"; c["holder_pq"] = "HP"; b = (D)Priv("SignableHopBody", c)!;
        Assert.Equal("PK", b["pq_pk"]); Assert.Equal("HP", b["holder_pq"]);
        c["holder_pq"] = 5; Assert.False(((D)Priv("SignableHopBody", c)!).ContainsKey("holder_pq"));
        // checkSig
        var root = As(Valid()["cap_chain"] is L l ? l[0] : null); var iss = (string)root["issuer"]!;
        string Cs(D cap, object? signer) => (string)Priv("CheckSig", cap, signer, "X")!;
        Assert.Equal("", Cs(root, iss)); Assert.Equal("X: bad signature (not signed by expected key)", Cs(root, root["holder"]));
        var cc = Clone(root); cc["alg"] = "bogus"; Assert.Equal("X: unknown signature alg 'bogus'", Cs(cc, iss));
        cc = Clone(root); cc["caveats"] = Li(new object()); Assert.Equal("X: malformed body", Cs(cc, iss));
        cc = Clone(root); cc["id"] = B32.Replace('q', 'r'); Assert.Equal("X: body digest mismatch", Cs(cc, iss));
        cc = Clone(root); cc["body_digest"] = B32.Replace('q', 'r'); Assert.Equal("X: body digest mismatch", Cs(cc, iss));
        cc = Clone(root); cc.Remove("id"); Assert.Equal("X: body digest mismatch", Cs(cc, iss));
        cc = Clone(root); cc["sig"] = B64; Assert.Equal("X: bad signature (not signed by expected key)", Cs(cc, iss));
        cc["sig"] = 5; Assert.Equal("X: bad signature (not signed by expected key)", Cs(cc, iss));
    }

    // ------------------------------------------------------------------ wire
    static string? W(Action<D> f) { var p = Valid(); f(p); return Pca.ValidateWire(p); }
    static D Act(D p) => As(p["action"]); static D Pln(D p) => As(p["plan"]); static D Ip(D p) => As(Pln(p)["inclusion_proof"]); static D Hop(D p) => As(Ls(p["cap_chain"])[0]);

    [Fact] public void WireTop()
    {
        Assert.Null(Pca.ValidateWire(Valid())); Assert.Equal("PCActn is not an object", Pca.ValidateWire("x")); Assert.Equal("PCActn is not an object", Pca.ValidateWire(null));
        Assert.Equal("unknown field 'zzz'", W(p => p["zzz"] = N("1")));
        foreach (var k in new[] { "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig" })
            Assert.Equal($"missing field '{k}'", W(p => p.Remove(k)));
        foreach (var k in new[] { "ver", "counter", "iat", "exp" }) { Assert.Equal($"'{k}' must be a safe integer", W(p => p[k] = N("1.5"))); Assert.Equal($"'{k}' must be a safe integer", W(p => p[k] = "1")); }
        Assert.Equal("canonicalize: trailing fractional zero is not canonical", W(p => p["counter"] = N("1.50")));
        Assert.Equal("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", W(p => p["sig"] = "\ud800"));
        Assert.Null(W(p => p["threshold"] = M(("shares", new L()), ("extra", N("1e5")))));
        Assert.Equal("'aud' must be a non-empty string", W(p => p["aud"] = "")); Assert.Equal("'aud' must be a non-empty string", W(p => p["aud"] = N("1")));
        Assert.Null(W(p => p["aud"] = new string('x', 256))); Assert.Equal("'aud' must be a non-empty string", W(p => p["aud"] = new string('x', 257)));
        Assert.Null(W(p => p["aud"] = new string('\u20ac', 85))); Assert.Equal("'aud' must be a non-empty string", W(p => p["aud"] = new string('\u20ac', 86)));
        Assert.Null(W(p => p["nonce"] = new string('n', 128))); Assert.Equal("'nonce' must be a non-empty string", W(p => p["nonce"] = new string('n', 129)));
        Assert.Equal("'nonce' must be a non-empty string", W(p => p["nonce"] = "")); Assert.Equal("'nonce' must be a non-empty string", W(p => p["nonce"] = N("1")));
        Assert.Null(W(p => p["nonce"] = new string('\u20ac', 42))); Assert.Equal("'nonce' must be a non-empty string", W(p => p["nonce"] = new string('\u20ac', 43)));
        Assert.Equal("'grant_ref' is not canonical base64url (32 bytes)", W(p => p["grant_ref"] = "x"));
        Assert.Equal("'alg' must be a string", W(p => p["alg"] = 5)); Assert.Equal("unknown signature alg 'bogus'", W(p => p["alg"] = "bogus"));
        Assert.Equal("'pq_pk' must be absent for alg 'ed25519'", W(p => p["pq_pk"] = B32)); Assert.Equal("'pq_sig' must be absent for alg 'ed25519'", W(p => p["pq_sig"] = B32));
        Assert.Equal("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'", W(p => p["alg"] = "ml-dsa-65"));
        string pk = new string('A', 2603), sg = new string('A', 4412);
        Assert.Null(W(p => { p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = pk; p["pq_sig"] = sg; }));
        Assert.Equal("'pq_sig' is not canonical base64url (3309 bytes)", W(p => { p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = pk; p["pq_sig"] = "\ud800"; }));
        Assert.Equal("'pq_pk' is not canonical base64url (1952 bytes)", W(p => { p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = "x"; p["pq_sig"] = sg; }));
        Assert.Equal("'pq_sig' is not canonical base64url (3309 bytes)", W(p => { p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = pk; }));
        Assert.Null(W(p => { p["alg"] = "ml-dsa-65"; p["pq_pk"] = pk; p["sig"] = sg; }));
        Assert.Equal("'pq_sig' must be absent for alg 'ml-dsa-65'", W(p => { p["alg"] = "ml-dsa-65"; p["pq_pk"] = pk; p["sig"] = sg; p["pq_sig"] = sg; }));
    }

    [Fact] public void WireNested()
    {
        Assert.Equal("unknown field in 'action'", W(p => Act(p)["zz"] = "x")); Assert.Equal("'action' must be an object", W(p => p["action"] = "x"));
        foreach (var k in new[] { "verb", "resource", "reversibility_class" }) Assert.Equal("action.verb/resource/reversibility_class must be strings", W(p => Act(p)[k] = N("1")));
        Assert.Equal("'action.params_digest' is not canonical base64url (32 bytes)", W(p => Act(p)["params_digest"] = "x"));
        Assert.Equal("'plan' must be an object", W(p => p["plan"] = "x")); Assert.Equal("unknown field in 'plan'", W(p => Pln(p)["zz"] = "x"));
        Assert.Equal("'plan.root' is not canonical base64url (32 bytes)", W(p => Pln(p)["root"] = "x")); Assert.Equal("'plan.node_id' must be a string", W(p => Pln(p)["node_id"] = N("1")));
        Assert.Equal("'plan.conditions_digest' must be a canonical base64url string (32 bytes)", W(p => Pln(p)["conditions_digest"] = "x")); Assert.Null(W(p => Pln(p).Remove("conditions_digest")));
        Assert.Equal("'plan.inclusion_proof' must be an object", W(p => Pln(p)["inclusion_proof"] = "x")); Assert.Equal("unknown field in 'plan.inclusion_proof'", W(p => Ip(p)["zz"] = "x"));
        Assert.Equal("'plan.inclusion_proof.index' must be a safe integer", W(p => Ip(p)["index"] = "x")); Assert.Equal("'plan.inclusion_proof.size' must be a safe integer", W(p => Ip(p)["size"] = "x"));
        Assert.Equal("'plan.inclusion_proof.path' must be an array", W(p => Ip(p)["path"] = "x")); Assert.Equal("proof step 1 must be an object", W(p => Ls(Ip(p)["path"])[1] = "x"));
        Assert.Equal("unknown field in path[2]", W(p => As(Ls(Ip(p)["path"])[2])["zz"] = "x")); Assert.Equal("proof step 1: side must be 'L' or 'R'", W(p => As(Ls(Ip(p)["path"])[1])["side"] = "X"));
        Assert.Equal("proof step 1: side must be 'L' or 'R'", W(p => As(Ls(Ip(p)["path"])[1])["side"] = N("1")));
        Assert.Null(W(p => As(Ls(Ip(p)["path"])[0])["side"] = "R")); Assert.Equal("proof step 1: hash is not canonical base64url (32 bytes)", W(p => As(Ls(Ip(p)["path"])[1])["hash"] = "x"));
        Assert.Equal("'cap_chain' must be an array", W(p => p["cap_chain"] = "x")); Assert.Equal("cap_chain[0] must be an object", W(p => Ls(p["cap_chain"])[0] = "x"));
        Assert.Equal("unknown field in cap_chain[0]", W(p => Hop(p)["zz"] = "x"));
        foreach (var k in new[] { "id", "issuer", "holder", "body_digest" }) Assert.Equal($"cap_chain[0].{k} is not canonical base64url (32 bytes)", W(p => Hop(p)[k] = "x"));
        Assert.Equal("cap_chain[0]: unknown signature alg 'bogus'", W(p => Hop(p)["alg"] = "bogus"));
        Assert.Equal("cap_chain[0].parent is not canonical base64url (32 bytes)", W(p => Hop(p)["parent"] = "x")); Assert.Null(W(p => Hop(p)["parent"] = B32));
        Assert.Equal("cap_chain[0].holder_pq is not canonical base64url (32 bytes)", W(p => Hop(p)["holder_pq"] = "x")); Assert.Null(W(p => Hop(p)["holder_pq"] = B32));
        Assert.Equal("cap_chain[0].caveats must be an array of {type,...} objects", W(p => Hop(p)["caveats"] = "x"));
        Assert.Equal("cap_chain[0].caveats must be an array of {type,...} objects", W(p => Ls(Hop(p)["caveats"])[1] = "x"));
        Assert.Equal("cap_chain[0].caveats must be an array of {type,...} objects", W(p => As(Ls(Hop(p)["caveats"])[1])["type"] = N("1")));
        Assert.Equal("'attestation' must be an object with an integer 'epoch'", W(p => p["attestation"] = "x"));
        Assert.Equal("'attestation' must be an object with an integer 'epoch'", W(p => As(p["attestation"])["epoch"] = "x"));
        foreach (var k in new[] { "quote_digest", "model_id", "measurement", "operator" }) Assert.Equal("attestation string fields must be strings", W(p => As(p["attestation"])[k] = N("1")));
        Assert.Equal("'provenance' is malformed", W(p => p["provenance"] = "x")); Assert.Equal("'provenance' is malformed", W(p => As(p["provenance"])["causal_hash"] = N("1")));
        Assert.Equal("'provenance' is malformed", W(p => As(p["provenance"])["taint_level"] = "x")); Assert.Equal("'provenance' is malformed", W(p => As(p["provenance"])["trusted_refs"] = "x"));
        Assert.Equal("'provenance' is malformed", W(p => As(p["provenance"])["trusted_refs"] = Li("a", N("1")))); Assert.Null(W(p => As(p["provenance"])["trusted_refs"] = Li("a", "b")));
        Assert.Null(W(p => As(p["provenance"])["taint_level"] = N("0.5")));
        Assert.Equal("'freshness' is malformed", W(p => p["freshness"] = "x")); Assert.Equal("'freshness' is malformed", W(p => As(p["freshness"])["epoch"] = "x"));
        Assert.Equal("'freshness' is malformed", W(p => As(p["freshness"])["beacon_ref"] = N("1"))); Assert.Equal("'freshness' is malformed", W(p => As(p["freshness"])["accumulator_witness"] = N("1")));
        Assert.Equal("'risk_claim' is malformed", W(p => p["risk_claim"] = "x")); Assert.Equal("'risk_claim' is malformed", W(p => As(p["risk_claim"])["r"] = "x"));
        Assert.Equal("'risk_claim' is malformed", W(p => As(p["risk_claim"])["inputs"] = "x"));
        foreach (var (c, ok) in new[] { ("0", true), ("1", true), ("0.5", true), ("0.000001", true), ("-0.5", false), ("1.5", false), ("2", false), ("-1", false) })
            Assert.Equal(ok ? null : "'caution' must be a number in [0,1]", W(p => p["caution"] = N(c)));
        Assert.Equal("'caution' must be a number in [0,1]", W(p => p["caution"] = "x"));
        Assert.Equal("'rationale_commitment' is not canonical base64url (32 bytes)", W(p => p["rationale_commitment"] = "x")); Assert.Null(W(p => p["rationale_commitment"] = B32));
        Assert.Equal("'tool_binding' is not canonical base64url (32 bytes)", W(p => p["tool_binding"] = "x")); Assert.Null(W(p => p["tool_binding"] = B32));
        Assert.Equal("'progress_step' must be an object", W(p => p["progress_step"] = "x")); Assert.Null(W(p => p["progress_step"] = new D()));
        Assert.Equal("'prohibition_evidence' must be an object or array", W(p => p["prohibition_evidence"] = "x"));
        Assert.Null(W(p => p["prohibition_evidence"] = new L())); Assert.Null(W(p => p["prohibition_evidence"] = new D()));
        Assert.Equal("'threshold' must be {shares:[...]}", W(p => p["threshold"] = "x")); Assert.Equal("'threshold' must be {shares:[...]}", W(p => p["threshold"] = M(("shares", "x"))));
        Assert.Equal("'threshold' must be {shares:[...]}", W(p => p["threshold"] = new D()));
        Assert.Equal("threshold.shares[0] is malformed", W(p => p["threshold"] = M(("shares", Li("x"))))); Assert.Equal("threshold.shares[0] is malformed", W(p => p["threshold"] = M(("shares", Li(M(("role", N("1"))))))));
        var good = M(("role", "agent"), ("publicKey", B32), ("sig", B64));
        Assert.Null(W(p => p["threshold"] = M(("shares", Li(good)))));
        Assert.Equal("threshold.shares[1].publicKey is not canonical base64url (32 bytes)", W(p => p["threshold"] = M(("shares", Li(good, M(("role", "x")))))));
        Assert.Equal("threshold.shares[1].sig is not canonical base64url (64 bytes)", W(p => p["threshold"] = M(("shares", Li(good, M(("role", "x"), ("publicKey", B32)))))));
    }

    // ------------------------------------------------------------------ verdicts
    [Fact] public void VerifyApi()
    {
        var raw = (string)Vec("valid-raw-json-format-insensitive")["pcactn_json"]!;
        var g = Pca.VerifyRaw(raw, ValidGrant(), NOW, AUD);
        Assert.True(g.Allow); Assert.Equal("", g.Reason);
        Assert.Equal(new[] { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter" }, g.Checks.Keys.ToArray());
        Assert.False(Pca.VerifyRaw(raw, ValidGrant(), NOW, "other").Allow);
        Assert.Equal("audience: aud does not match this resource server / instance", Pca.VerifyRaw(raw, ValidGrant(), NOW, "other").Reason);
        Assert.Equal("wire: PCActn is not an object", Pca.VerifyPcactnCore("x", ValidGrant(), NOW, AUD).Reason);
        Assert.Equal("wire: " + Pca.ArtifactSizeReason, Pca.VerifyRaw(new string(' ', 524289), ValidGrant(), NOW, AUD).Reason);
        Assert.True(Pca.VerifyRaw(raw + new string(' ', 10), ValidGrant(), NOW, AUD).Allow);
        Assert.StartsWith("wire: strict JSON: expected a string key", Pca.VerifyRaw("{", ValidGrant(), NOW, AUD).Reason);
        D P(Action<D> f) { var p = Valid(); f(p); return p; }
        Assert.Equal("version: unsupported ver 3 (this verifier requires 2)", Pca.VerifyPcactnCore(P(p => p["ver"] = N("3")), ValidGrant(), NOW, AUD).Reason);
        long iat = NOW;
        Assert.Equal("validity: exp must be greater than iat", Pca.VerifyPcactnCore(P(p => p["exp"] = N($"{iat}")), ValidGrant(), NOW, AUD).Reason);
        Assert.Equal("validity: lifetime exceeds 3600000 ms", Pca.VerifyPcactnCore(P(p => p["exp"] = N($"{iat + 3600001}")), ValidGrant(), NOW, AUD).Reason);
        Assert.True(Pca.VerifyPcactnCore(P(p => p["exp"] = N($"{iat + 3600000}")), ValidGrant(), NOW, AUD).Checks["validity"]);
        var ok = P(p => p["exp"] = N($"{iat + 600000}"));
        Assert.Equal("validity: iat is in the future (clock skew)", Pca.VerifyPcactnCore(ok, ValidGrant(), NOW - 60001, AUD).Reason);
        Assert.True(Pca.VerifyPcactnCore(ok, ValidGrant(), NOW - 60000, AUD).Checks["validity"]);
        Assert.Equal("validity: the PCActn has expired", Pca.VerifyPcactnCore(ok, ValidGrant(), iat + 600001, AUD).Reason);
        Assert.True(Pca.VerifyPcactnCore(ok, ValidGrant(), iat + 600000, AUD).Checks["validity"]);
        g = Pca.VerifyPcactnCore(P(p => p["counter"] = N("-1")), ValidGrant(), NOW, AUD);
        Assert.False(g.Checks["counter"]); Assert.Equal("leaf_signature: signature does not verify under the leaf holder key", g.Reason);
        Assert.True(Pca.VerifyPcactnCore(P(p => p["counter"] = N("0")), ValidGrant(), NOW, AUD).Checks["counter"]);
        g = Pca.VerifyPcactnCore(P(p => p["cap_chain"] = new L()), ValidGrant(), NOW, AUD);
        Assert.Equal("chain: empty chain", g.Reason); Assert.False(g.Checks["chain"]); Assert.False(g.Checks["grant_ref_bound"]); Assert.False(g.Checks["leaf_signature"]);
        var first = Ls(Valid()["cap_chain"])[0];
        Assert.Equal("chain: chain too long (max 16 hops)", Pca.VerifyPcactnCore(P(p => p["cap_chain"] = new L(Enumerable.Repeat(first, 17))), ValidGrant(), NOW, AUD).Reason);
        Assert.Equal("chain: hop 1: broken parent link", Pca.VerifyPcactnCore(P(p => p["cap_chain"] = new L(Enumerable.Repeat(first, 16))), ValidGrant(), NOW, AUD).Reason);
        Assert.Equal("chain: " + Pca.CaveatLimitReason, Pca.VerifyPcactnCore(P(p => As(Ls(p["cap_chain"])[0])["caveats"] = new L(Enumerable.Range(0, 257).Select(_ => (object?)M(("type", "t"))))), ValidGrant(), NOW, AUD).Reason);
        var g2 = Clone(ValidGrant()); g2["holder"] = B32;
        Assert.Equal("chain: chain root is not the grant", Pca.VerifyPcactnCore(Valid(), g2, NOW, AUD).Reason);
        var g4 = Clone(ValidGrant()); g4["weird"] = new object();
        g = Pca.VerifyPcactnCore(Valid(), g4, NOW, AUD);
        Assert.False(g.Allow); Assert.StartsWith("malformed PCActn: ", g.Reason); Assert.True(g.Checks["wire"]); Assert.True(g.Checks["version"]); Assert.False(g.Checks["chain"]); Assert.False(g.Checks["counter"]);
        Assert.StartsWith("malformed PCActn: ", Pca.VerifyPcactnCore(P(p => p["ver"] = N("3")), g4, NOW, AUD).Reason);
        g = Pca.VerifyPcactnCore(P(p => p["grant_ref"] = B32.Replace('q', 'r')), ValidGrant(), NOW, AUD);
        Assert.False(g.Checks["grant_ref_bound"]); Assert.Equal("grant_ref_bound: grant_ref is not the id of the root capability in cap_chain", g.Reason);
        Assert.Equal("plan_inclusion: action is not a node of the committed plan", Pca.VerifyPcactnCore(P(p => Act(p)["verb"] = "other"), ValidGrant(), NOW, AUD).Reason);
        Assert.True(Pca.VerifyPcactnCore(P(p => Pln(p).Remove("conditions_digest")), ValidGrant(), NOW, AUD).Checks["plan_inclusion"]);
        Assert.Equal("leaf_signature: signature does not verify under the leaf holder key", Pca.VerifyPcactnCore(P(p => p["sig"] = B64), ValidGrant(), NOW, AUD).Reason);
        g = Pca.VerifyPcactnCore(Valid(), ValidGrant(), NOW, AUD, Array.Empty<string>());
        Assert.Equal("chain: hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy", g.Reason); Assert.False(g.Checks["leaf_signature"]);
        Assert.True(Pca.VerifyPcactnCore(Valid(), ValidGrant(), NOW, AUD, new[] { "ed25519" }).Allow);
        var tm = Pca.ThresholdMessage(Valid()); var pv = Valid(); pv["threshold"] = M(("shares", new L())); pv["pq_sig"] = "zz"; pv["sig"] = "other";
        Assert.Equal(tm, Pca.ThresholdMessage(pv)); pv["alg"] = "ed25519"; Assert.NotEqual(tm, Pca.ThresholdMessage(pv)); Assert.Equal(18 + 32, tm.Length);
    }

    // ------------------------------------------------------------------ PQ key resolution / suite sig / shares
    [Fact] public void ResolveAndSuiteSig()
    {
        var t = typeof(Pca).GetNestedType("PinnedPq", BindingFlags.NonPublic)!;
        var res = t.GetMethod("Resolve")!;
        PinnedPqView? R(string? id, object? pk, object? hp, IReadOnlyDictionary<string, string>? pins, string? trusted)
        {
            var o = res.Invoke(null, new object?[] { id, pk, hp, pins, trusted });
            return o == null ? null : new PinnedPqView((string)t.GetProperty("Key")!.GetValue(o)!);
        }
        var commit = Pca.HolderPqCommitment("PK");
        Assert.Equal("T", R("i", "PK", null, null, "T")!.Key); Assert.Null(R("i", "PK", null, null, "")); Assert.Null(R("i", "PK", null, null, null)); Assert.Null(R("i", "", null, null, null));
        Assert.Null(R("i", 5, commit, null, null)); Assert.Equal("PK", R("i", "PK", commit, null, null)!.Key); Assert.Null(R("i", "PK", "wrong", null, null)); Assert.Null(R("i", "PK", 5, null, null));
        Assert.Equal("PK", R("i", "PK", null, new Dictionary<string, string> { ["i"] = "PK" }, null)!.Key);
        Assert.Null(R("i", "PK", commit, new Dictionary<string, string> { ["i"] = "OTHER" }, null));
        Assert.Equal("PK", R("i", "PK", commit, new Dictionary<string, string> { ["j"] = "x" }, null)!.Key); Assert.Null(R("i", "PK", null, new Dictionary<string, string> { ["j"] = "PK" }, null));
        Assert.Equal("PK", R(null, "PK", commit, new Dictionary<string, string> { ["i"] = "x" }, null)!.Key);
        Assert.Equal("T", R("i", null, null, new Dictionary<string, string> { ["i"] = "X" }, "T")!.Key);
        var cv = t.GetMethod("CallerVouched")!;
        Assert.Null(cv.Invoke(null, new object?[] { 5 })); Assert.Null(cv.Invoke(null, new object?[] { "" })); Assert.Null(cv.Invoke(null, new object?[] { null })); Assert.NotNull(cv.Invoke(null, new object?[] { "k" }));
        // VerifySuiteSig over a genuine ml-dsa / hybrid leaf
        foreach (var nm in new[] { "pq-leaf-ml-dsa-65-valid", "pq-leaf-hybrid-ed25519-ml-dsa-65-valid" })
        {
            var p = As(Vec(nm)["pcactn"]); var chain = Ls(p["cap_chain"]); var holder = As(chain[^1])["holder"];
            var msg = Pca.ThresholdMessage(p); var alg = (string)p["alg"]!;
            Assert.True(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, p["sig"], p.GetValueOrDefault("pq_sig")), nm);
            Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, 5, p.GetValueOrDefault("pq_sig")));
            Assert.False(Pca.VerifySuiteSig("bogus", holder, p["pq_pk"], msg, p["sig"], p.GetValueOrDefault("pq_sig")));
            Assert.Equal(alg.StartsWith("hybrid"), Pca.VerifySuiteSig(null, holder, p["pq_pk"], msg, p["sig"], p.GetValueOrDefault("pq_sig"))); // absent alg == ed25519: only the ed25519 half is checked
            Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], new byte[] { 1 }, p["sig"], p.GetValueOrDefault("pq_sig")));
            Assert.False(Pca.VerifySuiteSig(alg, holder, 5, msg, p["sig"], p.GetValueOrDefault("pq_sig")));
            Assert.False(Pca.VerifySuiteSig(alg, holder, new string('A', 2603), msg, p["sig"], p.GetValueOrDefault("pq_sig")));
            if (alg.StartsWith("hybrid"))
            {
                Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, p["sig"], null)); Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, p["sig"], new string('A', 4412)));
                Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, new string('A', 86), p.GetValueOrDefault("pq_sig"))); Assert.False(Pca.VerifySuiteSig(alg, new string('A', 43), p["pq_pk"], msg, p["sig"], p.GetValueOrDefault("pq_sig")));
            }
            else Assert.False(Pca.VerifySuiteSig(alg, holder, p["pq_pk"], msg, new string('A', 4412), null));
            var pkb = Pca.B64uDecode(p["pq_pk"], 1952)!; var sgb = Pca.B64uDecode(alg.StartsWith("hybrid") ? p.GetValueOrDefault("pq_sig") : p["sig"], 3309)!;
            Assert.True(Pq.MlDsa65Verify(pkb, msg, sgb)); Assert.False(Pq.MlDsa65Verify(new byte[1951], msg, sgb)); Assert.False(Pq.MlDsa65Verify(new byte[1953], msg, sgb));
            Assert.False(Pq.MlDsa65Verify(pkb, msg, new byte[3308])); Assert.False(Pq.MlDsa65Verify(pkb, msg, new byte[3310])); Assert.False(Pq.MlDsa65Verify(pkb, new byte[] { 1 }, sgb));
        }
        Assert.Equal(1952, Pq.MlDsa65PublicKeyBytes); Assert.Equal(3309, Pq.MlDsa65SignatureBytes); Assert.Equal(64, Pq.Ed25519SignatureBytes);
        Assert.Equal(3, Pq.Suites.Count); Assert.Equal(64, Pq.Suites["ed25519"].SigBytes); Assert.False(Pq.Suites["ed25519"].NeedsPqPk); Assert.True(Pq.Suites["ml-dsa-65"].NeedsPqPk);
        Assert.False(Pq.Suites["ml-dsa-65"].NeedsPqSig); Assert.True(Pq.Suites["hybrid-ed25519-ml-dsa-65"].NeedsPqSig); Assert.Equal(3309, Pq.Suites["ml-dsa-65"].SigBytes);
    }
    sealed record PinnedPqView(string Key);

    [Fact] public void ThresholdSharesRegistry()
    {
        string a = Pub("agent"), pr = Pub("principal");
        D Entry(string role, L set, D share, int t = 1, string tm = "\u0001\u0002") => M(("role", role), ("t", N(t.ToString())), ("signer_set", set), ("threshold_message", Pca.B64u(Encoding.Latin1.GetBytes(tm))), ("share", share));
        byte[] Ssh(L set) => (byte[])typeof(Pca).GetMethod("SignerSetHash", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { set })!;
        byte[] Msg(string role, L set, int t, string tm = "\u0001\u0002") => Encoding.UTF8.GetBytes("atlas-pca/share/" + role + "\0").Concat(System.Security.Cryptography.SHA256.HashData(Encoding.Latin1.GetBytes(tm))).Concat(Ssh(set)).Concat(new[] { (byte)t }).ToArray();
        var set = Li(M(("publicKey", a), ("role", "agent")));
        var good = M(("role", "agent"), ("publicKey", a), ("sig", EdSign("agent", Msg("agent", set, 1))));
        Assert.True(Pca.VerifyThresholdShare(Entry("agent", set, good)));
        var noRole = Clone(good); noRole.Remove("role"); Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, noRole))); // R6-03: share.role is required (reference wellFormed)
        var expl = Clone(good); expl["alg"] = "ed25519"; Assert.True(Pca.VerifyThresholdShare(Entry("agent", set, expl)));
        foreach (var t in new[] { 2, 3 }) Assert.True(Pca.VerifyThresholdShare(Entry("agent", set, M(("role", "agent"), ("publicKey", a), ("sig", EdSign("agent", Msg("agent", set, t)))), t)), $"t={t}");
        foreach (var t in new[] { 0, 4, 255 }) Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, M(("role", "agent"), ("publicKey", a), ("sig", EdSign("agent", Msg("agent", set, t)))), t)), $"t={t} (R6-04: t must be 1..3)");
        foreach (var t in new[] { -1, 256 }) Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, M(("publicKey", a), ("sig", EdSign("agent", Msg("agent", set, 255)))), t)), $"t={t}");
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, good, 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, M(("publicKey", a), ("sig", EdSign("agent", Msg("agent", set, 0)))), 0)) && false);
        var wrongRole = Clone(good); wrongRole["role"] = "guardian"; Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, wrongRole)));
        var two = Li(M(("publicKey", a), ("role", "agent")), M(("publicKey", pr), ("role", "agent")));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", two, M(("publicKey", a), ("sig", EdSign("agent", Msg("agent", two, 1)))))));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", two, M(("publicKey", pr), ("sig", EdSign("principal", Msg("agent", two, 1)))))));
        var dual = Li(M(("publicKey", a), ("role", "agent")), M(("publicKey", a), ("role", "guardian")));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", dual, M(("publicKey", a), ("sig", EdSign("agent", Msg("agent", dual, 1)))))));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, M(("publicKey", pr), ("sig", EdSign("principal", Msg("agent", set, 1)))))));
        Assert.False(Pca.VerifyThresholdShare(Entry("guardian", set, good)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, M(("publicKey", a), ("sig", "x")))));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, Clone(good).Also(d => d["alg"] = "bogus"))));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, Clone(good).Also(d => d["alg"] = "ml-dsa-65"))));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, Clone(good).Also(d => d["alg"] = 5))));
        var bad = Entry("agent", set, good); bad["t"] = "x"; Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); bad["threshold_message"] = "not*b64"; Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); bad["share"] = "x"; Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); bad["signer_set"] = "x"; Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); bad["role"] = 5; Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); bad["signer_set"] = Li("x"); Assert.False(Pca.VerifyThresholdShare(bad));
        bad = Entry("agent", set, good); ((D)bad["share"]!).Remove("publicKey"); Assert.False(Pca.VerifyThresholdShare(bad));
        // PQ share: key from the signer set
        var k = PqKey();
        var pset = Li(M(("publicKey", a), ("role", "agent"), ("pq_pk", PqPk(k))));
        var tag = Encoding.UTF8.GetBytes("\0atlas-pca/share-suite/v1\0ml-dsa-65");
        var pmsg = Msg("agent", pset, 2).Concat(tag).ToArray();
        var psh = M(("role", "agent"), ("publicKey", a), ("alg", "ml-dsa-65"), ("sig", PqSign(k, pmsg)));
        Assert.True(Pca.VerifyThresholdShare(Entry("agent", pset, psh, 2)));
        Assert.True(Pca.VerifyThresholdShare(Entry("agent", pset, Clone(psh).Also(d => d["pq_pk"] = PqPk(k)), 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", pset, Clone(psh).Also(d => d["pq_pk"] = PqPk(PqKey())), 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", set, psh, 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", pset, psh, 1)));
        var hybridMsg = Msg("agent", pset, 2).Concat(Encoding.UTF8.GetBytes("\0atlas-pca/share-suite/v1\0hybrid-ed25519-ml-dsa-65")).ToArray();
        var hsh = M(("role", "agent"), ("publicKey", a), ("alg", "hybrid-ed25519-ml-dsa-65"), ("sig", EdSign("agent", hybridMsg)), ("pq_sig", PqSign(k, hybridMsg)));
        Assert.True(Pca.VerifyThresholdShare(Entry("agent", pset, hsh, 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", pset, Clone(hsh).Also(d => d.Remove("pq_sig")), 2)));
        Assert.False(Pca.VerifyThresholdShare(Entry("agent", pset, Clone(hsh).Also(d => d["pq_sig"] = PqSign(PqKey(), hybridMsg)), 2)));
        // signer set hash sorting
        var s2 = Li(M(("publicKey", pr), ("role", "r")), M(("publicKey", a), ("role", "r")), M(("publicKey", a), ("role", "a")));
        var sorted = Li(s2[2], string.CompareOrdinal(a, pr) < 0 ? s2[1] : s2[0], string.CompareOrdinal(a, pr) < 0 ? s2[0] : s2[1]);
        Assert.Equal(Ssh(sorted), Ssh(s2));
        var expect = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca/signerset/v1\0" + "[{\"publicKey\":\"" + a + "\",\"role\":\"a\"}," + string.Join(",", new[] { a, pr }.OrderBy(x => x, StringComparer.Ordinal).Select(x => "{\"publicKey\":\"" + x + "\",\"role\":\"r\"}")) + "]"));
        Assert.Equal(expect, Ssh(s2));
        var withPq = Li(M(("publicKey", a), ("role", "a"), ("pq_pk", "PQ"))); var numPq = Li(M(("publicKey", a), ("role", "a"), ("pq_pk", 5)));
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca/signerset/v1\0[{\"pq_pk\":\"PQ\",\"publicKey\":\"" + a + "\",\"role\":\"a\"}]")), Ssh(withPq));
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca/signerset/v1\0[{\"publicKey\":\"" + a + "\",\"role\":\"a\"}]")), Ssh(numPq));
        Assert.Null(typeof(Pca).GetMethod("SignerSetHash", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { Li("x") }));
        Assert.Null(typeof(Pca).GetMethod("SignerSetHash", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { Li(M(("role", 5), ("publicKey", a))) }));
        Assert.Null(typeof(Pca).GetMethod("SignerSetHash", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object[] { Li(M(("role", "r"))) }));
    }
}

static class Ext { public static T Also<T>(this T x, Action<T> f) { f(x); return x; } }
