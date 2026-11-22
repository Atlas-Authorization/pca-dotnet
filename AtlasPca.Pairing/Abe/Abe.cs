using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Pairing;
using static supranational.blst;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Abe;

/// <summary>An invalid policy, master public key or master secret key.</summary>
public sealed class PcaEncryptionError : ArgumentException
{
    public PcaEncryptionError(string m) : base(m) { }
}

/// <summary>
/// Proof-carrying encryption: ciphertext-policy ABE (FAME, see <see cref="Fame"/>) with the payload sealed under AES-256-GCM, the
/// whole header authenticated. Keys, ciphertexts and the master keys are JSON trees with the TypeScript reference's member names, so
/// material crosses languages unchanged. Every parser is fail-closed: <see cref="Decrypt"/> returns null on any deviation and never throws.
/// </summary>
public static class Abe
{
    public const string AbeAlg = "fame-cpabe-bls12381-type3/aes-256-gcm";
    const string CekInfo = "atlas-pca-abe/cek/v3";
    const int SaltLen = 16;

    // ---- wire helpers ----

    static string B64u(byte[] b) => AtlasPca.Pca.B64u(b);

    /// <summary>Canonical unpadded base64url only; null otherwise.</summary>
    static byte[]? Unb64u(object? o) => AtlasPca.Pca.B64uDecode(o);

    static D? Obj(object? o) => o as D;

    static object? Get(D m, string k) => m.TryGetValue(k, out var v) ? v : null;

    static bool IsTwo(object? o) => AbePolicy.NumVal(o) is double d && d == 2.0;

    static P1? ReadG1(object? x)
    {
        var b = Unb64u(x);
        if (b == null) return null;
        try
        {
            var p = Bls12.DecodeG1(b);
            return p.is_inf() ? null : p;
        }
        catch (ArgumentException) { return null; }
    }

    static P2? ReadG2(object? x)
    {
        var b = Unb64u(x);
        if (b == null) return null;
        try
        {
            var p = Bls12.DecodeG2(b);
            return p.is_inf() ? null : p;
        }
        catch (ArgumentException) { return null; }
    }

    static byte[]? ReadGt(object? x)
    {
        var b = Unb64u(x);
        return b != null && Gt.IsElement(b) ? b : null;
    }

    static P1[]? Tri1(object? x)
    {
        if (x is not L l || l.Count != 3) return null;
        var o = new P1[3];
        for (int i = 0; i < 3; i++) { var p = ReadG1(l[i]); if (p == null) return null; o[i] = p.Value; }
        return o;
    }

    static P2[]? Tri2(object? x)
    {
        if (x is not L l || l.Count != 3) return null;
        var o = new P2[3];
        for (int i = 0; i < 3; i++) { var p = ReadG2(l[i]); if (p == null) return null; o[i] = p.Value; }
        return o;
    }

    static L Enc(P1[] p) => new() { B64u(p[0].compress()), B64u(p[1].compress()), B64u(p[2].compress()) };

    static L Enc(P2[] p) => new() { B64u(p[0].compress()), B64u(p[1].compress()), B64u(p[2].compress()) };

    // ---- scalars ----

    static BigInteger RandomScalar()
    {
        while (true)
        {
            var v = Bls12.Mod(Bls12.Os2ip(RandomNumberGenerator.GetBytes(64)));
            if (!v.IsZero) return v;
        }
    }

    static string ScalarB64(BigInteger s) => B64u(Bls12.I2osp(s, 32));

    /// <summary>Exactly one encoding per scalar: 32 bytes, non-zero, and below r.</summary>
    static BigInteger? CanonicalScalar(object? enc)
    {
        var b = Unb64u(enc);
        if (b == null || b.Length != 32) return null;
        var x = Bls12.Os2ip(b);
        return x.IsZero || x >= Bls12.R ? null : x;
    }

    // ---- setup / keygen ----

    /// <summary>A fresh master key pair: <c>{mpk, msk}</c>.</summary>
    public static D Setup()
    {
        var a = new[] { RandomScalar(), RandomScalar() };
        var b = new[] { RandomScalar(), RandomScalar() };
        var d = new[] { RandomScalar(), RandomScalar(), RandomScalar() };
        var m = Fame.Setup(a, b, d);
        var msk = new D
        {
            ["v"] = 2L,
            ["curve"] = "bls12-381",
            ["a"] = new L { ScalarB64(a[0]), ScalarB64(a[1]) },
            ["b"] = new L { ScalarB64(b[0]), ScalarB64(b[1]) },
            ["g"] = new L { B64u(m.Msk.G[0].compress()), B64u(m.Msk.G[1].compress()), B64u(m.Msk.G[2].compress()) },
        };
        var mpk = new D
        {
            ["v"] = 2L,
            ["curve"] = "bls12-381",
            ["h"] = new L { B64u(m.Mpk.H1.compress()), B64u(m.Mpk.H2.compress()) },
            ["t"] = new L { B64u(m.Mpk.T1), B64u(m.Mpk.T2) },
        };
        return new D { ["mpk"] = mpk, ["msk"] = msk };
    }

    static Fame.Msk ParseMsk(object? o)
    {
        var m = Obj(o);
        if (m == null || !IsTwo(Get(m, "v"))) throw new PcaEncryptionError("invalid master secret key");
        var a = ScalarPair(Get(m, "a"));
        var b = ScalarPair(Get(m, "b"));
        var g = Tri1(Get(m, "g"));
        if (a == null || b == null || g == null) throw new PcaEncryptionError("invalid master secret key");
        return new Fame.Msk(a, b, g);
    }

    static BigInteger[]? ScalarPair(object? x)
    {
        if (x is not L l || l.Count != 2) return null;
        var o = new BigInteger[2];
        for (int i = 0; i < 2; i++) { var s = CanonicalScalar(l[i]); if (s == null) return null; o[i] = s.Value; }
        return o;
    }

    static Fame.Mpk ParseMpk(object? o)
    {
        var m = Obj(o);
        if (m != null && IsTwo(Get(m, "v")) && Get(m, "h") is L h && h.Count == 2 && Get(m, "t") is L t && t.Count == 2)
        {
            var h1 = ReadG2(h[0]);
            var h2 = ReadG2(h[1]);
            var t1 = ReadGt(t[0]);
            var t2 = ReadGt(t[1]);
            if (h1 != null && h2 != null && t1 != null && t2 != null) return new Fame.Mpk(h1.Value, h2.Value, t1, t2);
        }
        throw new PcaEncryptionError("invalid master public key");
    }

    /// <summary>Issue a decryption key for an explicit set of attribute tokens (empty or ill-formed names are dropped).</summary>
    public static D KeygenForAttributes(object? msk, IEnumerable<string> attrs)
    {
        var m = ParseMsk(msk);
        var names = new List<string>();
        foreach (var a in attrs.Distinct()) if (!string.IsNullOrEmpty(a) && !AtlasPca.Pca.HasLoneSurrogate(a)) names.Add(a);
        var sigmas = new List<BigInteger>();
        for (int i = 0; i < names.Count; i++) sigmas.Add(RandomScalar());
        var key = Fame.Keygen(m, names, new[] { RandomScalar(), RandomScalar() }, sigmas, RandomScalar());
        var asd = new D();
        foreach (var n in names) asd[n] = new D { ["k"] = Enc(key.Attrs[n]) };
        return new D { ["v"] = 2L, ["curve"] = "bls12-381", ["k0"] = Enc(key.K0), ["kp"] = Enc(key.Kp), ["attrs"] = asd };
    }

    /// <summary>Issue a key bound to a capability: its <see cref="CapabilityAttributes"/> plus the extra tokens; <c>holder</c> is recorded.</summary>
    public static D KeygenForCapability(object? msk, D capability, IEnumerable<string> extra, D? opts)
    {
        var attrs = CapabilityAttributesOrdered(capability, opts);
        foreach (var a in extra) if (!string.IsNullOrEmpty(a)) attrs.Add(a);
        var key = KeygenForAttributes(msk, attrs);
        if (Get(capability, "holder") is string h) key["holder"] = h;
        return key;
    }

    /// <summary>An untrusted key; a malformed attribute component counts as not held. Null if K0, K' or the container is malformed.</summary>
    static Fame.Key? ParseKey(object? o)
    {
        var k = Obj(o);
        if (k == null || !IsTwo(Get(k, "v")) || Obj(Get(k, "attrs")) is not D src) return null;
        var k0 = Tri2(Get(k, "k0"));
        var kp = Tri1(Get(k, "kp"));
        if (k0 == null || kp == null) return null;
        var attrs = new Dictionary<string, P1[]>();
        foreach (var e in src)
        {
            var comp = Obj(e.Value);
            var t = comp == null ? null : Tri1(Get(comp, "k"));
            if (t != null) attrs[e.Key] = t;
        }
        return new Fame.Key(k0, kp, attrs);
    }

    // ---- KDF / AEAD ----

    /// <summary>HKDF-SHA256 (RFC 5869), 32 bytes: the content-encryption key from the KEM key.</summary>
    static byte[] Kdf32(byte[] ikm, byte[] salt, string info) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, salt, Encoding.UTF8.GetBytes(info));

    static (byte[] Iv, byte[] Ct, byte[] Tag) Seal(byte[] key, byte[] pt, byte[] aad)
    {
        var iv = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[pt.Length];
        var tag = new byte[16];
        using var g = new AesGcm(key, 16);
        g.Encrypt(iv, pt, ct, tag, aad);
        return (iv, ct, tag);
    }

    static byte[]? Open(byte[] key, byte[] iv, byte[] ct, byte[] tag, byte[] aad)
    {
        if (key.Length != 32 || iv.Length != 12 || tag.Length != 16) return null;
        try
        {
            using var g = new AesGcm(key, 16);
            var pt = new byte[ct.Length];
            g.Decrypt(iv, ct, tag, pt, aad);
            return pt;
        }
        catch (CryptographicException) { return null; }
    }

    /// <summary>The authenticated header bytes (strict canonical JSON); throws InvalidOperationException outside the profile.</summary>
    static byte[] Aad(D c)
    {
        var h = new D();
        foreach (var k in new[] { "v", "alg", "salt", "ct0", "tree", "rows" }) h[k] = Get(c, k);
        return Encoding.UTF8.GetBytes(AtlasPca.Pca.Canonicalize(h));
    }

    // ---- encrypt ----

    /// <summary>Encrypt so that only a key whose attributes satisfy <paramref name="policy"/> opens it. Throws <see cref="PcaEncryptionError"/> on a bad policy or key.</summary>
    public static D EncryptForPolicy(object? mpk, object? policy, byte[] plaintext)
    {
        var norm = AbePolicy.Normalize(policy);
        if (!norm.Ok) throw new PcaEncryptionError("invalid policy: " + norm.Reason);
        var dup = Fame.FirstRepeatedAttribute(norm.Tree!);
        if (dup != null) throw new PcaEncryptionError("invalid policy: attribute " + JsCanon.Lenient(dup) + " is named by more than one leaf (single-use attributes only)");
        var pk = ParseMpk(mpk);
        var salt = RandomNumberGenerator.GetBytes(SaltLen);
        var e = Fame.Encrypt(pk, norm.Tree!, new[] { RandomScalar(), RandomScalar() });
        var rows = new L();
        foreach (var r in e.Ct.Rows) rows.Add(Enc(r));
        var header = new D
        {
            ["v"] = 2L,
            ["alg"] = AbeAlg,
            ["salt"] = B64u(salt),
            ["ct0"] = Enc(e.Ct.Ct0),
            ["tree"] = norm.Tree,
            ["rows"] = rows,
        };
        byte[] headerAad;
        try { headerAad = Aad(header); }
        catch (InvalidOperationException) { throw new PcaEncryptionError("policy cannot be authenticated (header outside the canonical JSON profile)"); }
        var s = Seal(Kdf32(e.K, salt, CekInfo), plaintext, headerAad);
        header["iv"] = B64u(s.Iv);
        header["ct"] = B64u(s.Ct);
        header["tag"] = B64u(s.Tag);
        return header;
    }

    public static D EncryptForPolicy(object? mpk, object? policy, string plaintext) =>
        EncryptForPolicy(mpk, policy, Encoding.UTF8.GetBytes(plaintext));

    /// <summary>Encrypt a JSON value (the payload layer of <see cref="DecryptWithCapability"/>).</summary>
    public static D EncryptToolPayload(object? mpk, object? policy, object? payload) =>
        EncryptForPolicy(mpk, policy, JsCanon.Lenient(payload) ?? throw new ArgumentException("canonicalize: not canonicalizable"));

    // ---- parse ----

    static D? ParseTree(object? x, int gates, int[] budget)
    {
        var m = Obj(x);
        if (++budget[0] > AbePolicy.MaxPolicyNodes || m == null) return null;
        var kind = Get(m, "kind");
        if (kind is string ks && ks == "leaf")
        {
            if (Get(m, "attr") is not string a || a.Length == 0 || AtlasPca.Pca.HasLoneSurrogate(a) || m.Count != 2) return null;
            return AbePolicy.Leaf(a);
        }
        if (kind is string kg && kg == "gate")
        {
            if (gates + 1 > AbePolicy.MaxPolicyDepth || m.Count != 3) return null;
            var t = Get(m, "t");
            if (!AbePolicy.IsPosInt(t) || Get(m, "of") is not L of || of.Count == 0) return null;
            double td = AbePolicy.NumVal(t)!.Value;
            if (td > of.Count || of.Count >= AbePolicy.MaxPolicyNodes) return null;
            var kids = new L();
            foreach (var b in of)
            {
                var sub = ParseTree(b, gates + 1, budget);
                if (sub == null) return null;
                kids.Add(sub);
            }
            return AbePolicy.Gate((long)td, kids);
        }
        return null;
    }

    static L? StrTri(object? x)
    {
        if (x is not L l || l.Count != 3) return null;
        foreach (var e in l) if (Unb64u(e) == null) return null;
        return new L(l);
    }

    /// <summary>Validate an untrusted value as a ciphertext; null (fail closed) on any deviation.</summary>
    public static D? ParseCiphertext(object? o)
    {
        var x = Obj(o);
        if (x == null || !IsTwo(Get(x, "v")) || Get(x, "alg") is not string alg || alg != AbeAlg) return null;
        foreach (var k in new[] { "salt", "iv", "ct", "tag" }) if (Unb64u(Get(x, k)) == null) return null;
        var ct0 = StrTri(Get(x, "ct0"));
        var tree = ParseTree(Get(x, "tree"), 0, new int[1]);
        if (ct0 == null || tree == null || Get(x, "rows") is not L rawRows) return null;
        if (rawRows.Count != Fame.LeafCount(tree) || Fame.FirstRepeatedAttribute(tree) != null) return null;
        var rows = new L();
        foreach (var r in rawRows)
        {
            var t = StrTri(r);
            if (t == null) return null;
            rows.Add(t);
        }
        return new D
        {
            ["v"] = 2L,
            ["alg"] = AbeAlg,
            ["salt"] = Get(x, "salt"),
            ["ct0"] = ct0,
            ["tree"] = tree,
            ["rows"] = rows,
            ["iv"] = Get(x, "iv"),
            ["ct"] = Get(x, "ct"),
            ["tag"] = Get(x, "tag"),
        };
    }

    // ---- decrypt ----

    /// <summary>The plaintext iff the key's attributes satisfy the ciphertext's policy and the AEAD authenticates; otherwise null. Never throws.</summary>
    public static byte[]? Decrypt(object? key, object? ciphertext)
    {
        try
        {
            var ct = ParseCiphertext(ciphertext);
            if (ct == null) return null;
            var pk = ParseKey(key);
            if (pk == null) return null;
            var salt = Unb64u(ct["salt"]);
            var iv = Unb64u(ct["iv"]);
            var body = Unb64u(ct["ct"]);
            var tag = Unb64u(ct["tag"]);
            var ct0 = Tri2(ct["ct0"]);
            var rows = new List<P1[]>();
            foreach (var r in (L)ct["rows"]!)
            {
                var t = Tri1(r);
                if (t == null) return null;
                rows.Add(t);
            }
            if (salt == null || iv == null || body == null || tag == null || ct0 == null) return null;
            var k = Fame.Decrypt(pk, (D)ct["tree"]!, new Fame.Ciphertext(ct0, rows));
            if (k == null) return null;
            byte[] headerAad;
            try { headerAad = Aad(ct); }
            catch (InvalidOperationException) { return null; }
            return Open(Kdf32(k, salt, CekInfo), iv, body, tag, headerAad);
        }
        catch (System.Exception e) when (!Bls12.Fatal(e)) { return null; }
    }

    public static string? DecryptText(object? key, object? ciphertext)
    {
        var pt = Decrypt(key, ciphertext);
        return pt == null ? null : new UTF8Encoding(false).GetString(pt);
    }

    /// <summary><c>{ok:true, payload}</c> or <c>{ok:false, reason}</c>.</summary>
    public static D DecryptWithCapability(object? key, object? ciphertext)
    {
        var pt = Decrypt(key, ciphertext);
        if (pt == null) return new D { ["ok"] = false, ["reason"] = "capability does not satisfy the policy, or ciphertext is invalid" };
        try
        {
            var payload = AtlasPca.Pca.ParseJson(new UTF8Encoding(false).GetString(pt));
            return new D { ["ok"] = true, ["payload"] = payload };
        }
        catch (StrictJsonException)
        {
            return new D { ["ok"] = false, ["reason"] = "decrypted payload is not valid JSON" };
        }
    }

    // ---- capability attributes ----

    static string Act(string verb, string resource) => "act:" + JsCanon.Lenient(new L { verb, resource });

    static List<string> VerbsOf(object? v)
    {
        var o = new List<string>();
        if (v is string s) o.Add(s);
        else if (v is L l) foreach (var e in l) if (e is string es) o.Add(es);
        return o;
    }

    /// <summary>
    /// The canonical attribute set a capability possesses (sorted): holder, scope, and (from the ROOT only, never from a delegated hop's
    /// own caveats) act/verb/resource tokens. A delegated capability gets scope/act/verb/resource tokens only with a verified chain (root
    /// first, ending in the capability); a chain that fails verification yields none (fail closed). <paramref name="opts"/>: chain, principal, pqPins.
    /// </summary>
    public static SortedSet<string> CapabilityAttributes(D? cap, D? opts) => new(CapabilityAttributesOrdered(cap, opts), StringComparer.Ordinal);

    /// <summary>An insertion-ordered, de-duplicated list of tokens (a JS Set): the order the reference issues key attributes in.</summary>
    sealed class OSet : List<string> { public new void Add(string s) { if (!Contains(s)) base.Add(s); } }

    static OSet CapabilityAttributesOrdered(D? cap, D? opts)
    {
        var o = new OSet();
        if (cap == null) return o;
        object? scopeSource = null;
        D? envSource = null;
        if (opts != null && opts.ContainsKey("chain"))
        {
            if (opts["chain"] is not L chain || chain.Count == 0) return o;
            var root = Obj(chain[0]);
            var last = Obj(chain[^1]);
            if (root == null || last == null || !Equals(Get(last, "id"), Get(cap, "id"))) return o;
            var principal = Get(opts, "principal") ?? Get(root, "issuer");
            Dictionary<string, string>? pins = null;
            if (Obj(Get(opts, "pqPins")) is D pd)
            {
                pins = new Dictionary<string, string>();
                foreach (var e in pd) if (e.Value is string sv) pins[e.Key] = sv;
            }
            if (!AtlasPca.Pca.VerifyChain(chain, principal as string, principal is string, null, pins, null).Ok) return o;
            scopeSource = Get(root, "caveats");
            envSource = root;
        }
        else if (!cap.ContainsKey("parent"))
        {
            scopeSource = Get(cap, "caveats");
            envSource = cap;
        }
        if (Get(cap, "holder") is string holder && holder.Length > 0) o.Add("holder:" + holder);
        if (scopeSource is L cavs)
        {
            foreach (var c in cavs)
            {
                var cv = Obj(c);
                if (cv == null) continue;
                var type = Get(cv, "type");
                if (type is string t1 && t1 == "scope" && Get(cv, "value") is string val) o.Add("scope:" + val);
                if (type is string t2 && t2 == "scopes" && Get(cv, "values") is L vals)
                    foreach (var s in vals) if (s is string ss) o.Add("scope:" + ss);
            }
        }
        var env = envSource == null ? null : AtlasPca.Pca.ReadEnvelope(envSource);
        if (env != null && Get(env, "predicates") is L plist)
        {
            var preds = new List<D>();
            foreach (var p in plist)
            {
                if (p is D pdict) preds.Add(pdict);
                else if (p is L) preds.Add(new D()); // an array is an object to the reference: it counts, and names no verb or resource
            }
            foreach (var p in preds)
                if (Get(p, "resource") is string res) foreach (var v in VerbsOf(Get(p, "verb"))) o.Add(Act(v, res));
            if (preds.Count == 1)
            {
                var p = preds[0];
                foreach (var v in VerbsOf(Get(p, "verb"))) o.Add("verb:" + v);
                if (Get(p, "resource") is string res) o.Add("resource:" + res);
            }
        }
        return o;
    }
}
