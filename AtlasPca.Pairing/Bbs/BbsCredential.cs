using System.Globalization;
using System.Numerics;
using System.Text;
using AtlasPca.Pairing;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Bbs;

/// <summary>
/// PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is
/// <c>iss</c>, <c>sub</c>, then one message per caveat named <c>cav:&lt;i&gt;:&lt;type&gt;</c> whose value is the strict-canonical JSON
/// of the caveat; each message's octets are <c>utf8(name) || 0x00 || utf8(value)</c>. Credentials, attributes and
/// presentations are JSON maps with the same member names as the TypeScript types.
/// </summary>
public static class BbsCredential
{
    /// <summary>UTF-8 with U+FFFD for an unpaired surrogate (what a JavaScript TextEncoder produces).</summary>
    static byte[] Utf8(string s) => new UTF8Encoding(false, false).GetBytes(s);

    internal static byte[] EncodeAttribute(object? name, object? value)
    {
        if (name is not string n || value is not string v) throw new ArgumentException("attribute name and value must be strings");
        if (n.Contains('\0')) throw new ArgumentException("attribute name must not contain NUL");
        var nb = Utf8(n);
        var vb = Utf8(v);
        var o = new byte[nb.Length + 1 + vb.Length];
        nb.CopyTo(o, 0);
        vb.CopyTo(o, nb.Length + 1);
        return o;
    }

    static D AsMap(object? o) => o as D ?? throw new ArgumentException("not an object");
    static L AsList(object? o) => o as L ?? throw new ArgumentException("not an array");

    /// <summary>Java-style string conversion of a JSON value (null prints "null").</summary>
    static string Str(object? o) => o switch { null => "null", string s => s, Num n => n.Raw, bool b => b ? "true" : "false", _ => o.ToString() ?? "null" };

    static byte[] Encode(object? attr) { var a = AsMap(attr); return EncodeAttribute(a.GetValueOrDefault("name"), a.GetValueOrDefault("value")); }

    static List<byte[]> EncodeAll(object? attrs) => AsList(attrs).Select(Encode).ToList();

    static D Attr(int index, string name, object? value) => new() { ["index"] = new Num(index.ToString(CultureInfo.InvariantCulture)), ["name"] = name, ["value"] = value };

    static byte[] Unb64u(object? o) => AtlasPca.Pca.B64uDecode(o) ?? throw new ArgumentException("not canonical base64url");

    /// <summary>The ordered attribute vector for a capability: issuer, holder, then each caveat.</summary>
    public static List<D> CapabilityAttributes(D capability)
    {
        var attrs = new List<D> { Attr(0, "iss", capability.GetValueOrDefault("issuer")), Attr(1, "sub", capability.GetValueOrDefault("holder")) };
        if (capability.GetValueOrDefault("caveats") is L cs)
        {
            for (int i = 0; i < cs.Count; i++)
            {
                var cv = AsMap(cs[i]);
                attrs.Add(Attr(i + 2, "cav:" + i.ToString(CultureInfo.InvariantCulture) + ":" + Str(cv.GetValueOrDefault("type")), AtlasPca.Pca.Canonicalize(cv)));
            }
        }
        return attrs;
    }

    /// <summary>Sign a capability's attributes as a BBS credential; <paramref name="header"/> is optional application context (null = empty).</summary>
    public static D IssueCapabilityCredential(D capability, BigInteger sk, byte[] pk, byte[]? header)
    {
        var attributes = CapabilityAttributes(capability);
        var hdr = header ?? Array.Empty<byte>();
        var signature = Bbs.Sign(sk, pk, hdr, EncodeAll(new L(attributes.Cast<object?>())));
        return new D
        {
            ["issuerPublicKey"] = AtlasPca.Pca.B64u(pk),
            ["header"] = AtlasPca.Pca.B64u(hdr),
            ["attributes"] = new L(attributes.Cast<object?>()),
            ["signature"] = AtlasPca.Pca.B64u(signature),
        };
    }

    /// <summary>Verify a whole credential against its issuer key (every attribute). Never throws.</summary>
    public static bool VerifyCredential(D cred)
    {
        byte[] pk, header, signature;
        try
        {
            pk = Unb64u(cred.GetValueOrDefault("issuerPublicKey"));
            header = Unb64u(cred.GetValueOrDefault("header"));
            signature = Unb64u(cred.GetValueOrDefault("signature"));
        }
        catch (System.Exception e) when (!Bls12.Fatal(e)) { return false; }
        try { return Bbs.Verify(pk, signature, header, EncodeAll(cred.GetValueOrDefault("attributes"))); }
        catch (System.Exception e) when (!Bls12.Fatal(e)) { return false; }
    }

    static int IndexOf(object? attr)
    {
        var i = AsMap(attr).GetValueOrDefault("index");
        double d = i is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var x) ? x : double.NaN;
        if (double.IsNaN(d) || double.IsInfinity(d) || d != Math.Floor(d) || Math.Abs(d) > int.MaxValue) throw new ArgumentException("attribute index is not an integer");
        return (int)d;
    }

    /// <summary>Selective-disclosure presentation revealing only the named attributes; <paramref name="presentationHeader"/> binds it to a context (null = empty). The proof is randomized.</summary>
    public static D PresentCredential(D cred, IEnumerable<string> disclose, byte[]? presentationHeader)
    {
        var pk = Unb64u(cred.GetValueOrDefault("issuerPublicKey"));
        var header = Unb64u(cred.GetValueOrDefault("header"));
        var signature = Unb64u(cred.GetValueOrDefault("signature"));
        var ph = presentationHeader ?? Array.Empty<byte>();
        var wanted = new SortedSet<string>(disclose, StringComparer.Ordinal);
        var messages = EncodeAll(cred.GetValueOrDefault("attributes"));
        var idx = new List<int>();
        var disclosed = new L();
        foreach (var a in AsList(cred.GetValueOrDefault("attributes")))
        {
            if (AsMap(a).GetValueOrDefault("name") is string nm && wanted.Contains(nm))
            {
                idx.Add(IndexOf(a));
                disclosed.Add(a);
            }
        }
        var missing = wanted.Where(w => !disclosed.Any(d => w.Equals(AsMap(d).GetValueOrDefault("name")))).ToList();
        if (missing.Count > 0) throw new ArgumentException("presentCredential: unknown attribute(s): " + string.Join(", ", missing));
        var proof = Bbs.ProofGen(pk, signature, header, ph, messages, idx);
        return new D
        {
            ["issuerPublicKey"] = cred.GetValueOrDefault("issuerPublicKey"),
            ["header"] = cred.GetValueOrDefault("header"),
            ["presentationHeader"] = AtlasPca.Pca.B64u(ph),
            ["messageCount"] = new Num(AsList(cred.GetValueOrDefault("attributes")).Count.ToString(CultureInfo.InvariantCulture)),
            ["disclosed"] = disclosed,
            ["proof"] = AtlasPca.Pca.B64u(proof),
        };
    }

    /// <summary>
    /// Check a presentation. <paramref name="pk"/>, <paramref name="disclosed"/> and <paramref name="presentationHeader"/> default (when null) to the values the
    /// presentation carries; pass them to assert the verifier's own expectations. Never throws.
    /// </summary>
    public static bool VerifyPresentation(D pres, byte[]? pk, L? disclosed, byte[]? presentationHeader)
    {
        byte[] pkb, header, proof;
        try
        {
            pkb = pk ?? Unb64u(pres.GetValueOrDefault("issuerPublicKey"));
            header = Unb64u(pres.GetValueOrDefault("header"));
            proof = Unb64u(pres.GetValueOrDefault("proof"));
        }
        catch (System.Exception e) when (!Bls12.Fatal(e)) { return false; }
        if (pk != null && AtlasPca.Pca.B64u(pk) != pres.GetValueOrDefault("issuerPublicKey") as string) return false;
        byte[] ph;
        if (presentationHeader != null) ph = presentationHeader;
        else
        {
            try { ph = Unb64u(pres.GetValueOrDefault("presentationHeader")); }
            catch (System.Exception e) when (!Bls12.Fatal(e)) { return false; }
        }
        if (presentationHeader != null && presentationHeader.Length > 0 && AtlasPca.Pca.B64u(ph) != pres.GetValueOrDefault("presentationHeader") as string) return false;
        try { return VerifyInner(pres, pkb, header, proof, ph, disclosed); }
        catch (System.Exception e) when (!Bls12.Fatal(e)) { return false; }
    }

    static string Key(object? x) { var a = AsMap(x); return IndexOf(x).ToString(CultureInfo.InvariantCulture) + "\0" + Str(a.GetValueOrDefault("name")) + "\0" + Str(a.GetValueOrDefault("value")); }

    static bool SameDisclosure(L a, L b)
    {
        if (a.Count != b.Count) return false;
        var sa = a.Select(Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var sb = b.Select(Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
        return sa.SequenceEqual(sb);
    }

    static bool VerifyInner(D pres, byte[] pk, byte[] header, byte[] proof, byte[] ph, L? optsDisclosed)
    {
        var disclosed = optsDisclosed ?? AsList(pres.GetValueOrDefault("disclosed"));
        if (optsDisclosed != null && !SameDisclosure(optsDisclosed, AsList(pres.GetValueOrDefault("disclosed")))) return false;
        foreach (var o in disclosed) IndexOf(o); // an attribute without an integer index fails closed
        var ordered = disclosed.OrderBy(IndexOf).ToList();
        var msgs = ordered.Select(Encode).ToList();
        var idx = ordered.Select(IndexOf).ToList();
        double count = pres.GetValueOrDefault("messageCount") is Num mc && double.TryParse(mc.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var c) ? c : double.NaN;
        foreach (var i in idx) if (i >= count || i < 0) return false;
        return Bbs.ProofVerify(pk, proof, header, ph, msgs, idx);
    }
}
