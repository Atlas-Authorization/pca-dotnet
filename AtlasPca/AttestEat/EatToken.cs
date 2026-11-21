// Building and verifying an entity attestation token (RFC 9711, a compact JWS with typ eat+jwt) signed with EdDSA or ES256, and the join of a verified token's
// image measurement to a release digest.
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.AttestEat;

/// <summary>A signing or verification key of an EAT: Ed25519 (EdDSA) or P-256 (ES256).</summary>
public sealed class EatKey
{
    public string Alg { get; }
    readonly byte[]? edSeed, edPub;
    readonly ECDsa? ec;
    EatKey(string alg, byte[]? edSeed, byte[]? edPub, ECDsa? ec) { Alg = alg; this.edSeed = edSeed; this.edPub = edPub; this.ec = ec; }

    public static EatKey Ed25519Private(byte[] seed) => new("EdDSA", seed, new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded(), null);
    public static EatKey Ed25519Public(byte[] pub) => pub.Length == 32 ? new("EdDSA", null, pub, null) : throw new ArgumentException("an Ed25519 public key is 32 bytes");
    public static EatKey Es256Private(byte[] d, byte[] x, byte[] y) => new("ES256", null, null, ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, D = d, Q = new ECPoint { X = x, Y = y } }));
    public static EatKey Es256Public(byte[] x, byte[] y) => new("ES256", null, null, ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } }));

    /// <summary>Generate a signing key for <paramref name="alg"/> (<c>EdDSA</c>: Ed25519, <c>ES256</c>: P-256); anything else throws. The key also verifies; hand
    /// <see cref="PublicOnly"/> to a verifier.</summary>
    public static EatKey Generate(string alg = "EdDSA") => alg switch
    {
        "EdDSA" => Ed25519Private(RandomNumberGenerator.GetBytes(32)),
        "ES256" => FromEc(ECDsa.Create(ECCurve.NamedCurves.nistP256)),
        _ => throw new ArgumentException($"generateEatKeyPair: unsupported alg '{alg}'"),
    };

    static EatKey FromEc(ECDsa k) => new("ES256", null, null, k);

    /// <summary>The verification-only form of this key (no private material).</summary>
    public EatKey PublicOnly()
    {
        if (ec == null) return Ed25519Public(edPub!);
        var q = ec.ExportParameters(false).Q;
        return Es256Public(q.X!, q.Y!);
    }

    internal byte[] Sign(string alg, byte[] data)
    {
        if (alg != Alg) throw new AtlasPca.Grants.CodedException("ERR_OSSL_INVALID_DIGEST", $"a {Alg} key cannot sign {alg}");
        if (alg == "EdDSA")
        {
            if (edSeed == null) throw new InvalidOperationException("a public key cannot sign");
            var s = new Ed25519Signer();
            s.Init(true, new Ed25519PrivateKeyParameters(edSeed, 0));
            s.BlockUpdate(data, 0, data.Length);
            return s.GenerateSignature();
        }
        return ec!.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    internal bool Verify(string alg, byte[] data, byte[] sig)
    {
        if (alg != Alg) throw new AtlasPca.Grants.CodedException("ERR_OSSL_INVALID_DIGEST", $"a {Alg} key cannot verify {alg}");
        if (alg == "EdDSA")
        {
            if (sig.Length != 64) return false;
            var s = new Ed25519Signer();
            s.Init(false, new Ed25519PublicKeyParameters(edPub!, 0));
            s.BlockUpdate(data, 0, data.Length);
            return s.VerifySignature(sig);
        }
        return ec!.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}

/// <summary>A server-issued, single-use freshness challenge: the opaque <see cref="Value"/> the attester echoes into the token's <c>eat_nonce</c> and the time it was issued (epoch ms).</summary>
public sealed record IssuedNonce(string Value, double IssuedAt);

public static class EatToken
{
    /// <summary>Mint a fresh nonce for an attestation challenge: random AND time-stamped (the issue time, base 36, after a <c>.</c>), so a verifier can also bound the nonce's
    /// own age. <paramref name="bytes"/> is the random length (at least 16, default 32). The server should still remember and consume it once. A fractional <paramref name="now"/>
    /// is truncated to whole milliseconds in the value.</summary>
    public static IssuedNonce IssueNonce(double? now = null, int? bytes = null)
    {
        var at = now is double n && double.IsFinite(n) ? n : (double)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var len = Math.Max(16, bytes ?? 32);
        return new IssuedNonce(Pca.B64u(RandomNumberGenerator.GetBytes(len)) + "." + Base36((long)Math.Truncate(at)), at);
    }

    static string Base36(long v)
    {
        if (v == 0) return "0";
        var neg = v < 0;
        var u = neg ? (ulong)(-v) : (ulong)v;
        var sb = new StringBuilder();
        while (u > 0) { sb.Insert(0, "0123456789abcdefghijklmnopqrstuvwxyz"[(int)(u % 36)]); u /= 36; }
        return neg ? "-" + sb : sb.ToString();
    }


    static readonly string[] SupportedAlgs = { "EdDSA", "ES256" };
    internal static readonly string[] DbgstatValues = { "enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently" };
    const int MaxEatBytes = 1 << 20;

    static D Obj(params (string, object?)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static object? P(object? o, string k) => Jx.Prop(o, k);
    static bool Def(object? x) => !Jx.IsUndef(x);
    static string B64Utf8(string s) => Pca.B64u(Encoding.UTF8.GetBytes(s));

    /// <summary>Builds and signs an EAT. <paramref name="args"/>: <c>issuer</c>, <c>nonce</c>, <c>alg?</c> (EdDSA default), <c>channelId?</c> and/or <c>channelBinding?</c>
    /// (at least one binding is required: unbound evidence is never emitted), <c>measured?</c>, <c>sevsnp?</c>, <c>measurements?</c>, <c>ueid?</c>, <c>sueid?</c>,
    /// <c>dbgstat?</c>, <c>oemid?</c>, <c>now?</c> (epoch ms).</summary>
    public static string BuildEat(object? args, EatKey key)
    {
        if (P(args, "issuer") is not string issuer || issuer.Length == 0) throw new ArgumentException("buildEAT: issuer is required");
        if (P(args, "nonce") is not string nonce || nonce.Length == 0) throw new ArgumentException("buildEAT: nonce (eat_nonce) is required for freshness");
        var algO = P(args, "alg");
        var alg = algO == null || Jx.IsUndef(algO) ? "EdDSA" : algO;
        if (alg is not string algS || !SupportedAlgs.Contains(algS)) throw new ArgumentException($"buildEAT: unsupported alg '{JsX.Str(alg)}'");

        string? exporter = null, jkt = null;
        var cid = P(args, "channelId");
        if (Def(cid)) exporter = (string)PcaAttestEat.DeriveChannelCnf(cid)["tls_exporter"]!;
        var cb = P(args, "channelBinding");
        if (Def(cb))
        {
            if (P(cb, "tls_exporter") is string te) exporter = te;
            if (P(cb, "jkt") is string jk) jkt = jk;
        }
        if (exporter == null && jkt == null)
            throw new ArgumentException("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence");
        var iatMs = Jx.Fin(P(args, "now")) is double nd ? nd : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        var cnf = new D();
        if (exporter != null) cnf["tls_exporter"] = exporter;
        if (jkt != null) cnf["jkt"] = jkt;
        var claims = Obj(("iss", issuer), ("iat", Jx.NumOut(Math.Floor(iatMs / 1000))), ("eat_nonce", nonce), ("cnf", cnf));
        foreach (var k in new[] { "ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp" })
        {
            var v = P(args, k);
            if (Def(v)) claims[k] = v;
        }
        var signingInput = B64Utf8(AtlasPca.Js.JsJson.Stringify(Obj(("alg", algS), ("typ", PcaAttestEat.EatTyp)))) + "." + B64Utf8(AtlasPca.Js.JsJson.Stringify(claims));
        return signingInput + "." + Pca.B64u(key.Sign(algS, Encoding.UTF8.GetBytes(signingInput)));
    }

    static string NormalizeTyp(string typ)
    {
        var t = typ.ToLowerInvariant();
        return t.Contains('/') ? t : "application/" + t;
    }

    static D? ParseCnf(object? v)
    {
        if (v is not D) return null;
        var o = new D();
        if (P(v, "tls_exporter") is string te) o["tls_exporter"] = te;
        if (P(v, "jkt") is string jk) o["jkt"] = jk;
        return o.Count == 0 ? null : o;
    }

    static L? ParseMeasurements(object? v)
    {
        if (v is not L l) return null;
        var o = new L();
        foreach (var e in l) if (e is D && P(e, "type") is string t && P(e, "value") is string val) o.Add(Obj(("type", t), ("value", val)));
        return o.Count > 0 ? o : null;
    }

    static object? ParseTcb(object? v)
    {
        if (Jx.Fin(v) != null) return v;
        if (v is string) return v;
        if (v is D)
        {
            var o = new D();
            foreach (var k in new[] { "bootloader", "tee", "snp", "microcode" }) if (Jx.IsNum(P(v, k))) o[k] = P(v, k);
            return o;
        }
        return Jx.Undef;
    }

    static D? ParseMeasured(object? v)
    {
        if (v is not D) return null;
        if (P(v, "model_id") is not string m || P(v, "weights_digest") is not string w || P(v, "runtime_measurement") is not string r || P(v, "operator") is not string op) return null;
        var o = Obj(("model_id", m), ("weights_digest", w), ("runtime_measurement", r), ("operator", op));
        if (P(v, "weights_measured") is bool wm) o["weights_measured"] = wm;
        if (P(v, "system_prompt_digest") is string sp) o["system_prompt_digest"] = sp;
        if (P(v, "tool_manifest_digest") is string tm) o["tool_manifest_digest"] = tm;
        return o;
    }

    static D? ParseSevSnp(object? v)
    {
        if (v is not D || !Jx.IsNum(P(v, "version")) || P(v, "measurement") is not string meas) return null;
        var o = Obj(("version", P(v, "version")), ("measurement", meas));
        var tcb = ParseTcb(P(v, "reported_tcb"));
        if (Def(tcb)) o["reported_tcb"] = tcb;
        if (Jx.IsNum(P(v, "guest_svn"))) o["guest_svn"] = P(v, "guest_svn");
        if (P(v, "chip_id") is string chip) o["chip_id"] = chip;
        if (P(v, "debug") is bool dbg) o["debug"] = dbg;
        if (P(v, "degraded") is bool deg) o["degraded"] = deg;
        return o;
    }

    /// <summary>Verifies a compact EAT and returns its claims: the canonical-spelling gate, the header (a supported <c>alg</c> in the allowed set, the <c>typ</c>), the signature
    /// under <paramref name="key"/>, then the claims (<c>iss</c> a string, <c>iat</c> a finite number, an optional issuer allowlist). Anything else throws. Options: <c>issuer?</c>
    /// (string or list), <c>algorithms?</c>, <c>typ?</c>, <c>requireTyp?</c>.</summary>
    public static D VerifyEat(object? eat, EatKey key, object? opts = null)
    {
        opts ??= new D();
        if (eat is not string token) throw new ArgumentException("EAT invalid: token is not a string");
        AtlasPca.Jose.CanonicalJws cj;
        try { cj = J.AssertCanonicalCompactJws(token, 3, MaxEatBytes, true); }
        catch (AtlasPca.Jose.CanonicalJwsException e) { throw new ArgumentException("EAT invalid: " + e.Message); }
        var header = cj.Header;
        if (!(header.GetValueOrDefault("alg") is string alg && SupportedAlgs.Contains(alg))) throw new ArgumentException("EAT invalid: missing or unsupported `alg` header");
        var allowedO = P(opts, "algorithms");
        var allowedOk = allowedO == null || Jx.IsUndef(allowedO) ? true
            : allowedO is L al ? al.Any(x => x is string xs && xs == alg)
            : allowedO is string asr ? asr.Contains(alg, StringComparison.Ordinal)
            : throw new InvalidOperationException("TypeError: allowed.includes is not a function");
        if (!allowedOk) throw new ArgumentException($"EAT invalid: alg {alg} not in the allowed set");
        if (!(P(opts, "requireTyp") is false))
        {
            var wantO = P(opts, "typ");
            var want = wantO == null || Jx.IsUndef(wantO) ? PcaAttestEat.EatTyp : wantO;
            if (header.GetValueOrDefault("typ") is not string htyp || (want is string ws ? NormalizeTyp(htyp) != NormalizeTyp(ws) : throw new InvalidOperationException("TypeError: typ.toLowerCase is not a function")))
                throw new ArgumentException($"EAT invalid: typ {JsX.Str(header.GetValueOrDefault("typ"))} is not {JsX.Str(want)}");
        }
        var segs = cj.Segments;
        if (!key.Verify(alg, Encoding.UTF8.GetBytes(segs[0] + "." + segs[1]), Pca.B64uDecode(segs[2]) ?? throw new ArgumentException("EAT invalid: signature does not verify")))
            throw new ArgumentException("EAT invalid: signature does not verify");
        var payload = cj.Payload ?? throw new ArgumentException("EAT invalid: payload is not an object");
        if (payload.GetValueOrDefault("iss") is not string iss) throw new ArgumentException("EAT invalid: missing or non-string `iss`");
        if (Jx.Fin(payload.GetValueOrDefault("iat")) == null) throw new ArgumentException("EAT invalid: missing or non-numeric `iat`");
        var issuerO = P(opts, "issuer");
        if (Def(issuerO))
        {
            var allowedIss = issuerO is L il ? il : new L { issuerO };
            if (!allowedIss.Any(x => x is string xs && xs == iss)) throw new ArgumentException($"EAT invalid: iss {iss} is not an accepted issuer");
        }
        var claims = Obj(("iss", iss), ("iat", payload["iat"]));
        if (payload.GetValueOrDefault("eat_nonce") is string nonce) claims["eat_nonce"] = nonce;
        if (ParseCnf(payload.GetValueOrDefault("cnf")) is { } cnf) claims["cnf"] = cnf;
        if (payload.GetValueOrDefault("ueid") is string ueid) claims["ueid"] = ueid;
        if (payload.GetValueOrDefault("sueid") is string sueid) claims["sueid"] = sueid;
        if (ParseMeasurements(payload.GetValueOrDefault("measurements")) is { } ms) claims["measurements"] = ms;
        if (payload.GetValueOrDefault("dbgstat") is string dbg && DbgstatValues.Contains(dbg)) claims["dbgstat"] = dbg;
        if (payload.GetValueOrDefault("oemid") is string oem) claims["oemid"] = oem;
        if (ParseMeasured(payload.GetValueOrDefault("measured")) is { } measured) claims["measured"] = measured;
        if (ParseSevSnp(payload.GetValueOrDefault("sevsnp")) is { } sev) claims["sevsnp"] = sev;
        return claims;
    }

    static bool IsLowerHex(string s, int len) => s.Length == len && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>The digest a verified token's measurement slot (default <c>image</c>) names, as <c>{alg, digest}</c>, or null: the verdict must be ok with claims, the slot
    /// must occur exactly once, and its value must be lowercase hex of the algorithm's length (no case folding). Options: <c>slot?</c>, <c>alg?</c> (sha256 default).</summary>
    public static D? RuntimeDigestFromEat(object? verdict, object? o = null)
    {
        o ??= new D();
        if (verdict == null || !(P(verdict, "ok") is true) || !Jx.Truthy(P(verdict, "claims"))) return null;
        var slotO = P(o, "slot"); var algO = P(o, "alg");
        var slot = slotO == null || Jx.IsUndef(slotO) ? "image" : slotO;
        var alg = algO == null || Jx.IsUndef(algO) ? "sha256" : algO;
        var ms = P(P(verdict, "claims"), "measurements");
        var list = ms == null || Jx.IsUndef(ms) ? new L() : ms as L ?? throw new InvalidOperationException("TypeError: measurements.filter is not a function");
        var hits = list.Where(m => JsX.StrictEq(P(m, "type"), slot)).ToList();
        if (hits.Count != 1) return null;
        var v = P(hits[0], "value");
        return v is string s && IsLowerHex(s, alg is string a && a == "sha256" ? 64 : 128) ? Obj(("alg", alg), ("digest", s)) : null;
    }
}
