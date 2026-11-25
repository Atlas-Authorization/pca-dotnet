using System.Text;
using AtlasPca.InteropJs;
using J = AtlasPca.Jose.Jose;
using JoseException = AtlasPca.Jose.JoseException;
using JoseTypeError = AtlasPca.Jose.JoseTypeError;
using CanonicalJws = AtlasPca.Jose.CanonicalJws;
using CanonicalJwsException = AtlasPca.Jose.CanonicalJwsException;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.A2aPkg;

/// <summary>Detached-payload flattened JWS for A2A Agent Cards and agent-card attestations (the signing primitive behind the reference's
/// FlattenedSign / flattenedVerify use). Keys are JWK maps. Profiles: the legacy detached profile (<c>b64:false</c>, <c>crit:["b64"]</c>) and
/// the A2A 1.0 section 8.4 profile (payload base64url in the signing input, <c>typ:"JOSE"</c>). Verification gates the protected and signature
/// segments for canonical spelling first, then applies the JOSE rules (alg, crit, b64) and key selection (one key, or a JWKS matched by
/// kid / alg / kty).</summary>
public static class A2aJws
{
    /// <summary>Sign <paramref name="payload"/>; returns <c>{protected, signature}</c>. <paramref name="header"/> members follow <c>kid</c> in the protected header.</summary>
    public static D SignDetached(byte[] payload, D jwk, string alg, string? kid, bool standardPayload, D? header)
    {
        var key = J.ImportJwk(jwk, alg); // the reference imports a plain JWK first
        var prot = new D { ["alg"] = alg };
        if (standardPayload) prot["typ"] = "JOSE";
        else { prot["b64"] = false; prot["crit"] = new L { "b64" }; }
        if (kid != null) prot["kid"] = kid;
        if (header != null) foreach (var (k, v) in header) prot[k] = v;
        var protectedB64 = J.B64u(J.Utf8(J.Stringify(prot)));
        var sig = J.SignRaw(alg, key, SigningInput(protectedB64, payload, standardPayload));
        return new D { ["protected"] = protectedB64, ["signature"] = J.B64u(sig) };
    }

    static byte[] SigningInput(string protectedB64, byte[] payload, bool b64)
    {
        var p = b64 ? Encoding.ASCII.GetBytes(J.B64u(payload)) : payload;
        return Encoding.ASCII.GetBytes(protectedB64 + ".").Concat(p).ToArray();
    }

    /// <summary>What a verify call resolves its key from.</summary>
    public sealed class Resolver
    {
        internal object? Key;                 // the imported single key (null when a set is used)
        internal Func<D, object?>? Set;       // the JWKS resolver (null when a single key is used)
        internal bool Invalid;                // a key that is not a JWK: passed through, and no signature verifies under it
    }

    /// <summary>Resolve the verification key. A truthy <paramref name="jwks"/> wins over <paramref name="key"/>; neither: "no verification key or JWKS
    /// supplied". A key that is a JWK object is imported with <paramref name="alg"/> (default EdDSA); an import failure is a resolution failure.</summary>
    public static (Resolver? Resolver, string? Error) ResolveVerifyKey(object? jwks, bool hasKey, object? key, string? alg)
    {
        if (JsX.Truthy(jwks))
        {
            try { return (new Resolver { Set = J.CreateLocalJwkSet(jwks) }, null); }
            catch (JoseException e) { return (null, "could not resolve verification key: " + e.Message); }
        }
        if (hasKey)
        {
            if (key is not D jwk || !jwk.ContainsKey("kty")) return (new Resolver { Invalid = true }, null);
            try { return (new Resolver { Key = J.ImportJwk(jwk, alg ?? "EdDSA") }, null); }
            catch (Exception e) when (e is JoseException || e is JoseTypeError) { return (null, "could not resolve verification key: " + e.Message); }
        }
        return (null, "no verification key or JWKS supplied");
    }

    /// <summary>The outcome of a detached verification: <c>Ok</c>, else the <c>Reason</c> (the JOSE library's wording is not reproduced);
    /// <c>ProtectedHeader</c> when ok.</summary>
    public sealed record Result(bool Ok, string? Reason, D? ProtectedHeader)
    {
        internal static Result Fail(string why) => new(false, why, null);
    }

    /// <summary>Verify a detached-payload JWS (<paramref name="sig"/> = <c>{protected, signature}</c>) over <paramref name="payload"/>. Never throws.</summary>
    public static Result VerifyDetached(byte[] payload, object? sig, Resolver resolver)
    {
        try
        {
            if (!(sig is D sd && sd.GetValueOrDefault("protected") is string prot && sd.GetValueOrDefault("signature") is string sg)) return Result.Fail("signature is malformed");
            // canonical-spelling gate BEFORE the JOSE rules (a one-byte payload segment stands in: only the two segments are gated)
            if (prot.Length + sg.Length > J.DefaultMaxJwsBytes) return Result.Fail("non-canonical compact JWS: too-long");
            CanonicalJws gate;
            try { gate = J.AssertCanonicalCompactJws(prot + ".AA." + sg, 3, int.MaxValue, false); }
            catch (CanonicalJwsException e) { return Result.Fail("non-canonical compact JWS: " + e.Reason); }
            var header = gate.Header;
            if (header.GetValueOrDefault("alg") is not string alg || alg.Length == 0) return Result.Fail("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
            bool b64 = true;
            if (header.ContainsKey("crit"))
            {
                const string critMsg = "\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present";
                if (header["crit"] is not L crit || crit.Count == 0) return Result.Fail(critMsg);
                bool b64Listed = false;
                foreach (var c in crit)
                {
                    if (c is not string cs || cs.Length == 0) return Result.Fail(critMsg);
                    if (cs != "b64") return Result.Fail($"Extension Header Parameter \"{cs}\" is not recognized");
                    if (!header.ContainsKey("b64")) return Result.Fail("Extension Header Parameter \"b64\" is missing");
                    b64Listed = true;
                }
                if (b64Listed)
                {
                    if (header["b64"] is not bool bb) return Result.Fail("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
                    b64 = bb;
                }
            }
            // the payload the caller hands over: raw bytes under a header that says b64:false, else base64url text
            bool rawGiven = header.GetValueOrDefault("b64") is bool rb && !rb;
            if (b64 && rawGiven) return Result.Fail("JWS Payload must be a string");
            if (resolver.Invalid) throw new JoseTypeError("Key must be a key object");
            object? key = resolver.Set != null ? resolver.Set(header) : resolver.Key;
            J.CheckKeyType(alg, key);
            byte[] signature = J.DecodeCanonicalBase64Url(sg);
            return J.VerifyWith(alg, key!, signature, SigningInput(prot, payload, b64)) ? new Result(true, null, header) : Result.Fail("signature verification failed");
        }
        catch (Exception e) when (e is JoseException || e is JoseTypeError || e is CanonicalJwsException)
        {
            return Result.Fail(e.Message);
        }
        catch (Exception)
        {
            return Result.Fail("signature verification failed");
        }
    }
}
