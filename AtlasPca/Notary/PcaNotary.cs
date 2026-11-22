using System.Text;
using AtlasPca.Js;
using static AtlasPca.Explain.ExplainJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Notary;

/// <summary>A notary's signing key pair: the Ed25519 seed and the public key whose b64u form becomes <c>attestation.notary</c>.</summary>
public sealed record NotaryKeyPair(byte[] SecretKey, byte[] PublicKey);

/// <summary>Options of <see cref="PcaNotary.NotarizeResponse"/>. <see cref="ObservedAt"/> is a JSON number (null: now); a
/// <see cref="TextChunkSize"/> of at least 1 commits a string body as chunks of that many characters (floored) instead of one leaf.</summary>
public sealed class NotarizeOptions
{
    public required NotaryKeyPair NotaryKey { get; init; }
    public object? ObservedAt { get; init; }
    public double? TextChunkSize { get; init; }
    /// <summary>Epoch ms clock for a missing <see cref="ObservedAt"/>.</summary>
    public Func<long>? Clock { get; init; }
    /// <summary>The 16-byte hiding salt of each committed leaf as b64u; default random.</summary>
    public Func<string>? Salt { get; init; }
}

/// <summary>External-fact attestation for proof-carrying actions: a notary witnesses one HTTP request/response and signs a canonical record
/// with a salted Merkle commitment to the body, so an agent can later disclose one field with an inclusion proof while every other stays
/// hidden, and bind the fact to one PCActn. The notary is the trust assumption (this is not trustless zkTLS). Everything fails closed.
/// Attestations, witnesses, disclosures, sessions and caveats are JSON trees (maps, lists, strings, <see cref="Num"/>, bool, null).</summary>
public static class PcaNotary
{
    public const string BodyCommitAlg = "salted-merkle-sha256-v1";
    public const string AttestedFactCaveat = "attested_fact";
    const string NotaryDomain = "atlas-pca/notary/v1\0";

    // ---- helpers --------------------------------------------------------------------------------------------------------

    static bool CanonicalEqual(object? a, object? b)
    {
        try { return Pca.HashCanonical(a) == Pca.HashCanonical(b); }
        catch (Exception) { return false; }
    }

    static bool NumEq(object? a, object? b) => a is Num x && b is Num y && JsJson.ToJsNumber(x) == JsJson.ToJsNumber(y);

    static Num NumOf(long n) => new(n.ToString(System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>Normalize a public-key input to its b64u form: a string as is, bytes, or a key pair (a <see cref="NotaryKeyPair"/> or a map with a
    /// <c>publicKey</c> of bytes). Anything else throws.</summary>
    static string ToPubB64u(object? key)
    {
        switch (key)
        {
            case string s: return s;
            case byte[] b: return Pca.B64u(b);
            case NotaryKeyPair kp: return Pca.B64u(kp.PublicKey);
            default:
                var pk = G(key, "publicKey");
                if (pk is byte[] pb) return Pca.B64u(pb);
                throw new InvalidOperationException("radix2.encode input should be Uint8Array");
        }
    }

    sealed record BareLeaf(L Path, object? Value);

    static L Extend(L prefix, object? seg) { var p = new L(prefix) { seg }; return p; }

    static void Flatten(object? value, L prefix, List<BareLeaf> outp)
    {
        if (value is L l)
        {
            if (l.Count == 0) { outp.Add(new BareLeaf(prefix, new L())); return; }
            for (int i = 0; i < l.Count; i++) Flatten(l[i], Extend(prefix, NumOf(i)), outp);
            return;
        }
        if (value is D m)
        {
            var keys = m.Keys.ToList();
            keys.Sort(IntentJs.CompareUtf8);
            if (keys.Count == 0) { outp.Add(new BareLeaf(prefix, new D())); return; }
            foreach (var k in keys) Flatten(m[k], Extend(prefix, k), outp);
            return;
        }
        outp.Add(new BareLeaf(prefix, value));
    }

    /// <summary>Split a string into chunks of <paramref name="size"/> code points (a surrogate pair is never split).</summary>
    static List<BareLeaf> ChunkString(string s, double size)
    {
        var chars = new List<string>();
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { chars.Add(s.Substring(i, 2)); i++; }
            else chars.Add(s[i].ToString());
        }
        if (chars.Count == 0) return new List<BareLeaf> { new(new L { "#chunk", NumOf(0) }, "") };
        var outp = new List<BareLeaf>();
        var step = size >= chars.Count ? chars.Count : (int)size;
        for (int i = 0, idx = 0; i < chars.Count; i += step, idx++)
            outp.Add(new BareLeaf(new L { "#chunk", NumOf(idx) }, string.Concat(chars.Skip(i).Take(step))));
        return outp;
    }

    /// <summary>The object committed per leaf: <c>{p, v, s}</c>.</summary>
    static D LeafObject(object? path, object? value, object? salt) => new() { ["p"] = path, ["v"] = value, ["s"] = salt };

    static string RequestHeadersDigest(object? headers)
    {
        var norm = new D();
        if (headers is D h) foreach (var kv in h) norm[kv.Key.ToLowerInvariant()] = kv.Value;
        return Pca.HashCanonical(norm);
    }

    // ---- Merkle proof (RFC 6962 split) ----------------------------------------------------------------------------------

    static void Prove(List<byte[]> hs, int idx, L outp)
    {
        if (hs.Count == 1) return;
        int k = (int)Pca.Split(hs.Count);
        if (idx < k)
        {
            Prove(hs.GetRange(0, k), idx, outp);
            outp.Add(new D { ["side"] = "R", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(k, hs.Count - k))) });
        }
        else
        {
            Prove(hs.GetRange(k, hs.Count - k), idx - k, outp);
            outp.Add(new D { ["side"] = "L", ["hash"] = Pca.B64u(Pca.Build(hs.GetRange(0, k))) });
        }
    }

    /// <summary>The inclusion proof <c>{index, size, path}</c> of leaf <paramref name="index"/> in the Merkle tree over <paramref name="leaves"/>.</summary>
    static D MerkleProof(List<object?> leaves, int index)
    {
        if (index < 0 || index >= leaves.Count) throw new ArgumentOutOfRangeException(nameof(index), "merkleProof: index out of range");
        var path = new L();
        Prove(leaves.Select(Pca.LeafHash).ToList(), index, path);
        return new D { ["index"] = NumOf(index), ["size"] = NumOf(leaves.Count), ["path"] = path };
    }

    // ---- notaryMessage ---------------------------------------------------------------------------------------------------

    /// <summary>The canonical bytes the notary signs: <c>NOTARY_DOMAIN || sha256(canonical(session))</c>.</summary>
    public static byte[] NotaryMessage(object? session)
    {
        var d = Pca.Sha(Encoding.UTF8.GetBytes(Pca.Canonicalize(session)));
        return Pca.Cat(Encoding.UTF8.GetBytes(NotaryDomain), d);
    }

    // ---- notarizeResponse ------------------------------------------------------------------------------------------------

    /// <summary>Witness a request/response (<c>{request:{method,url,headers?}, response:{status, body}}</c>) and produce the signed attestation plus the
    /// prover's private opening witness (keep it private; it is what <see cref="DiscloseField"/> takes).</summary>
    public static (D Attestation, D Witness) NotarizeResponse(object? input, NotarizeOptions opts)
    {
        var request = G(input, "request");
        var response = G(input, "response");
        if (!(G(request, "method") is string method && method.Length > 0)) throw new ArgumentException("notarizeResponse: request.method is required");
        if (!(G(request, "url") is string url && url.Length > 0)) throw new ArgumentException("notarizeResponse: request.url is required");
        var status = G(response, "status");
        if (!IntentJs.IsSafeInteger(status)) throw new ArgumentException("notarizeResponse: response.status must be an integer");

        var body = G(response, "body");
        var bare = new List<BareLeaf>();
        if (body is string text && opts.TextChunkSize is double cs && cs >= 1) bare = ChunkString(text, Math.Floor(cs));
        else Flatten(Nullish(body) ? null : body, new L(), bare);

        var salt = opts.Salt ?? (() => Pca.B64u(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)));
        var leaves = bare.Select(l => new D { ["path"] = l.Path, ["value"] = l.Value, ["salt"] = salt() }).ToList();
        var root = Pca.MerkleRoot(leaves.Select(l => (object?)LeafObject(l["path"], l["value"], l["salt"])).ToList());

        var session = new D
        {
            ["v"] = new Num("1"),
            ["method"] = method.ToUpperInvariant(),
            ["url"] = url,
            ["requestHeadersDigest"] = RequestHeadersDigest(Q(request, "headers")),
            ["responseStatus"] = status,
            ["responseBodyCommit"] = new D { ["alg"] = BodyCommitAlg, ["root"] = root, ["size"] = NumOf(leaves.Count) },
            ["observedAt"] = opts.ObservedAt ?? NumOf((opts.Clock ?? (() => AtlasPca.ReplayClock.NowMs()))()),
        };

        using var key = EdKey.FromSeed(opts.NotaryKey.SecretKey);
        var attestation = new D
        {
            ["session"] = session,
            ["notary"] = Pca.B64u(opts.NotaryKey.PublicKey),
            ["sig"] = Pca.B64u(key.Sign(NotaryMessage(session))),
        };
        return (attestation, new D { ["session"] = session, ["leaves"] = leaves.Cast<object?>().ToList() });
    }

    // ---- discloseField ---------------------------------------------------------------------------------------------------

    /// <summary>A redactable disclosure of ONE response field: the opened leaf and its Merkle inclusion proof. <paramref name="path"/> is a list of
    /// segments or a bare string (one top-level key). Throws when the path names no committed leaf.</summary>
    public static D DiscloseField(object? attestation, object? witness, object? path)
    {
        object want = path switch
        {
            string s => new L { s },
            L l => new L(l),
            _ => throw new InvalidOperationException("path.slice is not a function"),
        };
        if (G(witness, "leaves") is not L leaves) throw new InvalidOperationException("witness.leaves.findIndex is not a function");
        int idx = -1;
        for (int i = 0; i < leaves.Count; i++) if (CanonicalEqual(G(leaves[i], "path"), want)) { idx = i; break; }
        if (idx < 0) throw new InvalidOperationException($"discloseField: no committed field at path {JsJson.Stringify(want)}");
        var leaf = leaves[idx];
        var proof = MerkleProof(leaves.Select(l => (object?)LeafObject(G(l, "path"), G(l, "value"), G(l, "salt"))).ToList(), idx);
        var d = new D();
        foreach (var (k, src) in new[] { ("path", "path"), ("value", "value"), ("salt", "salt") })
        {
            var v = G(leaf, src);
            if (!IsUndef(v)) d[k] = v;
        }
        d["proof"] = proof;
        return d;
    }

    // ---- verification (fail closed) ---------------------------------------------------------------------------------------

    static bool ValidCommit(object? c)
    {
        if (!IsObject(c)) return false;
        return Q(c, "alg") is string a && a == BodyCommitAlg
            && Q(c, "root") is string root && Pca.B64uDecode(root, 32) != null
            && IntentJs.IsSafeInteger(Q(c, "size")) && JsJson.ToJsNumber(Q(c, "size")) >= 1;
    }

    static bool ValidSession(object? s)
    {
        if (!IsObject(s)) return false;
        return NumEq(Q(s, "v"), new Num("1"))
            && Q(s, "method") is string && Q(s, "url") is string && Q(s, "requestHeadersDigest") is string
            && IntentJs.IsInt(Q(s, "responseStatus")) && IntentJs.IsInt(Q(s, "observedAt"))
            && ValidCommit(Q(s, "responseBodyCommit"));
    }

    /// <summary>Verify the notary signature AND the session's structural integrity. <paramref name="notaryKey"/> is the TRUSTED notary's public key
    /// (b64u string, bytes, or key pair); the recorded signer must equal it and the signature must verify over the canonical session.</summary>
    public static bool VerifyNotaryAttestation(object? attestation, object? notaryKey)
    {
        try
        {
            if (!IsObject(attestation)) return false;
            var session = Q(attestation, "session");
            if (!ValidSession(session)) return false;
            if (Q(attestation, "notary") is not string notary || Q(attestation, "sig") is not string sig) return false;
            var expected = ToPubB64u(notaryKey);
            if (notary != expected) return false; // the recorded signer must be the trusted notary
            return IntentJs.VerifyEd(notary, NotaryMessage(session), sig);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Verify a disclosed field: the attestation is authentic AND the disclosed leaf is included under the attested body root at a position
    /// consistent with the committed size. A lie about the value, path or salt breaks inclusion.</summary>
    public static bool VerifyDisclosedField(object? attestation, object? disclosure, object? notaryKey)
    {
        try
        {
            if (!VerifyNotaryAttestation(attestation, notaryKey)) return false;
            if (!IsObject(disclosure)) return false;
            if (Q(disclosure, "path") is not L || Q(disclosure, "salt") is not string) return false;
            var proof = Q(disclosure, "proof");
            if (!IsObject(proof) || Q(proof, "path") is not L) return false;
            var commit = G(G(attestation, "session"), "responseBodyCommit");
            if (!NumEq(Q(proof, "size"), Q(commit, "size"))) return false; // bind the proof to the committed leaf count
            var leaf = LeafObject(Q(disclosure, "path"), Q(disclosure, "value"), Q(disclosure, "salt"));
            return Pca.VerifyInclusion((string)Q(commit, "root")!, proof as D, leaf);
        }
        catch (Exception) { return false; }
    }

    // ---- PCA binding -----------------------------------------------------------------------------------------------------

    /// <summary>A stable digest identifying this attested FACT (independent of any PCActn binding).</summary>
    public static string FactRef(object? attestation) => Pca.HashCanonical(new D
    {
        ["fact"] = "atlas-pca-notary/v1",
        ["session"] = G(attestation, "session"),
        ["notary"] = G(attestation, "notary"),
        ["sig"] = G(attestation, "sig"),
    });

    /// <summary>Bind an attested fact to a PCActn by stamping the action's digest into a copy of the attestation.</summary>
    public static D BindFactToPcActn(object? attestation, object? pcActn)
    {
        var d = new D();
        if (attestation is D a) foreach (var kv in a) d[kv.Key] = kv.Value;
        d["fact_binding"] = new D { ["pcactn_digest"] = Pca.HashCanonical(pcActn) };
        return d;
    }

    /// <summary>True iff the fact is bound to the PCActn in BOTH directions: the fact names the action (<c>fact_binding.pcactn_digest</c>) AND the action
    /// commits to the fact (<c>provenance.trusted_refs</c> includes <see cref="FactRef"/>). Fails closed.</summary>
    public static bool FactMatchesPcActn(object? attestation, object? pcActn)
    {
        try
        {
            var binding = G(attestation, "fact_binding");
            if (!Truthy(binding) || G(binding, "pcactn_digest") is not string digest) return false;
            if (digest != Pca.HashCanonical(pcActn)) return false;
            if (Q(G(pcActn, "provenance"), "trusted_refs") is not L refs) return false;
            var fr = FactRef(attestation);
            return refs.Any(r => r is string s && s == fr);
        }
        catch (Exception) { return false; }
    }

    // ---- the attested_fact caveat ------------------------------------------------------------------------------------------

    /// <summary>Build an <c>attested_fact</c> caveat from <c>{notary, path, equals, url?, bindToPcActn?}</c>; <c>notary</c> may be a b64u string, bytes
    /// or a key pair.</summary>
    public static D RequireAttestedFact(object? opts)
    {
        // a string has .slice() too: it would pass as a one-segment path that no disclosure ever matches
        if (G(opts, "path") is not L segments) throw new InvalidOperationException("requireAttestedFact: path must be an array of segments");
        var d = new D { ["type"] = AttestedFactCaveat, ["notary"] = ToPubB64u(G(opts, "notary")) };
        d["path"] = new L(segments);
        var eq = G(opts, "equals"); if (!IsUndef(eq)) d["equals"] = eq;
        var url = Q(opts, "url"); if (!IsUndef(url)) d["url"] = url;
        var bind = Q(opts, "bindToPcActn"); if (!IsUndef(bind)) d["bindToPcActn"] = bind;
        return d;
    }

    /// <summary>Type guard: a bare caveat object is an <c>attested_fact</c> caveat.</summary>
    public static bool IsAttestedFactCaveat(object? cv) =>
        IsObject(cv) && Q(cv, "type") is string t && t == AttestedFactCaveat && Q(cv, "notary") is string && Q(cv, "path") is L;

    /// <summary>True iff <paramref name="key"/> is listed in <paramref name="ring"/> (a list of <c>{key, notBefore?, notAfter?, revoked?}</c>), not revoked,
    /// and <paramref name="observedAt"/> lies in one listed window <c>[notBefore, notAfter)</c>.</summary>
    public static bool NotaryKeyUsable(object? ring, object? key, object? observedAt)
    {
        if (ring is not L entries || observedAt is not Num || !IntentJs.IsSafeInteger(observedAt)) return false;
        var mine = entries.Where(e => Truthy(e) && StrictEq(Q(e, "key"), key)).ToList();
        if (mine.Count == 0) return false;
        return mine.All(e => !(Q(e, "revoked") is true))
            && mine.Any(e => (IsUndef(Q(e, "notBefore")) || Le(Q(e, "notBefore"), observedAt)) && (IsUndef(Q(e, "notAfter")) || Lt(observedAt, Q(e, "notAfter"))));
    }

    static bool StrictEq(object? a, object? b)
    {
        if (IsUndef(a) || IsUndef(b)) return IsUndef(a) && IsUndef(b);
        return a switch
        {
            string x => b is string y && x == y,
            Num x => b is Num y && JsJson.ToJsNumber(x) == JsJson.ToJsNumber(y),
            bool x => b is bool y && x == y,
            null => b == null,
            _ => ReferenceEquals(a, b),
        };
    }

    /// <summary>Evaluate with the default policy <c>{}</c>.</summary>
    public static D EvaluateAttestedFactCaveat(object? caveat, object? evidence) => EvaluateAttestedFactCaveat(caveat, evidence, new D());

    /// <summary>Evaluate an <c>attested_fact</c> caveat against <c>{attestation, disclosure, pcActn?}</c>. Admits only when, failing closed at every step:
    /// the attestation is authentic under the caveat's notary; (when <c>policy.keyring</c>) the key is trusted for the observation time; (when
    /// <c>policy.maxAgeMs</c>) it is fresh; (when the caveat names a <c>url</c>) the URL matches; the disclosed field verifies; its path and value equal the
    /// caveat's; and (when <c>bindToPcActn</c>) the fact is two-way bound to the supplied PCActn. Returns <c>{ok, reason?, trust?}</c>. <paramref name="policy"/>
    /// is <c>{now?, maxAgeMs?, keyring?}</c> (default <c>{}</c>); <paramref name="clock"/> supplies <c>now</c> when the policy has none.</summary>
    public static D EvaluateAttestedFactCaveat(object? caveat, object? evidence, object? policy, Func<long>? clock = null)
    {
        D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            if (!IsObject(caveat) || !(Q(caveat, "type") is string ct && ct == AttestedFactCaveat)) return Fail("not an attested_fact caveat");
            if (Q(caveat, "notary") is not string notary || Q(caveat, "path") is not L) return Fail("caveat is malformed (notary/path)");
            if (Nullish(evidence)) throw new InvalidOperationException($"Cannot destructure property 'attestation' of 'evidence' as it is {(evidence == null ? "null" : "undefined")}.");
            var attestation = Q(evidence, "attestation");
            var disclosure = Q(evidence, "disclosure");
            var pcActn = Q(evidence, "pcActn");
            if (!VerifyNotaryAttestation(attestation, notary)) return Fail("notary attestation does not verify (fail closed)");
            var session = G(attestation, "session");
            var keyring = G(policy, "keyring");
            if (!IsUndef(keyring) && !NotaryKeyUsable(keyring, G(attestation, "notary"), G(session, "observedAt")))
                return Fail("notary key is not trusted for this observation time (unlisted, revoked or out of window)");
            var maxAge = G(policy, "maxAgeMs");
            if (!IsUndef(maxAge))
            {
                var nowV = G(policy, "now");
                object now = Nullish(nowV) ? NumOf((clock ?? (() => AtlasPca.ReplayClock.NowMs()))()) : nowV!;
                var age = Sub(now, G(session, "observedAt"));
                bool finiteMax = maxAge is Num && double.IsFinite(JsJson.ToJsNumber(maxAge));
                bool finiteNow = now is Num && double.IsFinite(JsJson.ToJsNumber(now));
                if (!finiteMax || !finiteNow || !(age >= 0 && age <= JsJson.ToJsNumber(maxAge))) return Fail("attestation is stale or from the future");
            }
            var url = Q(caveat, "url");
            if (!IsUndef(url) && !StrictEq(G(session, "url"), url)) return Fail("attested session URL does not match the caveat");
            if (!VerifyDisclosedField(attestation, disclosure, notary)) return Fail("disclosed field does not verify under the attested root");
            if (!CanonicalEqual(G(disclosure, "path"), Q(caveat, "path"))) return Fail("disclosed field is not the path the caveat requires");
            if (!CanonicalEqual(G(disclosure, "value"), Q(caveat, "equals"))) return Fail("disclosed field value does not satisfy the caveat");
            if (Truthy(Q(caveat, "bindToPcActn")))
            {
                if (!Truthy(pcActn)) return Fail("caveat requires PCActn binding but no PCActn was supplied");
                if (!FactMatchesPcActn(attestation, pcActn)) return Fail("fact is not bound to this PCActn");
            }
            return new D { ["ok"] = true, ["trust"] = "notary-trusted" };
        }
        catch (Exception e) { return Fail($"attested_fact evaluation error (fail closed): {e.Message}"); }
    }
}
