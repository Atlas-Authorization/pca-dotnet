// SCITT transparency receipts for Proof-Carrying Authority: RFC 9943 (architecture) Signed Statements and RFC 9942 COSE Receipts.
// A Signed Statement is a COSE_Sign1 over a canonical PCActn / verdict; a Receipt is a COSE_Sign1 signed by the Transparency Service
// whose detached payload is the RFC 9162 tree root and whose unprotected header carries the inclusion proof. Verification is fail-closed.
using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtlasPca.Scitt;

/// <summary>A COSE signing or verification key: Ed25519 (alg EdDSA) or ECDSA P-256 (alg ES256, raw IEEE-P1363 r||s).</summary>
public sealed class CoseKey
{
    public string Alg { get; }
    readonly byte[]? _seed, _pub, _d, _x, _y;

    CoseKey(string alg, byte[]? seed, byte[]? pub, byte[]? d, byte[]? x, byte[]? y) { Alg = alg; _seed = seed; _pub = pub; _d = d; _x = x; _y = y; }

    public static CoseKey Ed25519Private(byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("an Ed25519 seed is 32 bytes");
        var s = (byte[])seed.Clone();
        return new("EdDSA", s, new Ed25519PrivateKeyParameters(s, 0).GeneratePublicKey().GetEncoded(), null, null, null);
    }

    public static CoseKey Ed25519Public(byte[] pub) => new("EdDSA", null, (byte[])pub.Clone(), null, null, null);
    public static CoseKey Es256Private(byte[] d, byte[] x, byte[] y) => new("ES256", null, null, (byte[])d.Clone(), (byte[])x.Clone(), (byte[])y.Clone());
    public static CoseKey Es256Public(byte[] x, byte[] y) => new("ES256", null, null, null, (byte[])x.Clone(), (byte[])y.Clone());

    ECParameters Ec() => new()
    {
        Curve = ECCurve.NamedCurves.nistP256,
        Q = new ECPoint { X = _x, Y = _y },
        D = _d,
    };

    /// <summary>The raw signature over <paramref name="msg"/>: Ed25519 (deterministic) or ECDSA P-256 normalised to low-S.</summary>
    internal byte[] Sign(byte[] msg)
    {
        if (Alg == "EdDSA")
        {
            if (_seed == null) throw new InvalidOperationException("cose: not a private key");
            using var k = EdKey.FromSeed(_seed);
            return k.Sign(msg);
        }
        if (_d == null) throw new InvalidOperationException("cose: not a private key");
        using var ec = ECDsa.Create(Ec());
        var sig = ec.SignData(msg, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        // one valid signature form per statement: (r, n - s) would be a second leaf
        var s = new BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: true);
        if (s > Scitt.P256HalfN)
        {
            var ns = (Scitt.P256N - s).ToByteArray(isUnsigned: true, isBigEndian: true);
            Array.Clear(sig, 32, 32);
            ns.CopyTo(sig, 64 - ns.Length);
        }
        return sig;
    }

    /// <summary>Verify a raw signature as <paramref name="alg"/>; false when the key is of another algorithm or anything is malformed.</summary>
    internal bool VerifyRaw(string alg, byte[] msg, byte[] sig)
    {
        if (alg != Alg) return false;
        try
        {
            if (alg == "EdDSA") return _pub != null && Pca.VerifyEd25519Strict(_pub, msg, sig);
            if (sig.Length != 64) return false;
            var p = Ec();
            p.D = null;
            using var ec = ECDsa.Create(p);
            return ec.VerifyData(msg, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException) { return false; }
    }
}

public sealed record ProofStep(string Side, string Hash);

/// <summary>An RFC 9162 inclusion proof: the leaf index, the tree size and the bottom-up sibling hashes (b64u) with their sides.</summary>
public sealed record InclusionProof(long Index, long Size, IReadOnlyList<ProofStep> Path);

public sealed record CoseSign1(byte[] ProtectedBytes, CborMap ProtectedMap, CborMap Unprotected, byte[]? Payload, byte[] Signature);

/// <summary>Outcome of <see cref="Scitt.CheckStatement"/>: success, or the reason verification failed.</summary>
public sealed record StatementCheck(bool Ok, string? Reason = null);

public sealed record SignStatementOpts(string Alg, CoseKey Key, string Issuer, string? Subject = null, string? ContentType = null);
public sealed record ReceiptSignerOpts(string Alg, CoseKey Key, string? Issuer = null);
public sealed record VerifyReceiptOpts(string? TreeRoot = null, CoseKey? VerificationKey = null, CoseKey? StatementKey = null, bool AllowHighS = false);

/// <summary>An RFC 9942 consistency proof between two roots (b64u); <see cref="Proof"/> is CBOR <c>[tree-size-1, tree-size-2, [+ bstr]]</c>.</summary>
public sealed record ConsistencyProofResult(long OldSize, long NewSize, string OldRoot, string NewRoot, byte[] Proof);

public static class Scitt
{
    public const long CoseSign1Tag = 18;
    public const long HdrAlg = 1;
    public const long HdrContentType = 3;
    public const long HdrCwtClaims = 15;
    public const long CwtIss = 1;
    public const long CwtSub = 2;
    public const long HdrVds = 395;
    public const long HdrVdsProofs = 396;
    public const long VdsRfc9162Sha256 = 1;
    public const long ProofTypeInclusion = -1;
    public const string DefaultContentType = "application/pca+json";

    internal static readonly BigInteger P256N = BigInteger.Parse("0ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", System.Globalization.NumberStyles.HexNumber);
    internal static readonly BigInteger P256HalfN = P256N >> 1;

    static ScittException Err(string m) => new(m);

    static long AlgLabel(string alg) => alg switch { "EdDSA" => -8, "ES256" => -7, _ => throw new ArgumentException("scitt: unsupported alg " + alg) };

    static string? AlgForLabel(object? label) => label is long l ? (l == -8 ? "EdDSA" : l == -7 ? "ES256" : null) : null;

    /// <summary>True iff <paramref name="sig"/> is a 64-byte P-256 signature with 0 &lt; r &lt; n and 0 &lt; s &lt;= n/2 (low-S).</summary>
    static bool IsCanonicalEs256(byte[] sig)
    {
        if (sig.Length != 64) return false;
        var r = new BigInteger(sig.AsSpan(0, 32), isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: true);
        return r > 0 && r < P256N && s > 0 && s <= P256HalfN;
    }

    static byte[] SignBytes(string alg, CoseKey key, byte[] msg)
    {
        if (key.Alg != alg) throw new InvalidOperationException("scitt: key does not match alg");
        return key.Sign(msg);
    }

    static bool VerifyBytes(string alg, CoseKey key, byte[] msg, byte[] sig, bool allowHighS)
    {
        if (alg == "EdDSA") return key.VerifyRaw("EdDSA", msg, sig);
        // ECDSA is malleable: a high-S variant would be a second, distinct Merkle leaf; reject before the curve check
        if (!allowHighS && !IsCanonicalEs256(sig)) return false;
        if (allowHighS && sig.Length != 64) return false;
        return key.VerifyRaw("ES256", msg, sig);
    }

    /// <summary>The COSE_Sign1 Sig_structure to-be-signed bytes (RFC 9052 section 4.4), external_aad empty.</summary>
    static byte[] SigStructure(byte[] protectedBytes, byte[] payload) =>
        Cbor.Encode(new List<object?> { "Signature1", protectedBytes, Array.Empty<byte>(), payload });

    // ---------------------------------------------------------------- Signed Statements

    /// <summary>Sign a PCActn / verdict as a COSE Signed Statement. The protected header carries the algorithm, the content type and the
    /// CWT Claims (issuer, optional subject); the payload is the strict canonical serialisation of <paramref name="payload"/>.</summary>
    public static byte[] SignStatement(object? payload, SignStatementOpts opts)
    {
        var prot = new CborMap();
        prot.Set(HdrAlg, AlgLabel(opts.Alg));
        prot.Set(HdrContentType, opts.ContentType ?? DefaultContentType);
        var claims = new CborMap();
        claims.Set(CwtIss, opts.Issuer);
        if (opts.Subject != null) claims.Set(CwtSub, opts.Subject);
        prot.Set(HdrCwtClaims, claims);

        var protectedBytes = Cbor.Encode(prot);
        var payloadBytes = Pca.Canon(payload);
        var sig = SignBytes(opts.Alg, opts.Key, SigStructure(protectedBytes, payloadBytes));
        return Cbor.Encode(new CborTag(CoseSign1Tag, new List<object?> { protectedBytes, new CborMap(), payloadBytes, sig }));
    }

    /// <summary>Decode and structurally validate a COSE_Sign1 (tag 18). Throws <see cref="ScittException"/> on any deviation.</summary>
    public static CoseSign1 DecodeCoseSign1(byte[] bytes)
    {
        var top = Cbor.Decode(bytes);
        if (top is not CborTag { Tag: long tag } t || tag != CoseSign1Tag) throw Err("cose: not a COSE_Sign1 (tag 18)");
        if (t.Value is not List<object?> arr || arr.Count != 4) throw Err("cose: malformed COSE_Sign1 array");
        if (arr[0] is not byte[] protectedBytes) throw Err("cose: protected must be a bstr");
        if (arr[1] is not CborMap unprotected) throw Err("cose: unprotected must be a map");
        if (arr[2] is not (byte[] or null)) throw Err("cose: payload must be a bstr or nil");
        if (arr[3] is not byte[] signature) throw Err("cose: signature must be a bstr");
        var protectedMap = protectedBytes.Length == 0 ? new CborMap() : Cbor.Decode(protectedBytes) as CborMap ?? throw Err("cbor: expected a map");
        return new CoseSign1(protectedBytes, protectedMap, unprotected, (byte[]?)arr[2], signature);
    }

    static string AlgOf(CborMap protectedMap)
    {
        var label = protectedMap.Get(HdrAlg);
        if (ReferenceEquals(label, CborMap.Missing)) throw Err("cose: missing alg header");
        return AlgForLabel(label) ?? throw Err("cose: unsupported alg");
    }

    /// <summary>Verify a Signed Statement and say why it failed: <c>malformed: ...</c>, <c>unsupported alg</c> / <c>missing alg header</c>,
    /// <c>detached payload</c>, <c>non-canonical signature (high-S)</c> or <c>bad signature</c>. Never throws. external_aad is always empty.</summary>
    public static StatementCheck CheckStatement(byte[] statement, CoseKey publicKey, bool allowHighS = false)
    {
        CoseSign1 s;
        try { s = DecodeCoseSign1(statement); }
        catch (Exception e) { return new(false, "malformed: " + e.Message); }
        if (s.Payload == null) return new(false, "detached payload");
        string alg;
        try { alg = AlgOf(s.ProtectedMap); }
        catch (ScittException e) { return new(false, e.Message.Contains("missing") ? "missing alg header" : "unsupported alg"); }
        try
        {
            var msg = SigStructure(s.ProtectedBytes, s.Payload);
            if (VerifyBytes(alg, publicKey, msg, s.Signature, allowHighS)) return new(true);
            // tell a valid high-S variant (malleation) from a plain forgery
            if (alg == "ES256" && !IsCanonicalEs256(s.Signature) && VerifyBytes(alg, publicKey, msg, s.Signature, true))
                return new(false, "non-canonical signature (high-S)");
            return new(false, "bad signature");
        }
        catch (Exception) { return new(false, "bad signature"); }
    }

    public static bool VerifyStatement(byte[] statement, CoseKey publicKey, bool allowHighS = false) => CheckStatement(statement, publicKey, allowHighS).Ok;

    /// <summary>The raw canonical payload bytes of a Signed Statement. Throws on a malformed or detached statement.</summary>
    public static byte[] StatementPayload(byte[] statement) =>
        DecodeCoseSign1(statement).Payload ?? throw Err("cose: statement payload is detached");

    /// <summary>The b64u leaf a statement occupies in the transparency log.</summary>
    public static string StatementLeaf(byte[] statement) => Pca.B64u(statement);

    // ---------------------------------------------------------------- RFC 9162 inclusion proof codec

    /// <summary>Sibling sides (leaf to root) for <paramref name="index"/> in a tree of <paramref name="size"/> leaves (RFC 6962 split).</summary>
    public static List<string> SiblingSides(long index, long size)
    {
        var o = new List<string>();
        long idx = index, n = size;
        while (n > 1)
        {
            long k = Rfc9162.SplitPoint(n);
            if (idx < k) { o.Add("R"); n = k; }
            else { o.Add("L"); idx -= k; n -= k; }
        }
        o.Reverse();
        return o;
    }

    static List<object?> ProofSiblings(IEnumerable<object?> hashes)
    {
        var sibs = new List<object?>();
        foreach (var h in hashes)
            sibs.Add(Pca.B64uDecode(h, 32) ?? throw Err("scitt: proof step hash is not a 32-byte b64u hash"));
        return sibs;
    }

    /// <summary>Encode an inclusion proof as CBOR <c>[tree_size, leaf_index, [sibling hashes]]</c>.</summary>
    public static byte[] EncodeInclusionProof(InclusionProof proof) =>
        Cbor.Encode(new List<object?> { proof.Size, proof.Index, ProofSiblings(proof.Path.Select(s => (object?)s.Hash)) });

    /// <summary>The same for a JSON-shaped proof ({index, size, path: [{side, hash}]}), refusing malformed shapes the way the typed form cannot express.</summary>
    public static byte[] EncodeInclusionProof(Dictionary<string, object?> proof)
    {
        if (!proof.TryGetValue("path", out var p) || p is not List<object?> path) throw Err("proof.path.map is not a function");
        var hashes = new List<object?>();
        foreach (var step in path)
        {
            if (step == null) throw Err("Cannot read properties of null (reading 'hash')");
            hashes.Add(step is Dictionary<string, object?> d ? d.GetValueOrDefault("hash") : null);
        }
        var sibs = ProofSiblings(hashes);
        var size = proof.TryGetValue("size", out var sz) ? sz : new object(); // an absent member is JavaScript undefined: unencodable
        var index = proof.TryGetValue("index", out var ix) ? ix : new object();
        return Cbor.Encode(new List<object?> { size, index, sibs });
    }

    /// <summary>Decode an inclusion proof back into its parts (sides re-derived from the index and size).</summary>
    public static InclusionProof DecodeInclusionProof(byte[] bytes)
    {
        var v = Cbor.Decode(bytes);
        if (v is not List<object?> { Count: 3 } l) throw Err("scitt: malformed inclusion proof");
        if (l[0] is not long size || l[1] is not long index) throw Err("scitt: proof size/index must be integers");
        if (size < 1 || index < 0 || index >= size) throw Err("scitt: proof size/index out of range");
        if (l[2] is not List<object?> sibs) throw Err("scitt: inclusion path must be an array");
        var sides = SiblingSides(index, size);
        if (sibs.Count != sides.Count) throw Err("scitt: inclusion path length does not match (index,size)");
        var path = new List<ProofStep>();
        for (int i = 0; i < sibs.Count; i++)
        {
            if (sibs[i] is not byte[] { Length: 32 } h) throw Err("scitt: inclusion path entry must be a 32-byte bstr");
            path.Add(new ProofStep(sides[i], Pca.B64u(h)));
        }
        return new InclusionProof(index, size, path);
    }

    // ---------------------------------------------------------------- COSE Receipts

    /// <summary>Build a signed COSE Receipt for <paramref name="proof"/> against ledger root <paramref name="root"/> (b64u, 32 bytes). The
    /// payload is detached (nil): the signature covers the root a verifier recomputes from the proof.</summary>
    public static byte[] BuildReceipt(string root, InclusionProof proof, ReceiptSignerOpts signer)
    {
        var rootBytes = Pca.B64uDecode(root, 32) ?? throw Err("scitt: tree root is not a 32-byte b64u hash");
        var prot = new CborMap();
        prot.Set(HdrAlg, AlgLabel(signer.Alg));
        prot.Set(HdrVds, VdsRfc9162Sha256);
        if (signer.Issuer != null) prot.Set(HdrCwtClaims, new CborMap().Set(CwtIss, signer.Issuer));
        var protectedBytes = Cbor.Encode(prot);

        var proofs = new CborMap().Set(ProofTypeInclusion, new List<object?> { EncodeInclusionProof(proof) });
        var unprotected = new CborMap().Set(HdrVdsProofs, proofs);

        var sig = SignBytes(signer.Alg, signer.Key, SigStructure(protectedBytes, rootBytes));
        return Cbor.Encode(new CborTag(CoseSign1Tag, new List<object?> { protectedBytes, unprotected, null, sig }));
    }

    static (CoseSign1 Cose, InclusionProof Proof) DecodeReceipt(byte[] receipt)
    {
        var cose = DecodeCoseSign1(receipt);
        if (cose.ProtectedMap.Get(HdrVds) is not long vds || vds != VdsRfc9162Sha256) throw Err("scitt: receipt is not RFC9162_SHA256");
        if (cose.Payload != null && cose.Payload.Length != 32) throw Err("scitt: receipt payload (root) must be 32 bytes");
        if (cose.Unprotected.Get(HdrVdsProofs) is not CborMap proofs) throw Err("scitt: missing verifiable-data-structure-proofs");
        if (proofs.Get(ProofTypeInclusion) is not List<object?> { Count: >= 1 } inclusion) throw Err("scitt: missing inclusion proof");
        if (inclusion[0] is not byte[] first) throw Err("scitt: inclusion proof must be a bstr");
        return (cose, DecodeInclusionProof(first));
    }

    /// <summary>Verify a COSE Receipt for a Signed Statement. Fail-closed boolean, never throws. All must hold: an anchor is supplied
    /// (<c>TreeRoot</c> and/or <c>VerificationKey</c>); the receipt's TS signature over the root verifies when a key is given; the root equals
    /// the pinned <c>TreeRoot</c>; the inclusion proof binds the exact statement bytes to that root; the statement's own signature
    /// verifies when <c>StatementKey</c> is given.</summary>
    public static bool VerifyReceipt(byte[] receipt, byte[] statement, VerifyReceiptOpts opts)
    {
        try
        {
            if (opts.TreeRoot == null && opts.VerificationKey == null) return false;
            var (cose, proof) = DecodeReceipt(receipt);
            var hashes = proof.Path.Select(s => Pca.B64uDecode(s.Hash, 32) ?? throw Err("scitt: proof step hash is not a 32-byte b64u hash")).ToList();
            var root = Rfc9162.RootFromInclusionPath(Rfc9162.LeafHash(statement), proof.Index, proof.Size, hashes);
            if (root == null) return false;
            if (cose.Payload != null && !cose.Payload.AsSpan().SequenceEqual(root)) return false;

            if (opts.VerificationKey != null)
            {
                var alg = AlgOf(cose.ProtectedMap);
                if (!VerifyBytes(alg, opts.VerificationKey, SigStructure(cose.ProtectedBytes, root), cose.Signature, opts.AllowHighS)) return false;
            }
            if (opts.TreeRoot != null && !string.Equals(opts.TreeRoot, Pca.B64u(root), StringComparison.Ordinal)) return false;
            if (opts.StatementKey != null && !VerifyStatement(statement, opts.StatementKey, opts.AllowHighS)) return false;
            return true;
        }
        catch (Exception) { return false; }
    }

    /// <summary>Verify an RFC 9942 / RFC 9162 consistency proof between two pinned roots (b64u). Fail-closed boolean.</summary>
    public static bool VerifyConsistencyProof(byte[] proof, string oldRoot, string newRoot)
    {
        try
        {
            if (Cbor.Decode(proof) is not List<object?> { Count: 3 } v) return false;
            if (v[0] is not long oldSize || v[1] is not long newSize || v[2] is not List<object?> path) return false;
            var hashes = new List<byte[]>();
            foreach (var h in path) { if (h is not byte[] b) return false; hashes.Add(b); }
            var r1 = Pca.B64uDecode(oldRoot, 32);
            var r2 = Pca.B64uDecode(newRoot, 32);
            if (r1 == null || r2 == null) return false;
            return Rfc9162.VerifyConsistencyPath(oldSize, newSize, r1, r2, hashes);
        }
        catch (Exception) { return false; }
    }
}
