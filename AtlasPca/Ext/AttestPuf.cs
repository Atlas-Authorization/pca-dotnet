// The PUF (physical unclonable function) attestation root of the reference (attest-puf.ts): a repetition-code fuzzy extractor (code-offset secure sketch + HKDF-SHA256
// extractor), a simulated PUF (a test device), a TPM endorsement-key PUF provider over an INJECTED tpm2-tools command runner, enrollment (the device key comes from the
// extracted secret; Ed25519 or ML-DSA suites), the device attestor, the enrollment registry and the verifier (the same hardware-verifier seam as the other roots).
// Unclonability is a classical property of the device, not a post-quantum one; the derived key can carry an ML-DSA suite. Values are the JSON tree; refusals throw.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A source of PUF response bits (one 0/1 value per byte).</summary>
public interface IPufProvider
{
    string Id { get; }
    byte[] Response(byte[] challenge);
}

/// <summary>A PUF that answers deterministically from a seed (a test device); <c>flip</c> positions model measurement noise (out-of-range positions are ignored).</summary>
public sealed class SimulatedPuf(string id, byte[] seed, int length, IEnumerable<int>? flip = null) : IPufProvider
{
    readonly HashSet<int> _flips = new(flip ?? []);
    public string Id => id;

    public byte[] Response(byte[] challenge)
    {
        int bytesNeeded = (length + 7) / 8;
        var stream = new byte[(bytesNeeded + 31) / 32 * 32];
        for (int blk = 0; blk * 32 < stream.Length; blk++)
        {
            var ctr = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(ctr, (uint)blk);
            SHA256.HashData(Pca.Concat(seed, challenge, ctr)).CopyTo(stream, blk * 32);
        }
        var bits = new byte[length];
        for (int i = 0; i < length; i++) bits[i] = (byte)((stream[i >> 3] >> (i & 7)) & 1);
        foreach (var pos in _flips) if (pos >= 0 && pos < bits.Length) bits[pos] = (byte)((bits[pos] ^ 1) & 1);
        return bits;
    }
}

/// <summary>The answer of a tpm2-tools invocation: <c>Status</c> (null: no exit status), <c>Stdout</c> (null: not bytes), <c>Stderr</c>, <c>Error</c> (a spawn failure).</summary>
public sealed record TpmCommandResult(int? Status, byte[]? Stdout, string? Stderr = null, string? Error = null);

/// <summary>A tpm2-tools command runner: <c>(command, args)</c> to its result (null: no result).</summary>
public delegate TpmCommandResult? TpmCommandRunner(string command, IReadOnlyList<string> args);

/// <summary>The PUF of a TPM: the endorsement-key public blob (read through tpm2-tools) hashed with the challenge. Fails closed.</summary>
public sealed class TpmEkPufProvider : IPufProvider
{
    readonly int _length;
    readonly TpmCommandRunner _run;
    readonly string _tool;
    readonly IReadOnlyList<string> _args;
    readonly double _minEkBytes;
    public string Id { get; }

    /// <summary>Options: <c>id</c> (non-empty string), <c>length</c> (positive integer: the enrolled rep * messageBits), <c>tool</c> (default tpm2_readpublic), <c>ekHandle</c> (default 0x81010001),
    /// <c>args</c> (default <c>-c &lt;handle&gt; -f der -o /dev/stdout -Q</c>), <c>minEkBytes</c> (default 64). <paramref name="run"/> null: spawn the tool.</summary>
    public TpmEkPufProvider(D? opts, TpmCommandRunner? run = null)
    {
        opts ??= new D(); // no options is no id
        if (opts.GetValueOrDefault("id") is not string { Length: > 0 } id) throw new ArgumentException("TpmEkPufProvider: id must be a non-empty string");
        var len = opts.GetValueOrDefault("length");
        if (!AttestPuf.IsInteger(len) || IntentJs.NumOf(len)!.Value < 1) throw new ArgumentException("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)");
        var min = opts.GetValueOrDefault("minEkBytes");
        if (opts.ContainsKey("minEkBytes") && (!AttestPuf.IsInteger(min) || IntentJs.NumOf(min)!.Value < 1)) throw new ArgumentException("TpmEkPufProvider: minEkBytes must be a positive integer");
        Id = id;
        _length = (int)IntentJs.NumOf(len)!.Value;
        _run = run ?? AttestPuf.DefaultTpmCommandRunner;
        _tool = opts.GetValueOrDefault("tool") is string { Length: > 0 } t ? t : "tpm2_readpublic";
        var handle = opts.GetValueOrDefault("ekHandle") is string { Length: > 0 } h ? h : "0x81010001";
        _args = opts.GetValueOrDefault("args") is L al ? al.Select(x => x as string ?? JsJson.ToJsString(x)).ToList() : ["-c", handle, "-f", "der", "-o", "/dev/stdout", "-Q"];
        _minEkBytes = opts.ContainsKey("minEkBytes") ? IntentJs.NumOf(min)!.Value : 64;
    }

    /// <summary>The EK public blob. Throws (fail closed) when the tool failed, is unavailable, or the blob is shorter than <c>minEkBytes</c>.</summary>
    public byte[] ReadEkPublic()
    {
        TpmCommandResult? res;
        try { res = _run(_tool, _args); }
        catch (Exception e) { throw new InvalidOperationException("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
        if (res == null) throw new InvalidOperationException("TpmEkPufProvider: command runner returned no result (fail closed)");
        if (res.Error is { Length: > 0 }) throw new InvalidOperationException("TpmEkPufProvider: tpm2-tools unavailable (fail closed): " + res.Error);
        if (res.Status != 0)
            throw new InvalidOperationException($"TpmEkPufProvider: '{_tool}' exited with status {(res.Status is int s ? s.ToString() : "null")} (fail closed){(string.IsNullOrEmpty(res.Stderr) ? "" : ": " + AttestUtil.JsTrim(res.Stderr))}");
        var ek = res.Stdout;
        if (ek == null || ek.Length < _minEkBytes)
            throw new InvalidOperationException($"TpmEkPufProvider: EK public too short ({ek?.Length ?? 0} < {JsJson.NumberToString(_minEkBytes)} bytes) — TPM unavailable or wrong handle (fail closed)");
        return ek;
    }

    public byte[] Response(byte[] challenge)
    {
        var ek = ReadEkPublic();
        var secret = HKDF.DeriveKey(HashAlgorithmName.SHA256, ek, 32, Encoding.UTF8.GetBytes(AttestPuf.TpmEkDomain), challenge);
        return AttestPuf.ExpandSecretToBits(secret, _length);
    }
}

/// <summary>The device attestor: re-derives the device key from a fresh noisy response and signs an attestation statement.</summary>
public sealed class PufAttestor
{
    readonly IPufProvider _provider;
    readonly D _enrollment;
    readonly string _alg;
    readonly byte[] _challenge;

    internal PufAttestor(IPufProvider provider, D enrollment)
    {
        _provider = provider;
        _enrollment = enrollment;
        _alg = AttestPuf.AssertSuite(enrollment.GetValueOrDefault("alg"));
        _challenge = Pca.B64uDecode(enrollment.GetValueOrDefault("challenge")) ?? throw new ArgumentException("base64url: invalid input");
    }

    /// <summary>A signed statement for <c>{measurement, weights_digest?, holder_pub, grant_ref, epoch, nonce}</c>: <c>{provider_id, measurement, weights_digest?, binding, alg, sig, pq_sig?}</c>.
    /// Throws when the response is too noisy to reproduce the key (the signature then fails to verify, not here) or on a malformed enrollment or binding.</summary>
    public D Attest(D claims)
    {
        var bits = _provider.Response(_challenge);
        var key = AttestPuf.FuzzyReproduce(bits, _enrollment.GetValueOrDefault("helper"));
        var signer = AttestPuf.SignerFromSeed(_alg, key);
        var binding = AttestationSoft.AttestationBindingB64u(new D
        {
            ["holderPub"] = claims.GetValueOrDefault("holder_pub"), ["grantRef"] = claims.GetValueOrDefault("grant_ref"), ["epoch"] = claims.GetValueOrDefault("epoch"), ["nonce"] = claims.GetValueOrDefault("nonce"),
        });
        var body = new D { ["provider_id"] = _provider.Id, ["measurement"] = claims.GetValueOrDefault("measurement"), ["binding"] = binding, ["alg"] = _alg };
        if (claims.TryGetValue("weights_digest", out var w)) body["weights_digest"] = w;
        var parts = signer.Sign(AttestPuf.StatementMessage(body));
        var st = new D(body) { ["sig"] = parts.Sig };
        if (parts.PqSig != null) st["pq_sig"] = parts.PqSig;
        return st;
    }
}

/// <summary>The enrollment registry: register, look up (a revoked provider is hidden), revoke (a revocation outlives re-registration).</summary>
public sealed class PufEnrollmentRegistry
{
    readonly Dictionary<string, D> _byId = new(StringComparer.Ordinal);
    readonly HashSet<string> _revoked = new(StringComparer.Ordinal);

    /// <param name="enrollments">A list of enrollments (a malformed entry, or a non-list, is skipped); a later duplicate wins.</param>
    public PufEnrollmentRegistry(object? enrollments = null)
    {
        if (enrollments is L l) foreach (var e in l) Register(e);
    }

    public void Register(object? enrollment)
    {
        if (enrollment is D d && d.GetValueOrDefault("providerId") is string id) _byId[id] = d;
    }

    public D? Lookup(string providerId) => _revoked.Contains(providerId) ? null : _byId.GetValueOrDefault(providerId);
    public void Revoke(string providerId) => _revoked.Add(providerId);
    public bool IsRevoked(string providerId) => _revoked.Contains(providerId);
}

public static class AttestPuf
{
    public const string ExtractInfo = "atlas-pca/puf-extract/v1";
    public const string AttestDomain = "atlas-pca/attest-puf/v1\0";
    public const string TpmEkDomain = "atlas-pca/puf-tpm-ek/v1";
    public const int KeyBytes = 32;

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["PUF_EXTRACT_INFO"] = ExtractInfo, ["PUF_ATTEST_DOMAIN"] = AttestDomain, ["PUF_KEY_BYTES"] = (long)KeyBytes, ["TPM_EK_PUF_DOMAIN"] = TpmEkDomain };

    /// <summary>Number.isInteger of a JSON value.</summary>
    internal static bool IsInteger(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) && d == Math.Floor(d);

    static Num Int(double d) => IntentJs.OfLong((long)d);

    /// <summary>How many flipped bits per repetition block still decode: floor((rep - 1) / 2).</summary>
    public static double RepetitionCorrectionBound(double rep) => Math.Floor((rep - 1) / 2);

    static void AssertBits(byte[] b, string where)
    {
        foreach (var x in b) if (x > 1) throw new ArgumentException($"{where}: response must be a 0/1 bit array");
    }

    static byte[] XorBits(byte[] a, byte[] b)
    {
        var o = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = (byte)((a[i] ^ b[i]) & 1);
        return o;
    }

    static byte[] RepEncode(byte[] message, int rep)
    {
        var o = new byte[message.Length * rep];
        for (int i = 0; i < message.Length; i++)
            for (int j = 0; j < rep; j++) o[i * rep + j] = (byte)(message[i] & 1);
        return o;
    }

    static byte[] RepDecode(byte[] code, int rep)
    {
        int k = code.Length / rep;
        var o = new byte[k];
        for (int i = 0; i < k; i++)
        {
            int ones = 0;
            for (int j = 0; j < rep; j++) ones += code[i * rep + j] & 1;
            o[i] = (byte)(ones * 2 > rep ? 1 : 0); // strict majority; ties (even rep) resolve to 0: use ODD rep
        }
        return o;
    }

    static byte[] PackBits(byte[] bits)
    {
        var o = new byte[(bits.Length + 7) / 8];
        for (int i = 0; i < bits.Length; i++) if ((bits[i] & 1) != 0) o[i >> 3] |= (byte)(1 << (i & 7));
        return o;
    }

    static byte[] UnpackBits(byte[] packed, int n)
    {
        var o = new byte[n];
        for (int i = 0; i < n; i++) o[i] = (byte)((packed[i >> 3] >> (i & 7)) & 1);
        return o;
    }

    static byte[] ExtractKey(byte[] bits, byte[] salt) => HKDF.DeriveKey(HashAlgorithmName.SHA256, PackBits(bits), KeyBytes, salt, Encoding.UTF8.GetBytes(ExtractInfo));

    /// <summary>Enrollment of a response: a random codeword of the repetition code gives the helper (sketch = codeword xor response, a salt) and the HKDF-SHA256 extractor the 32-byte key.
    /// <paramref name="rep"/> must be an odd positive integer, <paramref name="messageBits"/> a positive integer and the response exactly rep * messageBits 0/1 bits.
    /// <paramref name="randomBytes"/> is called for the message (n = messageBits) and then the salt (n = 32).</summary>
    public static (byte[] Key, D Helper) FuzzyEnroll(byte[] responseBits, object? rep, object? messageBits, Func<int, byte[]> randomBytes)
    {
        if (!IsInteger(rep) || IntentJs.NumOf(rep)!.Value < 1 || IntentJs.NumOf(rep)!.Value % 2 == 0) throw new ArgumentException("fuzzyEnroll: rep must be an odd positive integer");
        if (!IsInteger(messageBits) || IntentJs.NumOf(messageBits)!.Value < 1) throw new ArgumentException("fuzzyEnroll: messageBits must be a positive integer");
        double r = IntentJs.NumOf(rep)!.Value, mb = IntentJs.NumOf(messageBits)!.Value;
        double n = r * mb;
        if (responseBits.Length != n) throw new ArgumentException($"fuzzyEnroll: response length {responseBits.Length} != rep*messageBits {JsJson.NumberToString(n)}");
        AssertBits(responseBits, "fuzzyEnroll");
        var m = new byte[(int)mb];
        var mr = randomBytes((int)mb);
        for (int i = 0; i < m.Length; i++) m[i] = (byte)((i < mr.Length ? mr[i] : 0) & 1);
        var sketch = XorBits(RepEncode(m, (int)r), responseBits); // C xor W
        var salt = randomBytes(32);
        var key = ExtractKey(responseBits, salt);
        return (key, new D { ["sketch"] = Pca.B64u(PackBits(sketch)), ["salt"] = Pca.B64u(salt), ["rep"] = Int(r), ["messageBits"] = Int(mb), ["n"] = Int(n) });
    }

    /// <summary>Re-derive the key from a noisy response: decode the corrupted codeword (up to <see cref="RepetitionCorrectionBound"/> errors per block), recover the enrolled response and extract. Throws on a
    /// malformed helper or a response of the wrong length or alphabet.</summary>
    public static byte[] FuzzyReproduce(byte[] responseBits, object? helperObj)
    {
        var helper = helperObj as D;
        if (helper == null || !IsInteger(helper.GetValueOrDefault("rep")) || !IsInteger(helper.GetValueOrDefault("messageBits"))
            || IntentJs.NumOf(helper["rep"])!.Value < 1 || IntentJs.NumOf(helper["rep"])!.Value % 2 == 0)
            throw new ArgumentException("fuzzyReproduce: malformed helper params");
        double rep = IntentJs.NumOf(helper["rep"])!.Value, mb = IntentJs.NumOf(helper["messageBits"])!.Value;
        double n = rep * mb;
        if (!(IntentJs.NumOf(helper.GetValueOrDefault("n")) is double hn && hn == n)) throw new ArgumentException("fuzzyReproduce: helper.n inconsistent with rep*messageBits");
        if (responseBits.Length != n) throw new ArgumentException($"fuzzyReproduce: response length {responseBits.Length} != {JsJson.NumberToString(n)}");
        AssertBits(responseBits, "fuzzyReproduce");
        if (helper.GetValueOrDefault("sketch") is not string || helper.GetValueOrDefault("salt") is not string) throw new ArgumentException("fuzzyReproduce: helper data missing sketch or salt");
        var packed = Pca.B64uDecode(helper["sketch"]);
        var salt = Pca.B64uDecode(helper["salt"]);
        if (packed == null || salt == null) throw new ArgumentException("fuzzyReproduce: helper sketch or salt is not canonical base64url");
        int ni = (int)n;
        if (packed.Length != (ni + 7) / 8) throw new ArgumentException("fuzzyReproduce: helper sketch has the wrong length");
        if (salt.Length != 32) throw new ArgumentException("fuzzyReproduce: helper salt has the wrong length");
        var sketchBits = UnpackBits(packed, ni);
        var corrupted = XorBits(responseBits, sketchBits); // W' xor s = C xor e
        var mHat = RepDecode(corrupted, (int)rep);
        var cHat = RepEncode(mHat, (int)rep);
        var wRec = XorBits(cHat, sketchBits); // C_hat xor s = the recovered W
        return ExtractKey(wRec, salt);
    }

    internal static byte[] ExpandSecretToBits(byte[] secret, int length)
    {
        int bytesNeeded = (length + 7) / 8;
        int nblocks = Math.Max(1, (bytesNeeded + 31) / 32);
        var stream = new byte[nblocks * 32];
        for (int blk = 0; blk < nblocks; blk++)
        {
            var ctr = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(ctr, (uint)blk);
            SHA256.HashData(Pca.Concat(secret, ctr)).CopyTo(stream, blk * 32);
        }
        var bits = new byte[length];
        for (int i = 0; i < length; i++) bits[i] = (byte)((stream[i >> 3] >> (i & 7)) & 1);
        return bits;
    }

    /// <summary>Runs tpm2-tools as a child process (15 s, 1 MiB of output). A failure to spawn is reported in <c>Error</c>.</summary>
    public static TpmCommandResult? DefaultTpmCommandRunner(string command, IReadOnlyList<string> args)
    {
        try
        {
            var psi = new ProcessStartInfo(command) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = false, UseShellExecute = false };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("spawn failed");
            using var ms = new MemoryStream();
            var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
            var err = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(15_000)) { try { p.Kill(true); } catch (Exception) { } return new(null, [], null, $"{command}: ETIMEDOUT"); }
            copy.Wait(15_000);
            var stdout = ms.Length > (1 << 20) ? [] : ms.ToArray();
            return new(p.ExitCode, stdout, err.Wait(1000) ? err.Result : null);
        }
        catch (Exception) { return new(null, [], null, command + ": spawn failed"); }
    }

    // ---- enrollment ----

    internal static string AssertSuite(object? alg) =>
        alg is "ed25519" or "ml-dsa-65" or "ml-dsa-87" ? (string)alg : throw new ArgumentException($"PUF root: unsupported derived suite '{JsJson.ToJsString(alg)}' (use ed25519, ml-dsa-65 or ml-dsa-87)");

    internal static PufSigner SignerFromSeed(string alg, byte[] seed)
    {
        switch (alg)
        {
            case "ed25519":
            {
                using var k = EdKey.FromSeed(seed);
                return new PufSigner(k.Id, m => PqSuites.SignWithSuite("ed25519", new SuiteSecretKeys { EdSecret = seed }, m));
            }
            case "ml-dsa-65":
            {
                var kp = PqSuites.MlDsa65Keygen(seed);
                return new PufSigner(PqSuites.EncodeMlDsaPublicKey(kp.PublicKey), m => PqSuites.SignWithSuite("ml-dsa-65", new SuiteSecretKeys { MlDsa = kp }, m));
            }
            default:
            {
                var kp = PqSuites.MlDsa87Keygen(seed);
                return new PufSigner(PqSuites.EncodeMlDsa87PublicKey(kp.PublicKey), m => PqSuites.SignWithSuite("ml-dsa-87", new SuiteSecretKeys { MlDsa87 = kp }, m));
            }
        }
    }

    internal sealed class PufSigner(string publicKey, Func<byte[], SuiteSignatureParts> sign)
    {
        public string PublicKey => publicKey;
        public SuiteSignatureParts Sign(byte[] msg) => sign(msg);
    }

    internal static byte[] StatementMessage(D body) => IntentJs.Message(AttestDomain, body);

    /// <summary>Enroll a device: read its response to <paramref name="challenge"/>, run the fuzzy extractor and derive the device key (suite <c>opts.alg</c>: ed25519, ml-dsa-65 (default) or ml-dsa-87).
    /// The enrollment is <c>{providerId, challenge, alg, publicKey, helper, helperCommitment}</c>. <paramref name="opts"/>: <c>rep</c>, <c>messageBits</c>, <c>alg</c>?; <paramref name="randomBytes"/>
    /// null: the system CSPRNG.</summary>
    public static D EnrollPuf(IPufProvider provider, byte[] challenge, D opts, Func<int, byte[]>? randomBytes = null)
    {
        var alg = AssertSuite(opts.TryGetValue("alg", out var a) && a != null ? a : "ml-dsa-65");
        randomBytes ??= RandomNumberGenerator.GetBytes;
        var bits = provider.Response(challenge);
        var (key, helper) = FuzzyEnroll(bits, opts.GetValueOrDefault("rep"), opts.GetValueOrDefault("messageBits"), randomBytes);
        var signer = SignerFromSeed(alg, key);
        return new D
        {
            ["providerId"] = provider.Id, ["challenge"] = Pca.B64u(challenge), ["alg"] = alg, ["publicKey"] = signer.PublicKey, ["helper"] = helper, ["helperCommitment"] = Pca.HashCanonical(helper),
        };
    }

    /// <summary>The device attestor for an enrollment (its suite is checked here, its challenge when it is first used).</summary>
    public static PufAttestor CreatePufAttestor(IPufProvider provider, D enrollment) => new(provider, enrollment);

    // ---- the verifier ----

    static bool Contains(List<object?> list, object? x) => x is string s && list.Any(e => e is string t && string.Equals(t, s, StringComparison.Ordinal));

    sealed class PufVerifier(Func<string, object?, object?, object?> resolveEnrollment, List<object?> measurements, List<object?>? weights, bool requirePq,
        Func<D, D, D> deriveIdentity, Func<string, bool>? isRevoked, Func<object?, object?, object?>? resolveEvidence) : IHardwareAttestation
    {
        static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

        public object? Verify(D input)
        {
            try
            {
                if (resolveEvidence == null) return Fail("no PUF evidence resolver configured (fail closed)");
                var st = resolveEvidence(input.GetValueOrDefault("document"), input.GetValueOrDefault("ctx")) as D;
                if (st == null || st.GetValueOrDefault("provider_id") is not string providerId || st.GetValueOrDefault("alg") is not string stAlg) return Fail("no PUF attestation statement for this action");
                if (isRevoked != null && isRevoked(providerId)) return Fail($"PUF enrollment for provider '{providerId}' is revoked");
                if (resolveEnrollment(providerId, input.GetValueOrDefault("document"), input.GetValueOrDefault("ctx")) is not D enr) return Fail($"no PUF enrollment registered for provider '{providerId}'");
                if (enr.TryGetValue("notAfter", out var na) && na != null && !(IntentJs.NumOf(input.GetValueOrDefault("nowMs")) is double now && IntentJs.NumOf(na) is double naf && now < naf)) return Fail("PUF enrollment has expired");
                if (enr.GetValueOrDefault("helperCommitment") is not string hc || hc != Pca.HashCanonical(enr.GetValueOrDefault("helper"))) return Fail("PUF enrollment helper commitment mismatch (helper tampered)");
                if (!Equals(stAlg, enr.GetValueOrDefault("alg"))) return Fail($"PUF statement suite '{stAlg}' does not match the enrolled suite '{JsJson.ToJsString(enr.GetValueOrDefault("alg"))}'");
                var suite = IntentJs.SuiteOf(stAlg, true);
                if (suite == null) return Fail($"PUF statement declares an unknown signature alg '{stAlg}'");
                var prim = Pq.Suites[suite].Pq;
                bool hasPq = prim is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87 or Pq.Prim.Slh128f or Pq.Prim.Slh256s;
                if (requirePq && !hasPq) return Fail($"PQ required: PUF-derived suite '{suite}' is classical");
                var body = st.Where(e => e.Key is not ("sig" or "pq_sig")).ToDictionary(e => e.Key, e => e.Value);
                var pk = enr.GetValueOrDefault("publicKey") as string;
                bool ok = PqSuites.VerifyWithSuite(suite, pk, pk, StatementMessage(body), st.GetValueOrDefault("sig"), st.GetValueOrDefault("pq_sig"));
                if (!ok) return Fail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)");
                var expected = input.GetValueOrDefault("expected");
                if (!IntentRevocation.Truthy(expected)) return Fail("no expected attestation binding supplied");
                string expectedB64u;
                try { expectedB64u = Pca.B64u(AttestationSoft.AttestationBinding(expected)); }
                catch (Exception e) { return Fail("binding not constructible: " + (string.IsNullOrEmpty(e.Message) ? "invalid" : e.Message)); }
                if (st.GetValueOrDefault("binding") is not string b || b != expectedB64u) return Fail("PUF statement binding mismatch (holder/grant/epoch/nonce)");
                if (!Contains(measurements, st.GetValueOrDefault("measurement"))) return Fail("measurement not in policy allowlist");
                if (weights != null && weights.Count > 0 && !(st.GetValueOrDefault("weights_digest") is string wd && Contains(weights, wd))) return Fail("measured weights digest not in policy allowlist");
                var measured = deriveIdentity(st, enr);
                return new D { ["ok"] = true, ["bound"] = true, ["measured"] = measured, ["hostAsserted"] = new D { ["provider_id"] = providerId, ["suite"] = suite } };
            }
            catch (Exception e) { return Fail("puf verification error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
        }
    }

    static D DefaultIdentity(D st, D _) => new()
    {
        ["model_id"] = "", ["weights_digest"] = st.GetValueOrDefault("weights_digest") is string w ? w : "", ["weights_measured"] = false, ["runtime_measurement"] = st.GetValueOrDefault("measurement"), ["operator"] = "",
    };

    /// <summary>The PUF verifier (the hardware-verifier seam; labelled software, vendor puf). Options: <c>resolveEnrollment</c> (Func&lt;string, object?, object?, object?&gt;: provider id, document, ctx), <c>policy</c>
    /// {measurements (a NON-EMPTY allowlist), weightsMeasurements?, deriveIdentity? (Func&lt;D, D, D&gt;: statement, enrollment)}, <c>requirePq</c>, <c>isRevoked</c> (Func&lt;string, bool&gt;) and
    /// <c>resolveEvidence</c> (Func&lt;object?, object?, object?&gt;: document, ctx; without it every verification is refused). Throws on an empty allowlist or no resolver. The statement signature is checked
    /// under the enrolled key, then the binding, the measurement and the optional weights allowlist.</summary>
    public static IHardwareAttestation CreatePufVerifier(D opts)
    {
        var policy = opts.GetValueOrDefault("policy") as D;
        if (policy == null || policy.GetValueOrDefault("measurements") is not L ms || ms.Count == 0)
            throw new ArgumentException("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
        if (opts.GetValueOrDefault("resolveEnrollment") is not Func<string, object?, object?, object?> resolve) throw new ArgumentException("createPufVerifier: resolveEnrollment is required");
        var v = new PufVerifier(resolve, new L(ms), policy.GetValueOrDefault("weightsMeasurements") is L wl ? new L(wl) : null, opts.GetValueOrDefault("requirePq") is true,
            policy.GetValueOrDefault("deriveIdentity") as Func<D, D, D> ?? DefaultIdentity, opts.GetValueOrDefault("isRevoked") as Func<string, bool>, opts.GetValueOrDefault("resolveEvidence") as Func<object?, object?, object?>);
        return AssuranceLabels.Set(v, new AssuranceLabel("software", "puf"));
    }
}
