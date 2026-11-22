using System.Security.Cryptography;
using System.Text;
using static AtlasPca.Mpc.LweOt.Lattice;

namespace AtlasPca.Mpc.LweOt;

/// <summary>A source of random bytes for OT needs.</summary>
public interface IOtRandom
{
    byte[] Bytes(int n);
}

/// <summary>The CSPRNG-backed default and the deterministic SplitMix64 stream the differential tests seed (reproducible tests only).</summary>
public static class OtRandom
{
    public static IOtRandom Secure() => new SecureRandomSource();

    public static IOtRandom SplitMix64(ulong seed) => new SplitMix(seed);

    sealed class SecureRandomSource : IOtRandom
    {
        public byte[] Bytes(int n) => RandomNumberGenerator.GetBytes(n);
    }

    sealed class SplitMix(ulong seed) : IOtRandom
    {
        ulong _s = seed;

        ulong Next()
        {
            _s += 0x9e3779b97f4a7c15UL;
            var z = _s;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9UL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebUL;
            return z ^ (z >> 31);
        }

        public byte[] Bytes(int n)
        {
            var o = new byte[n];
            int have = 0;
            while (have < n)
            {
                var v = Next();
                for (int i = 0; i < 8 && have < n; i++, v >>= 8) o[have++] = (byte)v;
            }
            return o;
        }
    }
}

/// <summary>The endemic base OT aborted: malformed input, or a sender ciphertext failing its commitment.</summary>
public sealed class EndemicAbortException(string message) : Exception(message);

public sealed record ReceiverMessage(byte[] Rn, byte[][][] Points, byte[][] Rhos);
public sealed record ReceiverState(int[] Choices, byte[][] SecretKeys, byte[][] Rhos, byte[] Rn, byte[] Sid);
public sealed record ReceiveResult(ReceiverMessage Message, ReceiverState State);
public sealed record SenderMessage(byte[][][] Ciphertexts, byte[][][] SenderPads);
public sealed record EndemicTranscript(byte[] Rn, byte[][][] Points, byte[][] Rhos, byte[][][] Ciphertexts, byte[][][] Encrypted, byte[][][] Commitments);
public sealed record EndemicResult(byte[][] Received, EndemicTranscript Transcript);
/// <summary>The in-process RANDOM endemic base OT: the sender's pads (it learns BOTH per slot), the receiver's chosen pad (it learns ONE), the session id, the receiver message and the ciphertexts.</summary>
public sealed record EndemicRandomResult(byte[][][] SenderPads, byte[][] RecvPads, byte[] Sid, ReceiverMessage Message, byte[][][] Ciphertexts);

/// <summary>
/// The post-quantum, maliciously-secure endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE), the TypeScript package's recommended base
/// OT. The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring vector at the other, so the sender's effective
/// key for the other slot is uniform and its ciphertext is unrecoverable; the chosen-message form pads and commits each message and aborts on any
/// inconsistency. All lattice work is <see cref="Lattice"/>; this class hashes, xors and marshals bytes. The receiver's real key pair is the
/// FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
/// </summary>
public static class EndemicOt
{
    static readonly byte[] TagSid = U("atlas-pca-mpc/endemic-lwe-ot-sid"), TagHpk = U("atlas-pca-mpc/endemic-lwe-ot-hpk"),
        TagN = U("atlas-pca-mpc/endemic-lwe-ot-N"), TagPad = U("atlas-pca-mpc/endemic-lwe-ot-pad"), TagCommit = U("atlas-pca-mpc/endemic-lwe-ot-commit");

    /// <summary>Byte length of a derived random-OT shared secret (a K-PKE payload).</summary>
    public const int EndemicSecretBytes = SymBytes;

    static byte[] U(string s) => Encoding.UTF8.GetBytes(s);

    static byte[] Sha(params byte[][] chunks)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in chunks) h.AppendData(c);
        return h.GetHashAndReset();
    }

    static byte[] U32(long x) => [(byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x];

    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    /// <summary>Feeds the endemic OT from a base-OT randomness source of the OT stack (both are plain byte sources).</summary>
    sealed class OtRandomBridge(Ot.IOtRandom inner) : IOtRandom
    {
        public byte[] Bytes(int n) => inner.Bytes(n);
    }

    /// <summary>The chosen-message endemic base OT as the OT-extension's base-OT seam: <c>new Ot.OtChannel(rng, EndemicOt.WithEndemicBaseOt(), binding)</c>.</summary>
    public static Ot.BaseOtFn WithEndemicBaseOt() => (m, c, r) => BaseOt(m, c, new OtRandomBridge(r), tamperEncrypted: null).Received;

    static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("endemic-ot: XOR length mismatch");
        var o = new byte[a.Length];
        for (int i = 0; i < o.Length; i++) o[i] = (byte)(a[i] ^ b[i]);
        return o;
    }

    /// <summary><c>sid = H(TAG || rn)</c>: binds every oracle query to this receiver nonce.</summary>
    public static byte[] SessionId(byte[] rn) => Sha(TagSid, rn);

    static byte[] Hpk(byte[] sid, int i, byte[] other) => HashToRing(Cat(TagHpk, sid, U32(i), other));

    /// <summary>The pad for a slot: SHA-256 in counter mode over <c>TAG || sid || i || slot || ctr || payload</c>.</summary>
    public static byte[] Pad(byte[] sid, int index, int slot, byte[] payload, int len)
    {
        var o = new byte[len];
        int produced = 0; long ctr = 0;
        while (produced < len)
        {
            var block = Sha(TagPad, sid, U32(index), [(byte)(slot & 1)], U32(ctr), payload);
            for (int k = 0; k < block.Length && produced < len; k++) o[produced++] = block[k];
            ctr++;
        }
        return o;
    }

    static byte[] Commit(byte[] sid, int i, int slot, byte[] msg, byte[] pad) => Sha(TagCommit, sid, U32(i), [(byte)(slot & 1)], msg, pad);

    /// <summary>Receiver round: a real key pair per choice, a uniform vector for the other slot, and C = t_real - Hpk(sid, i, N) at the choice slot.</summary>
    public static ReceiveResult Receive(int[] choices, IOtRandom rng)
    {
        var rn = rng.Bytes(SymBytes);
        var sid = SessionId(rn);
        var points = new byte[choices.Length][][]; var rhos = new byte[choices.Length][]; var sks = new byte[choices.Length][]; var kept = new int[choices.Length];
        for (int i = 0; i < choices.Length; i++)
        {
            int c = choices[i] & 1;
            var kp = KeygenFips203(rng.Bytes(SymBytes));
            var tReal = kp.PublicKey[..TvecBytes];
            var nSlot = HashToRing(Cat(TagN, sid, U32(i), rng.Bytes(SymBytes)));
            var cPoint = RingSub(tReal, Hpk(sid, i, nSlot));
            points[i] = c == 0 ? [cPoint, nSlot] : [nSlot, cPoint];
            rhos[i] = kp.PublicKey[TvecBytes..];
            sks[i] = kp.SecretKey;
            kept[i] = c;
        }
        return new ReceiveResult(new ReceiverMessage(rn, points, rhos), new ReceiverState(kept, sks, rhos, rn, sid));
    }

    static void Validate(ReceiverMessage? m)
    {
        if (m?.Rn is not { Length: SymBytes }) throw new EndemicAbortException("endemic LWE OT: malformed session nonce");
        if (m.Points is null || m.Rhos is null || m.Points.Length != m.Rhos.Length) throw new EndemicAbortException("endemic LWE OT: points/rhos length mismatch");
        for (int i = 0; i < m.Points.Length; i++)
        {
            var pt = m.Points[i];
            if (pt is not { Length: 2 } || pt[0] is not { Length: TvecBytes } || pt[1] is not { Length: TvecBytes })
                throw new EndemicAbortException($"endemic LWE OT: malformed point pair at index {i}");
            if (m.Rhos[i] is not { Length: PkBytes - TvecBytes }) throw new EndemicAbortException($"endemic LWE OT: malformed rho at index {i}");
        }
    }

    /// <summary>Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. <paramref name="tamper"/> is test-only.</summary>
    public static SenderMessage SendRandom(ReceiverMessage message, IOtRandom rng, Action<byte[][][]>? tamper = null)
    {
        Validate(message);
        var sid = SessionId(message.Rn);
        int n = message.Points.Length;
        var cts = new byte[n][][]; var pads = new byte[n][][];
        for (int i = 0; i < n; i++)
        {
            var p0 = message.Points[i][0]; var p1 = message.Points[i][1]; var rho = message.Rhos[i];
            var pk0 = Cat(RingAdd(p0, Hpk(sid, i, p1)), rho);
            var pk1 = Cat(RingAdd(p1, Hpk(sid, i, p0)), rho);
            var r0 = rng.Bytes(SymBytes); var r1 = rng.Bytes(SymBytes);
            var ct0 = Lattice.Enc(pk0, r0, rng.Bytes(SymBytes));
            var ct1 = Lattice.Enc(pk1, r1, rng.Bytes(SymBytes));
            cts[i] = [ct0, ct1];
            pads[i] = [Pad(sid, i, 0, r0, EndemicSecretBytes), Pad(sid, i, 1, r1, EndemicSecretBytes)];
        }
        tamper?.Invoke(cts);
        return new SenderMessage(cts, pads);
    }

    /// <summary>Receiver recovery (random-OT form): decrypt only the chosen ciphertext.</summary>
    public static byte[][] RecoverRandom(ReceiverState state, SenderMessage sm)
    {
        var cts = sm?.Ciphertexts;
        if (cts is null || cts.Length != state.Choices.Length) throw new EndemicAbortException("endemic LWE OT: ciphertext count does not match the transfer count");
        for (int i = 0; i < cts.Length; i++)
            if (cts[i] is not { Length: 2 } || cts[i][0] is not { Length: CtBytes } || cts[i][1] is not { Length: CtBytes })
                throw new EndemicAbortException($"endemic LWE OT: malformed ciphertext pair at index {i}");
        var o = new byte[cts.Length][];
        for (int i = 0; i < o.Length; i++)
        {
            int c = state.Choices[i] & 1;
            o[i] = Pad(state.Sid, i, c, Dec(state.SecretKeys[i], cts[i][c]), EndemicSecretBytes);
        }
        return o;
    }

    /// <summary>In-process RANDOM endemic base OT (the random-OT face the combiner reuses; the TypeScript <c>endemicLweBaseOtRandom</c>).
    /// <paramref name="tamper"/> (test-only) corrupts the ciphertexts on the wire.</summary>
    public static EndemicRandomResult BaseOtRandom(int[] choices, IOtRandom rng, Action<byte[][][]>? tamper = null)
    {
        var rv = Receive(choices, rng);
        var sm = SendRandom(rv.Message, rng, tamper);
        var recv = RecoverRandom(rv.State, sm);
        return new EndemicRandomResult(sm.SenderPads, recv, rv.State.Sid, rv.Message, sm.Ciphertexts);
    }

    /// <summary>The chosen-message endemic base OT as a <see cref="Ot.BaseOtFn"/> (the TypeScript <c>endemicLweBaseOtFn</c>; only the received messages are part of the contract).</summary>
    public static Ot.BaseOtFn BaseOtFn => WithEndemicBaseOt();

    /// <summary>In-process chosen-message endemic base OT. <paramref name="tamperEncrypted"/> (test-only) corrupts the padded messages on the wire.</summary>
    public static EndemicResult BaseOt(byte[][][] messages, int[] choices, IOtRandom rng, Action<byte[][][]>? tamperEncrypted = null) =>
        BaseOt(messages, choices, rng, rng, tamperEncrypted);

    /// <summary>The same with a separate entropy source per party (the differential test seeds each stream).</summary>
    public static EndemicResult BaseOt(byte[][][] messages, int[] choices, IOtRandom receiverRng, IOtRandom rng, Action<byte[][][]>? tamperEncrypted = null)
    {
        if (messages.Length != choices.Length) throw new ArgumentException("endemicBaseOT: messages/choices length mismatch");
        var rv = Receive(choices, receiverRng);
        var sid = rv.State.Sid;
        int n = messages.Length;
        var cts = new byte[n][][]; var enc = new byte[n][][]; var com = new byte[n][][];
        for (int i = 0; i < n; i++)
        {
            var m0 = messages[i][0]; var m1 = messages[i][1];
            if (m0.Length != m1.Length) throw new ArgumentException($"endemicBaseOT (index {i}): the two messages must be equal length");
            var p0 = rv.Message.Points[i][0]; var p1 = rv.Message.Points[i][1]; var rho = rv.Message.Rhos[i];
            var r0 = rng.Bytes(SymBytes); var r1 = rng.Bytes(SymBytes);
            var ct0 = Lattice.Enc(Cat(RingAdd(p0, Hpk(sid, i, p1)), rho), r0, rng.Bytes(SymBytes));
            var ct1 = Lattice.Enc(Cat(RingAdd(p1, Hpk(sid, i, p0)), rho), r1, rng.Bytes(SymBytes));
            cts[i] = [ct0, ct1];
            var pad0 = Pad(sid, i, 0, r0, m0.Length); var pad1 = Pad(sid, i, 1, r1, m1.Length);
            enc[i] = [Xor(m0, pad0), Xor(m1, pad1)];
            com[i] = [Commit(sid, i, 0, m0, pad0), Commit(sid, i, 1, m1, pad1)];
        }
        tamperEncrypted?.Invoke(enc);
        var received = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            int c = choices[i] & 1;
            var payload = Dec(rv.State.SecretKeys[i], cts[i][c]);
            var e = enc[i][c];
            var pad = Pad(sid, i, c, payload, e.Length);
            var m = Xor(e, pad);
            if (!CryptographicOperations.FixedTimeEquals(Commit(sid, i, c, m, pad), com[i][c]))
                throw new EndemicAbortException($"endemic base OT (index {i}): sender ciphertext inconsistent with its commitment; aborting");
            received[i] = m;
        }
        return new EndemicResult(received, new EndemicTranscript(rv.Message.Rn, rv.Message.Points, rv.Message.Rhos, cts, enc, com));
    }
}
