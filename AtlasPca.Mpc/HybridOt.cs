using System.Security.Cryptography;
using System.Text;
using BaseOtFn = AtlasPca.Mpc.Ot.BaseOtFn;
using BaseOtTamper = AtlasPca.Mpc.Ot.BaseOtTamper;
using IOtRandom = AtlasPca.Mpc.Ot.IOtRandom;
using Point = AtlasPca.Mpc.Ec.Point;

namespace AtlasPca.Mpc;

/// <summary>
/// Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every
/// transfer key, so the transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the
/// messages and a per-message commitment catches an inconsistent sender.
/// </summary>
public static class HybridOt
{
    static readonly byte[] TagHybridSid = Encoding.UTF8.GetBytes("atlas-pca-mpc/hybrid-ot-sid");
    static readonly byte[] TagHybridKey = Encoding.UTF8.GetBytes("atlas-pca-mpc/hybrid-ot-transfer-key");
    static readonly byte[] TagHybridCommit = Encoding.UTF8.GetBytes("atlas-pca-mpc/hybrid-ot-msg-commit");

    static byte[] Sha256(params byte[][] chunks)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in chunks) h.AppendData(c);
        return h.GetHashAndReset();
    }

    static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("hybrid-ot: XOR length mismatch");
        var o = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = (byte)(a[i] ^ b[i]);
        return o;
    }

    /// <summary>A hybrid base OT aborted: the sender's ciphertext is inconsistent with its commitment.</summary>
    public sealed class HybridOtAbort : Exception
    {
        public HybridOtAbort(string message) : base(message) { }
    }

    public static byte[] HybridSessionId(byte[] kemSid, Point ecS) => Sha256(TagHybridSid, kemSid, Ec.EncodePoint(ecS));

    public static byte[] HybridTransferKey(byte[] sid, int index, int slot, byte[] ssEc, byte[] ssKem, int len)
    {
        if (len < 0 || len > 1 << 20) throw new ArgumentException("hybridTransferKey: length must be an integer in [0, 1 MiB]");
        var o = new byte[len];
        int produced = 0;
        long ctr = 0;
        while (produced < len)
        {
            var block = Sha256(TagHybridKey, sid, Ot.U32(index), new[] { (byte)(slot & 1) }, Ot.U32(ctr), ssEc, ssKem);
            for (int k = 0; k < block.Length && produced < len; k++) o[produced++] = block[k];
            ctr++;
        }
        return o;
    }

    static byte[] HybridCommit(byte[] sid, int index, int slot, byte[] msg, byte[] key) =>
        Sha256(TagHybridCommit, sid, Ot.U32(index), new[] { (byte)(slot & 1) }, msg, key);

    public sealed record HybridSenderMessage(byte[][][] Encrypted, byte[][][] Commitments);

    public static HybridSenderMessage HybridSenderEncrypt(byte[] sid, byte[][][] messages, byte[][][] ecSecrets, byte[][][] kemSecrets)
    {
        if (messages.Length != ecSecrets.Length || messages.Length != kemSecrets.Length)
            throw new ArgumentException("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch");
        var encrypted = new byte[messages.Length][][];
        var commitments = new byte[messages.Length][][];
        for (int i = 0; i < messages.Length; i++)
        {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.Length != m1.Length) throw new ArgumentException("hybridSenderEncrypt (index " + i + "): the two messages must be equal length");
            var k0 = HybridTransferKey(sid, i, 0, ecSecrets[i][0], kemSecrets[i][0], m0.Length);
            var k1 = HybridTransferKey(sid, i, 1, ecSecrets[i][1], kemSecrets[i][1], m1.Length);
            encrypted[i] = new[] { Xor(m0, k0), Xor(m1, k1) };
            commitments[i] = new[] { HybridCommit(sid, i, 0, m0, k0), HybridCommit(sid, i, 1, m1, k1) };
        }
        return new HybridSenderMessage(encrypted, commitments);
    }

    public static byte[][] HybridReceiverRecover(byte[] sid, int[] choices, HybridSenderMessage sender, byte[][] ecRecv, byte[][] kemRecv)
    {
        int n = choices.Length;
        if (sender.Encrypted.Length != n || sender.Commitments.Length != n || ecRecv.Length != n || kemRecv.Length != n)
            throw new ArgumentException("hybridReceiverRecover: length mismatch");
        var received = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            int c = choices[i] & 1;
            var e = sender.Encrypted[i][c];
            var key = HybridTransferKey(sid, i, c, ecRecv[i], kemRecv[i], e.Length);
            var m = Xor(e, key);
            if (!CryptographicOperations.FixedTimeEquals(HybridCommit(sid, i, c, m, key), sender.Commitments[i][c]))
                throw new HybridOtAbort("hybrid base OT (index " + i + "): sender ciphertext inconsistent with its commitment; aborting");
            received[i] = m;
        }
        return received;
    }

    /// <summary>TEST-ONLY injection points (null = honest).</summary>
    public sealed class HybridBaseOtTamper
    {
        public BaseOtTamper? Ec;
        public KemOt.KemMalTamper? Kem;
        public Action<byte[][][]>? TamperEncrypted;
    }

    public sealed record HybridBaseOtTranscript(byte[] Sid, Point EcS, byte[] KemSid, byte[][][] Encrypted, byte[][][] Commitments);

    public sealed record HybridBaseOtResult(byte[][] Received, HybridBaseOtTranscript Transcript);

    public static HybridBaseOtResult HybridBaseOT(byte[][][] messages, int[] choices, IOtRandom? rng, HybridBaseOtTamper? tamper)
    {
        rng ??= Ot.SecureOtRandom();
        if (messages.Length != choices.Length) throw new ArgumentException("hybridBaseOT: messages/choices length mismatch");
        var ec = Ot.MalBaseRandomOT(choices, rng, tamper?.Ec, null);
        var kem = KemOt.KemBaseOtMalRandom(choices, rng, tamper?.Kem);
        var sid = HybridSessionId(kem.Sid, ec.S);
        var sender = HybridSenderEncrypt(sid, messages, ec.SenderPads, kem.SenderSecrets);
        tamper?.TamperEncrypted?.Invoke(sender.Encrypted);
        var received = HybridReceiverRecover(sid, choices, sender, ec.RecvPads, kem.RecvSecrets);
        return new HybridBaseOtResult(received, new HybridBaseOtTranscript(sid, ec.S, kem.Sid, sender.Encrypted, sender.Commitments));
    }

    /// <summary>The hybrid base OT as a pluggable base OT for Ot.OtChannel.</summary>
    public static BaseOtFn WithHybridBaseOt() => (m, c, r) => HybridBaseOT(m, c, r, null).Received;
}
