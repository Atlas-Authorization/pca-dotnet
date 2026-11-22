using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using BaseOtFn = AtlasPca.Mpc.Ot.BaseOtFn;
using IOtRandom = AtlasPca.Mpc.Ot.IOtRandom;

namespace AtlasPca.Mpc;

/// <summary>
/// Post-quantum base OT from ML-KEM-768 (FIPS 203): the receiver publishes a public-key pair with a known secret key for only
/// its chosen slot, the sender encapsulates to both and pads each message with the shared secret. Variants: the semi-honest
/// transfer (KemBaseOT), the commit-then-open malicious-secure transfer with a session id (KemBaseOtMal), and
/// the random-OT form that outputs fixed-width secrets for the hybrid base OT (KemBaseOtMalRandom).
/// </summary>
public static class KemOt
{
    static readonly byte[] TagKemot = Utf8("atlas-pca-mpc/kem-ot-pad");
    static readonly byte[] TagKemotCommit = Utf8("atlas-pca-mpc/kem-ot-commit");
    static readonly byte[] TagKemotSid = Utf8("atlas-pca-mpc/kem-ot-sid");
    static readonly byte[] TagKemotMalpad = Utf8("atlas-pca-mpc/kem-ot-mal-pad");
    static readonly byte[] TagKemotMalsecret = Utf8("atlas-pca-mpc/kem-ot-mal-secret");
    const int NonceBytes = 32;
    public const int KEM_OT_SECRET_BYTES = 32;

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    static byte[] Sha256(params byte[][] chunks)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in chunks) h.AppendData(c);
        return h.GetHashAndReset();
    }

    static byte[] U32(long x) => Ot.U32(x);

    static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("kem-ot: XOR length mismatch");
        var o = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = (byte)(a[i] ^ b[i]);
        return o;
    }

    static bool CtEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    static byte[] Expand(byte[] tag, byte[][] prefix, long index, int slot, byte[] sharedSecret, int len)
    {
        var o = new byte[len];
        int produced = 0;
        long ctr = 0;
        while (produced < len)
        {
            var parts = new List<byte[]> { tag };
            parts.AddRange(prefix);
            parts.Add(U32(index));
            parts.Add(new[] { (byte)(slot & 1) });
            parts.Add(U32(ctr));
            parts.Add(sharedSecret);
            var block = Sha256(parts.ToArray());
            for (int k = 0; k < block.Length && produced < len; k++) o[produced++] = block[k];
            ctr++;
        }
        return o;
    }

    /// <summary>Pad of len bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode.</summary>
    public static byte[] KemOtPad(int index, int slot, byte[] sharedSecret, int len)
    {
        if (len < 0 || len > 1 << 20) throw new ArgumentException("kemOtPad: length must be an integer in [0, 1 MiB]");
        return Expand(TagKemot, Array.Empty<byte[]>(), index, slot, sharedSecret, len);
    }

    /// <summary>Receiver state of the semi-honest transfer.</summary>
    public sealed record KemOtReceiverState(int[] Choices, MLKemPrivateKeyParameters[] SecretKeys);

    public sealed record KemOtReceiverMessage(byte[][][] PublicKeys);

    public sealed record KemOtSenderMessage(byte[][][] Ciphertexts, byte[][][] Encrypted);

    public sealed record KemBaseOtTranscript(byte[][][] PublicKeys, byte[][][] Ciphertexts, byte[][][] Encrypted);

    public sealed record KemBaseOtResult(byte[][] Received, KemBaseOtTranscript Transcript);

    public sealed record ReceiverStep(KemOtReceiverMessage Message, KemOtReceiverState State);

    public static ReceiverStep KemBaseOtReceive(int[] choices, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        var publicKeys = new byte[choices.Length][][];
        var secretKeys = new MLKemPrivateKeyParameters[choices.Length];
        var retained = new int[choices.Length];
        for (int i = 0; i < choices.Length; i++)
        {
            int c = choices[i] & 1;
            var chosen = MlKem768.Keygen(rng.Bytes(MlKem768.KEYGEN_SEED_BYTES));
            var other = MlKem768.Keygen(rng.Bytes(MlKem768.KEYGEN_SEED_BYTES));
            publicKeys[i] = new[] { c == 0 ? chosen.PublicKey : other.PublicKey, c == 0 ? other.PublicKey : chosen.PublicKey };
            secretKeys[i] = chosen.SecretKey;
            retained[i] = c;
        }
        return new ReceiverStep(new KemOtReceiverMessage(publicKeys), new KemOtReceiverState(retained, secretKeys));
    }

    public static KemOtSenderMessage KemBaseOtSend(byte[][][] messages, KemOtReceiverMessage receiverMessage, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        var publicKeys = receiverMessage.PublicKeys;
        if (messages.Length != publicKeys.Length) throw new ArgumentException("kemBaseOtSend: messages/publicKeys length mismatch");
        var cts = new byte[messages.Length][][];
        var encrypted = new byte[messages.Length][][];
        for (int i = 0; i < messages.Length; i++)
        {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.Length != m1.Length) throw new ArgumentException("kemBaseOtSend (index " + i + "): the two messages must be equal length");
            var e0 = MlKem768.Encapsulate(publicKeys[i][0], rng.Bytes(MlKem768.MSG_BYTES));
            var e1 = MlKem768.Encapsulate(publicKeys[i][1], rng.Bytes(MlKem768.MSG_BYTES));
            cts[i] = new[] { e0.CipherText, e1.CipherText };
            encrypted[i] = new[] { Xor(m0, KemOtPad(i, 0, e0.SharedSecret, m0.Length)), Xor(m1, KemOtPad(i, 1, e1.SharedSecret, m1.Length)) };
        }
        return new KemOtSenderMessage(cts, encrypted);
    }

    public static byte[][] KemBaseOtOpen(KemOtReceiverState state, KemOtSenderMessage senderMessage)
    {
        int n = state.Choices.Length;
        if (senderMessage.Ciphertexts.Length != n || senderMessage.Encrypted.Length != n) throw new ArgumentException("kemBaseOtOpen: transcript/state length mismatch");
        var received = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            int c = state.Choices[i] & 1;
            var ss = MlKem768.Decapsulate(senderMessage.Ciphertexts[i][c], state.SecretKeys[i]);
            var e = senderMessage.Encrypted[i][c];
            received[i] = Xor(e, KemOtPad(i, c, ss, e.Length));
        }
        return received;
    }

    public static KemBaseOtResult KemBaseOT(byte[][][] messages, int[] choices, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        if (messages.Length != choices.Length) throw new ArgumentException("kemBaseOT: messages/choices length mismatch");
        var r = KemBaseOtReceive(choices, rng);
        var s = KemBaseOtSend(messages, r.Message, rng);
        var received = KemBaseOtOpen(r.State, s);
        return new KemBaseOtResult(received, new KemBaseOtTranscript(r.Message.PublicKeys, s.Ciphertexts, s.Encrypted));
    }

    /// <summary>The semi-honest KEM OT as a pluggable base OT for Ot.OtChannel.</summary>
    public static BaseOtFn WithKemBaseOt() => (m, c, r) => KemBaseOT(m, c, r).Received;

    // ---- malicious-secure (commit-then-open, session id) ----

    /// <summary>A KEM base OT aborted: the opened keys do not match the receiver's commitment.</summary>
    public sealed class KemBaseOtAbort : Exception
    {
        public KemBaseOtAbort(string message) : base(message) { }
    }

    static byte[] KemMalCommit(byte[] rn, int index, byte[] pk0, byte[] pk1) => Sha256(TagKemotCommit, rn, U32(index), pk0, pk1);

    static byte[] KemMalSid(byte[] rn, byte[] sn) => Sha256(TagKemotSid, rn, sn);

    static byte[] KemOtMalPad(byte[] sid, byte[] com, int index, int slot, byte[] ss, int len) =>
        Expand(TagKemotMalpad, new[] { sid, com }, index, slot, ss, len);

    static byte[] KemOtMalSecret(byte[] sid, byte[] com, int index, int slot, byte[] ss) =>
        Sha256(TagKemotMalsecret, sid, com, U32(index), new[] { (byte)(slot & 1) }, ss)[..KEM_OT_SECRET_BYTES];

    public sealed record KemMalCommitMessage(byte[] Rn, byte[][] Commitments);

    public sealed record KemMalOpenMessage(byte[][][] PublicKeys);

    public sealed record KemMalSenderNonce(byte[] Sn);

    public sealed record KemMalSenderMessage(byte[][][] Ciphertexts, byte[][][] Encrypted);

    public sealed record KemMalReceiverState(int[] Choices, MLKemPrivateKeyParameters[] SecretKeys, byte[][][] PublicKeys, byte[] Rn);

    public sealed record KemMalTranscript(byte[] Rn, byte[][] Commitments, byte[] Sn, byte[][][] PublicKeys, byte[][][] Ciphertexts, byte[][][] Encrypted);

    public sealed record KemBaseOtMalResult(byte[][] Received, KemMalTranscript Transcript);

    /// <summary>TEST-ONLY injection points for a malicious sender or receiver (null = honest).</summary>
    public sealed class KemMalTamper
    {
        public Action<byte[][][]>? TamperOpenedKeys;
        public Func<byte[], byte[]>? TamperReceiverSid;
    }

    public sealed record CommitStep(KemMalCommitMessage Message, KemMalReceiverState State);

    public static CommitStep KemBaseOtMalCommit(int[] choices, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        var rn = rng.Bytes(NonceBytes);
        var publicKeys = new byte[choices.Length][][];
        var secretKeys = new MLKemPrivateKeyParameters[choices.Length];
        var retained = new int[choices.Length];
        var commitments = new byte[choices.Length][];
        for (int i = 0; i < choices.Length; i++)
        {
            int c = choices[i] & 1;
            var chosen = MlKem768.Keygen(rng.Bytes(MlKem768.KEYGEN_SEED_BYTES));
            var other = MlKem768.Keygen(rng.Bytes(MlKem768.KEYGEN_SEED_BYTES));
            publicKeys[i] = new[] { c == 0 ? chosen.PublicKey : other.PublicKey, c == 0 ? other.PublicKey : chosen.PublicKey };
            secretKeys[i] = chosen.SecretKey;
            retained[i] = c;
            commitments[i] = KemMalCommit(rn, i, publicKeys[i][0], publicKeys[i][1]);
        }
        return new CommitStep(new KemMalCommitMessage(rn, commitments), new KemMalReceiverState(retained, secretKeys, publicKeys, rn));
    }

    public static KemMalSenderNonce KemBaseOtMalSenderNonce(IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        return new KemMalSenderNonce(rng.Bytes(NonceBytes));
    }

    /// <summary>The receiver's opening: a copy of its public-key pairs.</summary>
    public static KemMalOpenMessage KemBaseOtMalOpen(KemMalReceiverState state)
    {
        var pk = new byte[state.PublicKeys.Length][][];
        for (int i = 0; i < pk.Length; i++) pk[i] = new[] { state.PublicKeys[i][0], state.PublicKeys[i][1] };
        return new KemMalOpenMessage(pk);
    }

    public static KemMalSenderMessage KemBaseOtMalSend(byte[][][] messages, KemMalCommitMessage commit, KemMalSenderNonce senderNonce, KemMalOpenMessage opening, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        var publicKeys = opening.PublicKeys;
        if (messages.Length != publicKeys.Length || commit.Commitments.Length != publicKeys.Length)
            throw new ArgumentException("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch");
        var sid = KemMalSid(commit.Rn, senderNonce.Sn);
        var cts = new byte[messages.Length][][];
        var encrypted = new byte[messages.Length][][];
        for (int i = 0; i < messages.Length; i++)
        {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.Length != m1.Length) throw new ArgumentException("kemBaseOtMalSend (index " + i + "): the two messages must be equal length");
            var com = KemMalCommit(commit.Rn, i, publicKeys[i][0], publicKeys[i][1]);
            if (!CtEqual(com, commit.Commitments[i])) throw new KemBaseOtAbort("kem base OT (index " + i + "): opened public keys do not match the receiver's commitment; aborting");
            var e0 = MlKem768.Encapsulate(publicKeys[i][0], rng.Bytes(MlKem768.MSG_BYTES));
            var e1 = MlKem768.Encapsulate(publicKeys[i][1], rng.Bytes(MlKem768.MSG_BYTES));
            cts[i] = new[] { e0.CipherText, e1.CipherText };
            encrypted[i] = new[] { Xor(m0, KemOtMalPad(sid, com, i, 0, e0.SharedSecret, m0.Length)), Xor(m1, KemOtMalPad(sid, com, i, 1, e1.SharedSecret, m1.Length)) };
        }
        return new KemMalSenderMessage(cts, encrypted);
    }

    public static byte[][] KemBaseOtMalRecover(KemMalReceiverState state, KemMalSenderNonce senderNonce, KemMalSenderMessage senderMessage, KemMalTamper? tamper)
    {
        int n = state.Choices.Length;
        if (senderMessage.Ciphertexts.Length != n || senderMessage.Encrypted.Length != n) throw new ArgumentException("kemBaseOtMalRecover: transcript/state length mismatch");
        var sid = KemMalSid(state.Rn, senderNonce.Sn);
        if (tamper?.TamperReceiverSid != null) sid = tamper.TamperReceiverSid(sid);
        var received = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            int c = state.Choices[i] & 1;
            var com = KemMalCommit(state.Rn, i, state.PublicKeys[i][0], state.PublicKeys[i][1]);
            var ss = MlKem768.Decapsulate(senderMessage.Ciphertexts[i][c], state.SecretKeys[i]);
            var e = senderMessage.Encrypted[i][c];
            received[i] = Xor(e, KemOtMalPad(sid, com, i, c, ss, e.Length));
        }
        return received;
    }

    public static KemBaseOtMalResult KemBaseOtMal(byte[][][] messages, int[] choices, IOtRandom? rng, KemMalTamper? tamper)
    {
        rng ??= Ot.SecureOtRandom();
        if (messages.Length != choices.Length) throw new ArgumentException("kemBaseOtMal: messages/choices length mismatch");
        var cs = KemBaseOtMalCommit(choices, rng);
        var nonce = KemBaseOtMalSenderNonce(rng);
        var opening = KemBaseOtMalOpen(cs.State);
        tamper?.TamperOpenedKeys?.Invoke(opening.PublicKeys);
        var sm = KemBaseOtMalSend(messages, cs.Message, nonce, opening, rng);
        var received = KemBaseOtMalRecover(cs.State, nonce, sm, tamper);
        return new KemBaseOtMalResult(received, new KemMalTranscript(cs.Message.Rn, cs.Message.Commitments, nonce.Sn, opening.PublicKeys, sm.Ciphertexts, sm.Encrypted));
    }

    /// <summary>The malicious-secure KEM OT as a pluggable base OT for Ot.OtChannel.</summary>
    public static BaseOtFn WithKemBaseOtMal() => (m, c, r) => KemBaseOtMal(m, c, r, null).Received;

    // ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

    public sealed record KemMalRandomSenderMessage(byte[][][] Ciphertexts, byte[][][] SenderSecrets);

    public sealed record KemMalRandomTranscript(byte[] Rn, byte[][] Commitments, byte[] Sn, byte[][][] PublicKeys, byte[][][] Ciphertexts);

    public sealed record KemBaseOtMalRandomResult(byte[][][] SenderSecrets, byte[][] RecvSecrets, byte[] Sid, KemMalRandomTranscript Transcript);

    public static KemMalRandomSenderMessage KemBaseOtMalRandomSend(KemMalCommitMessage commit, KemMalSenderNonce senderNonce, KemMalOpenMessage opening, IOtRandom? rng)
    {
        rng ??= Ot.SecureOtRandom();
        var publicKeys = opening.PublicKeys;
        if (commit.Commitments.Length != publicKeys.Length) throw new ArgumentException("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch");
        var sid = KemMalSid(commit.Rn, senderNonce.Sn);
        var cts = new byte[publicKeys.Length][][];
        var secrets = new byte[publicKeys.Length][][];
        for (int i = 0; i < publicKeys.Length; i++)
        {
            var com = KemMalCommit(commit.Rn, i, publicKeys[i][0], publicKeys[i][1]);
            if (!CtEqual(com, commit.Commitments[i])) throw new KemBaseOtAbort("kem base OT (index " + i + "): opened public keys do not match the receiver's commitment; aborting");
            var e0 = MlKem768.Encapsulate(publicKeys[i][0], rng.Bytes(MlKem768.MSG_BYTES));
            var e1 = MlKem768.Encapsulate(publicKeys[i][1], rng.Bytes(MlKem768.MSG_BYTES));
            cts[i] = new[] { e0.CipherText, e1.CipherText };
            secrets[i] = new[] { KemOtMalSecret(sid, com, i, 0, e0.SharedSecret), KemOtMalSecret(sid, com, i, 1, e1.SharedSecret) };
        }
        return new KemMalRandomSenderMessage(cts, secrets);
    }

    public static byte[][] KemBaseOtMalRandomRecover(KemMalReceiverState state, KemMalSenderNonce senderNonce, KemMalRandomSenderMessage senderMessage, KemMalTamper? tamper)
    {
        int n = state.Choices.Length;
        if (senderMessage.Ciphertexts.Length != n) throw new ArgumentException("kemBaseOtMalRandomRecover: transcript/state length mismatch");
        var sid = KemMalSid(state.Rn, senderNonce.Sn);
        if (tamper?.TamperReceiverSid != null) sid = tamper.TamperReceiverSid(sid);
        var recv = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            int c = state.Choices[i] & 1;
            var com = KemMalCommit(state.Rn, i, state.PublicKeys[i][0], state.PublicKeys[i][1]);
            var ss = MlKem768.Decapsulate(senderMessage.Ciphertexts[i][c], state.SecretKeys[i]);
            recv[i] = KemOtMalSecret(sid, com, i, c, ss);
        }
        return recv;
    }

    public static KemBaseOtMalRandomResult KemBaseOtMalRandom(int[] choices, IOtRandom? rng, KemMalTamper? tamper)
    {
        rng ??= Ot.SecureOtRandom();
        var cs = KemBaseOtMalCommit(choices, rng);
        var nonce = KemBaseOtMalSenderNonce(rng);
        var opening = KemBaseOtMalOpen(cs.State);
        tamper?.TamperOpenedKeys?.Invoke(opening.PublicKeys);
        var sm = KemBaseOtMalRandomSend(cs.Message, nonce, opening, rng);
        var recv = KemBaseOtMalRandomRecover(cs.State, nonce, sm, tamper);
        return new KemBaseOtMalRandomResult(sm.SenderSecrets, recv, KemMalSid(cs.Message.Rn, nonce.Sn),
            new KemMalRandomTranscript(cs.Message.Rn, cs.Message.Commitments, nonce.Sn, opening.PublicKeys, sm.Ciphertexts));
    }
}
