using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static AtlasPca.Mpc.Otx;
using Point = AtlasPca.Mpc.Ec.Point;
using SchnorrProof = AtlasPca.Mpc.Ec.SchnorrProof;

namespace AtlasPca.Mpc;

/// <summary>
/// Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519
/// subgroup: the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the
/// core runs as a random OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check
/// (a deviating receiver is caught and the protocol aborts). Both roles run in one process; the functions take both parties'
/// inputs and return the receiver's outputs plus an inspectable transcript.
/// </summary>
public static class Ot
{
    /// <summary>IKNP security parameter (number of base OTs / width of the selector s).</summary>
    public const int KAPPA = 128;
    /// <summary>KOS statistical parameter: extra random check rows beyond the kappa that mask the revealed combination.</summary>
    public const int SSEC = 128;
    internal const int SEED_BYTES = KAPPA / 8;

    /// <summary>The KOS correlation check failed: a cheating OT-extension receiver is detected.</summary>
    public sealed class MalOtAbort : Exception
    {
        public MalOtAbort(string message) : base(message) { }
    }

    /// <summary>A base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected.</summary>
    public sealed class BaseOtAbort : Exception
    {
        public BaseOtAbort(string message) : base(message) { }
    }

    /// <summary>A source of scalars and seeds for OT needs.</summary>
    public interface IOtRandom
    {
        /// <summary>A uniform scalar in [1, L).</summary>
        BigInteger Scalar();
        /// <summary>n random bytes.</summary>
        byte[] Bytes(int n);
    }

    sealed class SecureRnd : IOtRandom
    {
        public BigInteger Scalar()
        {
            var bound = (BigInteger.One << 256) - ((BigInteger.One << 256) % Ec.L);
            var b = new byte[32];
            for (; ; )
            {
                RandomNumberGenerator.Fill(b);
                var acc = new BigInteger(b, isUnsigned: true, isBigEndian: true);
                if (acc >= bound) continue;
                var s = acc % Ec.L;
                if (!s.IsZero) return s;
            }
        }

        public byte[] Bytes(int n)
        {
            var b = new byte[n];
            RandomNumberGenerator.Fill(b);
            return b;
        }
    }

    /// <summary>The CSPRNG-backed default: scalars by rejection over 32 random bytes.</summary>
    public static IOtRandom SecureOtRandom() => new SecureRnd();

    /// <summary>A raw SplitMix64 stream (deterministic; for reproducible tests only).</summary>
    public static Func<long> SplitMix64(BigInteger seed)
    {
        ulong s = (ulong)(seed & ulong.MaxValue);
        return () =>
        {
            unchecked
            {
                s += 0x9e3779b97f4a7c15UL;
                ulong z = s;
                z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9UL;
                z = (z ^ (z >> 27)) * 0x94d049bb133111ebUL;
                return (long)(z ^ (z >> 31));
            }
        };
    }

    sealed class StreamRnd : IOtRandom
    {
        readonly Func<long> next64;
        public StreamRnd(Func<long> next64) { this.next64 = next64; }

        public BigInteger Scalar()
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                var acc = BigInteger.Zero;
                for (int i = 0; i < 4; i++) acc = (acc << 64) | new BigInteger(unchecked((ulong)next64()));
                var s = acc % Ec.L;
                if (!s.IsZero) return s;
            }
            throw new InvalidOperationException("otRandom: entropy stream returned zero scalars repeatedly (RNG failure)");
        }

        public byte[] Bytes(int n)
        {
            var o = new byte[n];
            int have = 0;
            while (have < n)
            {
                ulong v = unchecked((ulong)next64());
                for (int i = 0; i < 8 && have < n; i++)
                {
                    o[have++] = (byte)v;
                    v >>= 8;
                }
            }
            return o;
        }
    }

    /// <summary>An IOtRandom from a 64-bit stream (each long is an unsigned 64-bit value).</summary>
    public static IOtRandom OtRandom(Func<long> next64) => new StreamRnd(next64);

    static byte[] Sha256(params byte[][] chunks)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in chunks) h.AppendData(c);
        return h.GetHashAndReset();
    }

    internal static byte[] U32(long x) => new[] { (byte)(x >>> 24), (byte)(x >>> 16), (byte)(x >>> 8), (byte)x };

    static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    static byte[] Concat(params byte[][] parts)
    {
        int n = 0;
        foreach (var p in parts) n += p.Length;
        var o = new byte[n];
        int at = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, o, at, p.Length);
            at += p.Length;
        }
        return o;
    }

    /// <summary>Session binding of one base OT: who runs it, in which session and round (indices are uint32).</summary>
    public sealed record BaseOtBinding(byte[] SessionId, long SenderIndex, long ReceiverIndex, string Round);

    static readonly byte[] TagBinding = Utf8("atlas-pca-mpc/base-ot-binding");
    static readonly byte[] TagTranscript = Utf8("atlas-pca-mpc/base-ot-transcript");
    static readonly byte[] TagKdf = Utf8("atlas-pca-mpc/ot-kdf");
    static readonly byte[] TagKos = Utf8("atlas-pca-mpc/ot-kos");
    static readonly byte[] TagCommit = Utf8("atlas-pca-mpc/ot-msg-commit");

    /// <summary>Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input).</summary>
    public static byte[] BindingBytes(BaseOtBinding b)
    {
        if (b.SessionId == null || b.SessionId.Length < 8 || b.SessionId.Length > 64) throw new ArgumentException("base-OT binding: sessionId must be 8..64 bytes");
        if (b.SenderIndex < 0 || b.SenderIndex > 0xffffffffL) throw new ArgumentException("base-OT binding: senderIndex must be a uint32");
        if (b.ReceiverIndex < 0 || b.ReceiverIndex > 0xffffffffL) throw new ArgumentException("base-OT binding: receiverIndex must be a uint32");
        if (b.SenderIndex == b.ReceiverIndex) throw new ArgumentException("base-OT binding: sender and receiver must be different parties");
        var round = Utf8(b.Round);
        if (round.Length == 0 || round.Length > 64) throw new ArgumentException("base-OT binding: round label must be 1..64 bytes");
        return Concat(TagBinding, U32(b.SessionId.Length), b.SessionId, U32(b.SenderIndex), U32(b.ReceiverIndex), U32(round.Length), round);
    }

    /// <summary>A fresh binding for an in-process OT: a random 16-byte session id from rng.</summary>
    public static BaseOtBinding RandomBinding(IOtRandom rng, string round, long senderIndex, long receiverIndex) =>
        new(rng.Bytes(16), senderIndex, receiverIndex, round);

    public static BaseOtBinding RandomBinding(IOtRandom rng, string round) => RandomBinding(rng, round, 0, 1);

    /// <summary>Hash of the whole base-OT transcript: binding, S and every receiver point, in order.</summary>
    public static byte[] BaseOtTranscriptHash(BaseOtBinding binding, Point S, Point[] R)
    {
        var parts = new List<byte[]> { TagTranscript, BindingBytes(binding), Ec.EncodePoint(S), U32(R.Length) };
        foreach (var r in R) parts.Add(Ec.EncodePoint(r));
        return Sha256(parts.ToArray());
    }

    /// <summary>H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes.</summary>
    public static byte[] BaseOtKdf(byte[] transcriptHash, int index, Point Ri, Point p) =>
        Sha256(TagKdf, transcriptHash, U32(index), Ec.EncodePoint(Ri), Ec.EncodePoint(p))[..SEED_BYTES];

    /// <summary>The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u.</summary>
    public static int[] KosChiWords(byte[] binding, int round, BigInteger[] u, int mExt, byte[][]? colBytesList)
    {
        int colBytes = (mExt + 7) / 8;
        using var ms = new MemoryStream();
        void Absorb(byte[] b) => ms.Write(b, 0, b.Length);
        Absorb(TagKos);
        Absorb(U32(binding.Length));
        Absorb(binding);
        Absorb(U32(round));
        Absorb(U32(mExt));
        Absorb(U32(u.Length));
        if (colBytesList != null) { foreach (var cb in colBytesList) Absorb(cb); }
        else { foreach (var col in u) Absorb(BigToBytes(col, colBytes)); }
        var o = Shake.Shake256(ms.ToArray(), mExt * 16);
        return WordsFromLeBytes(o, mExt * 4);
    }

    public static BigInteger[] KosChallenges(byte[] binding, int round, BigInteger[] u, int mExt)
    {
        var w = KosChiWords(binding, round, u, mExt, null);
        var chi = new BigInteger[mExt];
        for (int j = 0; j < mExt; j++) chi[j] = GfToBig(w, 4 * j);
        return chi;
    }

    static byte[] XorBytes(byte[] a, byte[] b)
    {
        var o = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) o[i] = (byte)(a[i] ^ b[i]);
        return o;
    }

    // ---- base OT ----

    /// <summary>TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (null = honest).</summary>
    public sealed class BaseOtTamper
    {
        public Func<Point, Point>? TamperS;
        public Func<SchnorrProof, SchnorrProof>? TamperProof;
        public Action<Point[]>? TamperR;
        public Action<byte[][][]>? TamperCiphertext;
    }

    /// <summary>The base-OT transcript. Ct and Com hold [i][0/1] byte strings.</summary>
    public sealed record BaseOtTranscript(Point S, SchnorrProof Proof, Point[] R, byte[][][] Ct, byte[][][] Com);

    public sealed record BaseOtResult(byte[][] Received, BaseOtTranscript Transcript);

    /// <summary>A pluggable chosen-message base OT: messages[i] = {m0, m1}; returns the receiver's recovered messages.</summary>
    public delegate byte[][] BaseOtFn(byte[][][] messages, int[] choices, IOtRandom rng);

    /// <summary>Output of the malicious-secure random base OT: validated points and the two RO pads per index.</summary>
    public sealed record MalRandomOtResult(Point S, SchnorrProof Proof, Point[] R, byte[][][] SenderPads, byte[][] RecvPads);

    static byte[] OtCommit(int i, int b, byte[] msg, byte[] pad) =>
        Sha256(TagCommit, U32(i), new[] { (byte)(b & 1) }, msg, pad);

    public static MalRandomOtResult MalBaseRandomOT(int[] choices, IOtRandom? rng, BaseOtTamper? tamper, BaseOtBinding? binding)
    {
        rng ??= SecureOtRandom();
        binding ??= RandomBinding(rng, "base-ot");
        var setup = MalBaseOtSenderSetup(rng, binding);
        var S = tamper?.TamperS != null ? tamper.TamperS(setup.S) : setup.S;
        var proof = tamper?.TamperProof != null ? tamper.TamperProof(setup.Proof) : setup.Proof;
        var rr = MalBaseOtReceiverRespond(S, proof, choices, rng, binding);
        tamper?.TamperR?.Invoke(rr.R);
        var senderPads = MalBaseOtSenderDerive(setup.Y, setup.T, rr.R, S, binding);
        return new MalRandomOtResult(S, proof, rr.R, senderPads, rr.RecvPads);
    }

    public sealed record SenderSetup(BigInteger Y, Point T, Point S, SchnorrProof Proof);

    public static SenderSetup MalBaseOtSenderSetup(IOtRandom rng, BaseOtBinding binding)
    {
        var ctx = BindingBytes(binding);
        var y = rng.Scalar();
        var S = Ec.MulBase(y);
        var T = Ec.Mul(y, S);
        var proof = Ec.SchnorrProve(y, S, rng.Scalar, ctx);
        return new SenderSetup(y, T, S, proof);
    }

    public sealed record ReceiverResponse(Point[] R, byte[][] RecvPads);

    public static ReceiverResponse MalBaseOtReceiverRespond(Point S, SchnorrProof proof, int[] choices, IOtRandom rng, BaseOtBinding binding)
    {
        var ctx = BindingBytes(binding);
        Ec.AssertInSubgroup(S, "base-OT S (received by receiver)");
        if (!Ec.SchnorrVerify(S, proof, ctx)) throw new BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting");
        var R = new Point[choices.Length];
        var xs = new BigInteger[choices.Length];
        for (int i = 0; i < choices.Length; i++)
        {
            var x = rng.Scalar();
            int ci = choices[i] & 1;
            R[i] = ci == 1 ? Ec.AddPoints(Ec.MulBase(x), S) : Ec.MulBase(x);
            xs[i] = x;
        }
        var th = BaseOtTranscriptHash(binding, S, R);
        var recvPads = new byte[choices.Length][];
        for (int i = 0; i < choices.Length; i++) recvPads[i] = BaseOtKdf(th, i, R[i], Ec.Mul(xs[i], S));
        return new ReceiverResponse(R, recvPads);
    }

    public static byte[][][] MalBaseOtSenderDerive(BigInteger y, Point T, Point[] R, Point S, BaseOtBinding binding)
    {
        for (int i = 0; i < R.Length; i++) Ec.AssertInSubgroup(R[i], "base-OT R_" + i + " (received by sender)");
        var th = BaseOtTranscriptHash(binding, S, R);
        var pads = new byte[R.Length][][];
        for (int i = 0; i < R.Length; i++)
        {
            var yR = Ec.Mul(y, R[i]);
            pads[i] = new[] { BaseOtKdf(th, i, R[i], yR), BaseOtKdf(th, i, R[i], Ec.Sub(yR, T)) };
        }
        return pads;
    }

    /// <summary>One-time-pads the messages under the sender pads and commits to each (message, pad). Returns {ct, com}.</summary>
    public static byte[][][][] BaseOtSenderEncrypt(byte[][][] messages, byte[][][] senderPads)
    {
        if (messages.Length != senderPads.Length) throw new ArgumentException("baseOT: messages/pads length mismatch");
        for (int i = 0; i < messages.Length; i++)
        {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.Length > SEED_BYTES || m1.Length > SEED_BYTES || m0.Length != m1.Length)
                throw new ArgumentException("baseOT: message pair " + i + " must be equal length and at most " + SEED_BYTES + " bytes (pad width)");
        }
        var ct = new byte[messages.Length][][];
        var com = new byte[messages.Length][][];
        for (int i = 0; i < messages.Length; i++)
        {
            byte[] p0 = senderPads[i][0], p1 = senderPads[i][1];
            ct[i] = new[] { XorBytes(messages[i][0], p0), XorBytes(messages[i][1], p1) };
            com[i] = new[] { OtCommit(i, 0, messages[i][0], p0), OtCommit(i, 1, messages[i][1], p1) };
        }
        return new[] { ct, com };
    }

    public static byte[][] BaseOtReceiverDecrypt(int[] choices, byte[][] recvPads, byte[][][] ct, byte[][][] com)
    {
        if (ct.Length != choices.Length || com.Length != choices.Length || recvPads.Length != choices.Length)
            throw new BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting");
        var received = new byte[choices.Length][];
        for (int i = 0; i < choices.Length; i++)
        {
            int ci = choices[i] & 1;
            byte[] c0 = ct[i][0], c1 = ct[i][1];
            if (c0.Length != c1.Length || c0.Length > SEED_BYTES) throw new BaseOtAbort("base OT (index " + i + "): malformed ciphertext shape; aborting");
            var m = XorBytes(ct[i][ci], recvPads[i]);
            var check = OtCommit(i, ci, m, recvPads[i]);
            if (!CryptographicOperations.FixedTimeEquals(check, com[i][ci])) throw new BaseOtAbort("base OT (index " + i + "): sender ciphertext inconsistent with its commitment; aborting");
            received[i] = m;
        }
        return received;
    }

    /// <summary>Chosen-message 1-of-2 OT for choices.Length transfers, built over the random base OT.</summary>
    public static BaseOtResult BaseOT(byte[][][] messages, int[] choices, IOtRandom? rng, BaseOtTamper? tamper, BaseOtBinding? binding)
    {
        rng ??= SecureOtRandom();
        binding ??= RandomBinding(rng, "base-ot");
        if (messages.Length != choices.Length) throw new ArgumentException("baseOT: messages/choices length mismatch");
        var ro = MalBaseRandomOT(choices, rng, tamper, binding);
        var enc = BaseOtSenderEncrypt(messages, ro.SenderPads);
        var ct = enc[0];
        var com = enc[1];
        tamper?.TamperCiphertext?.Invoke(ct);
        var received = BaseOtReceiverDecrypt(choices, ro.RecvPads, ct, com);
        return new BaseOtResult(received, new BaseOtTranscript(ro.S, ro.Proof, ro.R, ct, com));
    }

    // ---- OT extension (IKNP + KOS) ----

    /// <summary>The receiver's extension-round message: the u columns and the KOS values (x, t).</summary>
    public sealed record ExtRoundMsg(BigInteger[] U, BigInteger X, BigInteger TComb);

    /// <summary>The receiver's per-round state between Begin and Finish.</summary>
    public sealed record ExtPending(int M, int[] ChoiceBits, int[] T, int W, long RowOffset);

    static void CheckExtInputs(int[] choiceBits, BigInteger[]? msg0, BigInteger[]? msg1)
    {
        int m = choiceBits.Length;
        var limit = BigInteger.One << 64;
        for (int j = 0; j < m; j++)
            if (choiceBits[j] != 0 && choiceBits[j] != 1) throw new ArgumentException("OtChannel.extend: choice bit " + j + " must be 0 or 1");
        if (msg0 != null && msg1 != null)
        {
            for (int j = 0; j < m; j++)
            {
                BigInteger? a = j < msg0.Length ? msg0[j] : null, b = j < msg1.Length ? msg1[j] : null;
                if (a == null || b == null || a.Value.Sign < 0 || b.Value.Sign < 0 || a.Value >= limit || b.Value >= limit)
                    throw new ArgumentException("OtChannel.extend: message " + j + " must be a bigint in [0, 2^64) (the pad is 64 bits wide)");
            }
        }
    }

    /// <summary>The extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values.</summary>
    public sealed class OtExtReceiver
    {
        readonly IOtRandom rng;
        readonly byte[] kosBinding;
        readonly List<byte[]> seed0 = new(), seed1 = new();
        readonly long[] blk0 = new long[KAPPA], blk1 = new long[KAPPA];
        int round = 0;
        long rowsDone = 0;
        readonly int[] tweakDomain;
        public bool Ready = false;
        /// <summary>TEST-ONLY: mutate the u columns on the wire (a malicious receiver).</summary>
        public Action<BigInteger[], int>? TamperU;

        public OtExtReceiver(IOtRandom rng, byte[] kosBinding)
        {
            this.rng = rng;
            this.kosBinding = kosBinding;
            tweakDomain = OtTweakDomain(kosBinding);
        }

        /// <summary>The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices.</summary>
        public byte[][][] MakeSeeds()
        {
            var messages = new byte[KAPPA][][];
            for (int i = 0; i < KAPPA; i++)
            {
                var k0 = rng.Bytes(SEED_BYTES);
                var k1 = rng.Bytes(SEED_BYTES);
                seed0.Add(k0);
                seed1.Add(k1);
                messages[i] = new[] { k0, k1 };
            }
            Ready = true;
            return messages;
        }

        public sealed record BeginResult(ExtRoundMsg Msg, ExtPending Pending);

        public BeginResult Begin(int[] choiceBits)
        {
            if (!Ready) throw new InvalidOperationException("OtExtReceiver: base OT not done");
            CheckExtInputs(choiceBits, null, null);
            int m = choiceBits.Length;
            int roundIdx = round++;
            long rowOffset = rowsDone;
            rowsDone += m;
            int pad = KAPPA + SSEC;
            int mExt = m + pad;
            int W = (mExt + 31) >>> 5;
            int colBytes = (mExt + 7) / 8;
            var bvec = new int[W];
            for (int j = 0; j < m; j++) if ((choiceBits[j] & 1) != 0) bvec[j >>> 5] |= 1 << (j & 31);
            var padBytes = rng.Bytes(pad);
            for (int p = 0; p < pad; p++)
            {
                if ((padBytes[p] & 1) != 0)
                {
                    int j = m + p;
                    bvec[j >>> 5] |= 1 << (j & 31);
                }
            }
            int blocks = (W + 3) / 4;
            var t = new int[COLS * W];
            var u = new BigInteger[COLS];
            var uw = new int[W];
            var ubytes = new byte[COLS][];
            for (int i = 0; i < KAPPA; i++)
            {
                var ti = PrgColumn(seed0[i], blk0[i], W);
                var gi = PrgColumn(seed1[i], blk1[i], W);
                blk0[i] += blocks;
                blk1[i] += blocks;
                MaskTail(ti, mExt);
                MaskTail(gi, mExt);
                Array.Copy(ti, 0, t, i * W, W);
                for (int w = 0; w < W; w++) uw[w] = gi[w] ^ ti[w] ^ bvec[w];
                var all = new byte[4 * W];
                for (int w = 0; w < W; w++)
                {
                    all[4 * w] = (byte)uw[w];
                    all[4 * w + 1] = (byte)(uw[w] >>> 8);
                    all[4 * w + 2] = (byte)(uw[w] >>> 16);
                    all[4 * w + 3] = (byte)(uw[w] >>> 24);
                }
                ubytes[i] = all[..colBytes];
                u[i] = BytesToBig(ubytes[i]);
            }
            TamperU?.Invoke(u, roundIdx);
            var pending = new ExtPending(m, (int[])choiceBits.Clone(), t, W, rowOffset);
            var limit = BigInteger.One << mExt;
            foreach (var c in u)
            {
                if (c.Sign < 0 || c >= limit) return new BeginResult(new ExtRoundMsg(u, BigInteger.Zero, BigInteger.Zero), pending);
            }
            var chi = KosChiWords(kosBinding, roundIdx, u, mExt, TamperU != null ? null : ubytes);
            var x = new int[4];
            AccumColumn(bvec, 0, W, chi, x);
            var tComb = KosCombine(t, W, chi);
            return new BeginResult(new ExtRoundMsg(u, GfToBig(x), GfToBig(tComb)), pending);
        }

        /// <summary>The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts.</summary>
        public BigInteger[] Finish(ExtPending pending, BigInteger[] y0, BigInteger[] y1)
        {
            int m = pending.M;
            if (y0.Length != m || y1.Length != m) throw new MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting");
            var rows = TransposeCols(pending.T, pending.W, m);
            var h = TmmoCrh(rows, m, new OtTweak(pending.RowOffset, tweakDomain));
            var received = new BigInteger[m];
            for (int j = 0; j < m; j++) received[j] = (pending.ChoiceBits[j] == 1 ? y1[j] : y0[j]) ^ Word64(h, j);
            return received;
        }
    }

    /// <summary>The extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check.</summary>
    public sealed class OtExtSender
    {
        readonly IOtRandom rng;
        readonly byte[] kosBinding;
        int[] s = Array.Empty<int>();
        BigInteger sBits = BigInteger.Zero;
        byte[][] seeds = Array.Empty<byte[]>();
        long[] blk = Array.Empty<long>();
        int round = 0;
        long rowsDone = 0;
        readonly int[] tweakDomain;
        public bool Ready = false;

        public OtExtSender(IOtRandom rng, byte[] kosBinding)
        {
            this.rng = rng;
            this.kosBinding = kosBinding;
            tweakDomain = OtTweakDomain(kosBinding);
        }

        public int[] MakeSelector()
        {
            s = new int[KAPPA];
            for (int i = 0; i < KAPPA; i++) s[i] = rng.Bytes(1)[0] & 1;
            return (int[])s.Clone();
        }

        public void SetSeeds(byte[][] seeds)
        {
            if (seeds.Length != KAPPA || s.Length != KAPPA) throw new InvalidOperationException("OtExtSender: wrong base-OT output size");
            this.seeds = seeds;
            blk = new long[KAPPA];
            var acc = BigInteger.Zero;
            for (int i = 0; i < KAPPA; i++) if (s[i] == 1) acc |= BigInteger.One << i;
            sBits = acc;
            Ready = true;
        }

        public BigInteger Selector() => sBits;

        public sealed record Response(BigInteger[] Y0, BigInteger[] Y1);

        public Response Respond(ExtRoundMsg msg, BigInteger[] msg0, BigInteger[] msg1)
        {
            if (!Ready) throw new InvalidOperationException("OtExtSender: base OT not done");
            int m = msg0.Length;
            if (msg1.Length != m) throw new ArgumentException("OtChannel.extend: length mismatch");
            CheckExtInputs(new int[m], msg0, msg1);
            int roundIdx = round++;
            long rowOffset = rowsDone;
            rowsDone += m;
            int mExt = m + KAPPA + SSEC;
            var u = msg.U;
            if (u == null || u.Length != KAPPA)
                throw new MalOtAbort("KOS check (round " + roundIdx + "): wrong number of u columns; a cheating OT-extension receiver was detected; aborting");
            var colLimit = BigInteger.One << mExt;
            for (int i = 0; i < KAPPA; i++)
            {
                var ui = u[i];
                if (ui.Sign < 0 || ui >= colLimit)
                    throw new MalOtAbort("KOS check (round " + roundIdx + "): malformed u column " + i + "; a cheating OT-extension receiver was detected; aborting");
            }
            var lim128 = BigInteger.One << 128;
            if (msg.X.Sign < 0 || msg.X >= lim128 || msg.TComb.Sign < 0 || msg.TComb >= lim128)
                throw new MalOtAbort("KOS check (round " + roundIdx + "): malformed (x, t); a cheating OT-extension receiver was detected; aborting");
            int W = (mExt + 31) >>> 5;
            int colBytes = (mExt + 7) / 8;
            int blocks = (W + 3) / 4;
            var q = new int[COLS * W];
            var ubytes = new byte[COLS][];
            for (int i = 0; i < KAPPA; i++)
            {
                ubytes[i] = BigToBytes(u[i], colBytes);
                var ks = PrgColumn(seeds[i], blk[i], W);
                blk[i] += blocks;
                MaskTail(ks, mExt);
                if (s[i] == 1)
                {
                    var ub = new byte[4 * W];
                    Array.Copy(ubytes[i], 0, ub, 0, ubytes[i].Length);
                    var uw = WordsFromLeBytes(ub, W);
                    for (int w = 0; w < W; w++) ks[w] ^= uw[w];
                }
                Array.Copy(ks, 0, q, i * W, W);
            }
            var chi = KosChiWords(kosBinding, roundIdx, u, mExt, ubytes);
            var qComb = GfToBig(KosCombine(q, W, chi));
            var expected = msg.TComb ^ Gf128.Mul(msg.X, sBits);
            if (qComb != expected)
                throw new MalOtAbort("KOS correlation check FAILED (round " + roundIdx + "): a cheating OT-extension receiver was detected; aborting");
            var rows = TransposeCols(q, W, m);
            var tweak = new OtTweak(rowOffset, tweakDomain);
            var h0 = TmmoCrh(rows, m, tweak);
            var sw = GfFromBig(sBits);
            var row = new int[4];
            for (int j = 0; j < m; j++)
            {
                Array.Copy(rows, 4 * j, row, 0, 4);
                GfXorInto(row, sw, 0);
                Array.Copy(row, 0, rows, 4 * j, 4);
            }
            var h1 = TmmoCrh(rows, m, tweak);
            var y0 = new BigInteger[m];
            var y1 = new BigInteger[m];
            for (int j = 0; j < m; j++)
            {
                y0[j] = msg0[j] ^ Word64(h0, j);
                y1[j] = msg1[j] ^ Word64(h1, j);
            }
            return new Response(y0, y1);
        }
    }

    /// <summary>
    /// An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later Extend(). The base
    /// OT is the EC base OT unless baseOtFn supplies another (for example a post-quantum one).
    /// </summary>
    public sealed class OtChannel
    {
        readonly IOtRandom rng;
        readonly BaseOtFn? baseOtFn;
        readonly BaseOtBinding? bindingOpt;
        OtExtReceiver recv = null!;
        OtExtSender send = null!;
        bool ready = false;
        /// <summary>The EC base-OT transcript of the kappa setup transfers (null when a custom base OT is used).</summary>
        public BaseOtTranscript? BaseTranscript;
        /// <summary>TEST-ONLY: mutate the extension receiver's u matrix.</summary>
        public Action<BigInteger[], int>? TamperU;

        /// <param name="binding">only SessionId, SenderIndex and ReceiverIndex are used; its round is ignored. May be null.</param>
        public OtChannel(IOtRandom? rng, BaseOtFn? baseOtFn, BaseOtBinding? binding)
        {
            this.rng = rng ?? SecureOtRandom();
            this.baseOtFn = baseOtFn;
            bindingOpt = binding;
        }

        public OtChannel(IOtRandom? rng) : this(rng, null, null) { }

        void Setup()
        {
            var bas = bindingOpt ?? RandomBinding(rng, "x");
            var kos = BindingBytes(new BaseOtBinding(bas.SessionId, bas.SenderIndex, bas.ReceiverIndex, "iknp-kos"));
            var r = new OtExtReceiver(rng, kos);
            var sd = new OtExtSender(rng, kos);
            var messages = r.MakeSeeds();
            var sel = sd.MakeSelector();
            if (baseOtFn != null)
            {
                sd.SetSeeds(baseOtFn(messages, sel, rng));
            }
            else
            {
                var res = BaseOT(messages, sel, rng, null, new BaseOtBinding(bas.SessionId, bas.SenderIndex, bas.ReceiverIndex, "iknp-kappa-setup"));
                sd.SetSeeds(res.Received);
                BaseTranscript = res.Transcript;
            }
            recv = r;
            send = sd;
            ready = true;
        }

        public BigInteger Selector()
        {
            if (!ready) Setup();
            return send.Selector();
        }

        public sealed record Extended(BigInteger[] Received, BigInteger[] UMatrix);

        public Extended Extend(int[] choiceBits, BigInteger[] msg0, BigInteger[] msg1)
        {
            if (!ready) Setup();
            int m = choiceBits.Length;
            if (msg0.Length != m || msg1.Length != m) throw new ArgumentException("OtChannel.extend: length mismatch");
            if (m == 0) return new Extended(Array.Empty<BigInteger>(), Array.Empty<BigInteger>());
            CheckExtInputs(choiceBits, msg0, msg1);
            recv.TamperU = TamperU;
            var b = recv.Begin(choiceBits);
            var r = send.Respond(b.Msg, msg0, msg1);
            return new Extended(recv.Finish(b.Pending, r.Y0, r.Y1), b.Msg.U);
        }
    }
}
