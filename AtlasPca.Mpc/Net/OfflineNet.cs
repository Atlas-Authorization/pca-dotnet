using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static AtlasPca.Mpc.Field;
using static AtlasPca.Mpc.NetPa;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares; every party samples its own MAC
/// key shares and triple shares, and the products needed for the triples and MACs are computed by Gilboa OT multiplication
/// between every ordered pair (kappa = 128 base OTs per ordered pair, OT extension with the KOS correlation check). Two
/// multiplication layers (products and the MACs of known values, then the MACs of the products) and a third layer giving every
/// share pairwise tags T_ij = K_ij + Delta_j * x_i, so the online phase can name a party that lies. Receivers choose with the
/// privacy-amplified encoding of their share (selective-failure remedy) under a gadget all parties contribute a signed seed to.
/// The triple sacrifice and the input-consistency check run online. No security proof; a wrong OT operand in the offline
/// triple products is attributable from the OT transcript only after the sacrifice fails (see <see cref="Prep.PrepForensics"/>).
/// </summary>
public static class OfflineNet
{
    /// <summary>Most OT rows per extension round (bounds frame size and memory).</summary>
    private const int ROWS_PER_ROUND = 128 * Enc.FIELD_BITS;
    private const int T_M = 3;
    private static readonly Regex Hex128Re = new(@"\A(0|[1-9a-f][0-9a-f]{0,31})\z", RegexOptions.CultureInvariant);

    /// <summary>The OT multiplication item: my choice bits (weights <c>Gad</c>, public) against my sender operand <c>Y</c>.</summary>
    private sealed record Item(int[] Bits, BigInteger[] Gad, BigInteger Y);

    private sealed record Rows(Dictionary<int, BigInteger[]> Recv, Dictionary<int, BigInteger[]> SendSum, Kept Kept);

    private sealed record Kept(Dictionary<int, Dictionary<int, BigInteger[]>> Recv, Dictionary<int, Dictionary<int, BigInteger[]>> Rho);

    private sealed record Layer(BigInteger[] Z, Kept Kept);

    private sealed record Cipher(BigInteger[] Y0, BigInteger[] Y1);

    private sealed record PointMsg(Ec.Point S, Ec.SchnorrProof Proof);

    private sealed record BaseCt(byte[][][] Ct, byte[][][] Com);

    private sealed class FuncSource : IFieldSource
    {
        private readonly Func<BigInteger> f;
        public FuncSource(Func<BigInteger> f) { this.f = f; }
        public BigInteger Next() => f();
    }

    private static byte[] Sha256(params byte[][] parts)
    {
        using var ms = new MemoryStream();
        foreach (byte[] p in parts) ms.Write(p, 0, p.Length);
        return SHA256.HashData(ms.ToArray());
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private static byte[] Le8(long v) => Otx.BigToBytes(new BigInteger(v), 8);

    private static long FromLe8(byte[] b)
    {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[i] & 0xffL);
        return v;
    }

    /// <summary>The public gadget: H(all seeds in party order, session) expanded by a hash chain; every party contributed a committed seed.</summary>
    internal static BigInteger[] GadgetFromSeeds(string sessionId, byte[][] seeds)
    {
        using var input = new MemoryStream();
        byte[] tag = Utf8("atlas-pca-mpc/enc-gadget");
        input.Write(tag, 0, tag.Length);
        byte[] sb = Utf8(sessionId);
        input.Write(sb, 0, sb.Length);
        foreach (byte[] sd in seeds) input.Write(sd, 0, sd.Length);
        byte[] seed = Sha256(input.ToArray());
        long ctr = 0;
        var src = new FuncSource(() =>
        {
            for (;;)
            {
                long v = FromLe8(Sha256(seed, Le8(ctr++))) & ((1L << 61) - 1);
                if (v != (1L << 61) - 1) return new BigInteger(v);
            }
        });
        return Enc.MakeGadget(Enc.STAT_SEC, src, false);
    }

    public static Prep Run(Protocol.OfflineCtx ctx) => new Session(ctx).Go();

    private static BigInteger Hex128(object? s)
    {
        if (s is not string t || !Hex128Re.IsMatch(t)) throw new ArgumentException("bad 128-bit value");
        return ParseHex(t);
    }

    private static List<object?> PairsB64(byte[][][] ps)
    {
        var outp = new List<object?>();
        foreach (byte[][] p in ps) outp.Add(new List<object?> { NetCodec.B64(p[0]), NetCodec.B64(p[1]) });
        return outp;
    }

    private static byte[][][] ParsePairs(object? raw, int count, int len)
    {
        if (raw is not List<object?> list || list.Count != count) throw new ArgumentException("bad pair array");
        var outp = new byte[count][][];
        for (int i = 0; i < count; i++)
        {
            if (list[i] is not List<object?> p || p.Count != 2) throw new ArgumentException("bad pair");
            outp[i] = new[] { NetCodec.Unb64(p[0], len), NetCodec.Unb64(p[1], len) };
        }
        return outp;
    }

    private static object EncodeU(Ot.ExtRoundMsg msg, int mExt)
    {
        int cb = (mExt + 7) / 8;
        using var bo = new MemoryStream();
        foreach (BigInteger c in msg.U)
        {
            byte[] b = Otx.BigToBytes(c, cb);
            bo.Write(b, 0, b.Length);
        }
        return new JD { ["u"] = NetCodec.B64(bo.ToArray()), ["x"] = Hex(msg.X), ["t"] = Hex(msg.TComb) };
    }

    private static Ot.ExtRoundMsg DecodeU(object? raw, int mExt)
    {
        if (raw is not JD o) throw new ArgumentException("bad extension message");
        int cb = (mExt + 7) / 8;
        byte[] bytes = NetCodec.Unb64(o.GetValueOrDefault("u"), Ot.KAPPA * cb);
        var u = new BigInteger[Ot.KAPPA];
        for (int i = 0; i < Ot.KAPPA; i++) u[i] = Otx.BytesToBig(bytes[(i * cb)..((i + 1) * cb)]);
        return new Ot.ExtRoundMsg(u, Hex128(o.GetValueOrDefault("x")), Hex128(o.GetValueOrDefault("t")));
    }

    private static byte[] PackLe8(BigInteger[] vs)
    {
        var outp = new byte[vs.Length * 8];
        for (int i = 0; i < vs.Length; i++) Buffer.BlockCopy(Otx.BigToBytes(vs[i], 8), 0, outp, i * 8, 8);
        return outp;
    }

    private static BigInteger[] UnpackLe8(byte[] b, int m)
    {
        var outp = new BigInteger[m];
        for (int i = 0; i < m; i++) outp[i] = Otx.BytesToBig(b[(i * 8)..(i * 8 + 8)]);
        return outp;
    }

    private static object EncodeY(Cipher c) => new JD { ["y0"] = NetCodec.B64(PackLe8(c.Y0)), ["y1"] = NetCodec.B64(PackLe8(c.Y1)) };

    private static Cipher DecodeY(object? raw, int m)
    {
        if (raw is not JD o) throw new ArgumentException("bad ciphertext message");
        return new Cipher(UnpackLe8(NetCodec.Unb64(o.GetValueOrDefault("y0"), m * 8), m), UnpackLe8(NetCodec.Unb64(o.GetValueOrDefault("y1"), m * 8), m));
    }

    private static int[][] Jag(int a, int b)
    {
        var r = new int[a][];
        for (int i = 0; i < a; i++) r[i] = new int[b];
        return r;
    }

    private static int[][][] Jag3(int a, int b, int c)
    {
        var r = new int[a][][];
        for (int i = 0; i < a; i++) r[i] = Jag(b, c);
        return r;
    }

    private sealed class Session
    {
        private readonly Protocol.OfflineCtx a;
        private readonly Mesh mesh;
        private readonly int id, n, C, K, P;
        private readonly IExchanger io;
        private readonly List<int> others = new();
        private readonly Ot.IOtRandom rng = Ot.SecureOtRandom();
        private readonly SecureFieldRng frng = new();
        private readonly byte[] sid;
        private readonly string behKind;
        private BigInteger delta;
        private BigInteger[] gadget = Array.Empty<BigInteger>();
        private readonly Dictionary<int, Ot.OtExtReceiver> recvCh = new();
        private readonly Dictionary<int, Ot.OtExtSender> sendCh = new();

        public Session(Protocol.OfflineCtx a)
        {
            this.a = a;
            mesh = a.Mesh;
            id = a.Id;
            n = a.N;
            C = a.C;
            K = a.Keys;
            P = a.Partners;
            io = a.Io;
            behKind = a.Behavior == null ? "" : a.Behavior.Kind;
            sid = Sha256(Utf8("atlas-pca-mpc/net-session/v2"), Utf8(mesh.SessionId()));
            for (int i = 0; i < n; i++) if (i != id) others.Add(i);
        }

        /// <summary>Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is <paramref name="recv"/> and extension sender is <paramref name="send"/>.</summary>
        private Ot.BaseOtBinding Chan(int recv, int send, string round) => new(sid, recv, send, round);

        private T OtGuard<T>(int peer, string what, Func<T> f)
        {
            try
            {
                return f();
            }
            catch (NetWire.NetAbort)
            {
                throw;
            }
            catch (Exception e)
            {
                string kind = e is Ot.BaseOtAbort || e is Ot.MalOtAbort || e is Ec.PointValidationError ? "ot-check" : "malformed";
                var ne = new NetWire.NetAbort(kind, peer, id, what + ": " + e.Message);
                mesh.Fail(ne, null);
                throw ne;
            }
        }

        private BigInteger[] Arr(int p, object? raw, int len)
        {
            BigInteger[]? r = NetWire.UnhxArray(raw, len);
            if (r == null) throw io.Bad(p, "expected " + len + " canonical field elements");
            return r;
        }

        public Prep Go()
        {
            delta = frng.Next();
            while (delta.IsZero) delta = frng.Next();

            // ---------------------------------------------------------------- base OTs (kappa per ordered pair, both roles)
            var seeds = new Dictionary<int, byte[][][]>();
            var mySetup = new Dictionary<int, Ot.SenderSetup>();
            var selector = new Dictionary<int, int[]>();
            foreach (int p in others)
            {
                var r = new Ot.OtExtReceiver(rng, Ot.BindingBytes(Chan(id, p, "iknp-kos")));
                seeds[p] = r.MakeSeeds();
                recvCh[p] = r;
                mySetup[p] = Ot.MalBaseOtSenderSetup(rng, Chan(id, p, "offline-kappa"));
                var s = new Ot.OtExtSender(rng, Ot.BindingBytes(Chan(p, id, "iknp-kos")));
                selector[p] = s.MakeSelector();
                sendCh[p] = s;
            }
            Dictionary<int, PointMsg> theirS = io.Exchange<PointMsg>("ob-S", peer =>
            {
                Ot.SenderSetup st = mySetup[peer];
                BigInteger z = behKind == "ot-proof-lie" ? st.Proof.Z + BigInteger.One : st.Proof.Z;
                return new JD { ["S"] = NetCodec.PtJ(st.S), ["U"] = NetCodec.PtJ(st.Proof.U), ["z"] = NetWire.Hx(z) };
            }, (p, raw) =>
            {
                if (raw is not JD o) throw io.Bad(p, "bad S message");
                var proof = new Ec.SchnorrProof(NetCodec.JPt(o.GetValueOrDefault("U")), NetCodec.HexBig(o.GetValueOrDefault("z")));
                return new PointMsg(NetCodec.JPt(o.GetValueOrDefault("S")), proof);
            });
            var respond = new Dictionary<int, Ot.ReceiverResponse>();
            foreach (int p in others)
            {
                PointMsg st = theirS[p];
                respond[p] = OtGuard(p, "base OT (receiver)", () => Ot.MalBaseOtReceiverRespond(st.S, st.Proof, selector[p], rng, Chan(p, id, "offline-kappa")));
            }
            Dictionary<int, Ec.Point[]> theirR = io.Exchange<Ec.Point[]>("ob-R", peer =>
            {
                var outp = new List<object?>();
                foreach (Ec.Point pt in respond[peer].R) outp.Add(NetCodec.PtJ(pt));
                return outp;
            }, (p, raw) =>
            {
                if (raw is not List<object?> list || list.Count != Ot.KAPPA) throw io.Bad(p, "bad R array");
                var pts = new Ec.Point[Ot.KAPPA];
                for (int i = 0; i < pts.Length; i++) pts[i] = NetCodec.JPt(list[i]);
                return pts;
            });
            var enc = new Dictionary<int, byte[][][][]>();
            foreach (int p in others)
            {
                Ot.SenderSetup st = mySetup[p];
                enc[p] = OtGuard(p, "base OT (sender)", () =>
                {
                    byte[][][] pads = Ot.MalBaseOtSenderDerive(st.Y, st.T, theirR[p], st.S, Chan(id, p, "offline-kappa"));
                    return Ot.BaseOtSenderEncrypt(seeds[p], pads);
                });
            }
            Dictionary<int, BaseCt> theirCt = io.Exchange<BaseCt>("ob-C", peer =>
                new JD { ["ct"] = PairsB64(enc[peer][0]), ["com"] = PairsB64(enc[peer][1]) }, (p, raw) =>
            {
                if (raw is not JD o) throw io.Bad(p, "bad ciphertext message");
                return new BaseCt(ParsePairs(o.GetValueOrDefault("ct"), Ot.KAPPA, 16), ParsePairs(o.GetValueOrDefault("com"), Ot.KAPPA, 32));
            });
            foreach (int p in others)
            {
                BaseCt m = theirCt[p];
                byte[][] got = OtGuard(p, "base OT (receiver)", () => Ot.BaseOtReceiverDecrypt(selector[p], respond[p].RecvPads, m.Ct, m.Com));
                sendCh[p].SetSeeds(got);
            }

            // ---------------------------------------------------------------- the jointly contributed choice-bit gadget (signed commit / reveal / echo)
            byte[][] seedsAgreed = Gadget.AgreeGadgetSeeds(mesh, n, io);
            gadget = GadgetFromSeeds(mesh.SessionId(), seedsAgreed);

            // ---------------------------------------------------------------- my randomness and the input sharings
            var alphaEnc = new Enc.EncShare[K];
            var alphaShare = new BigInteger[K];
            for (int l = 0; l < K; l++)
            {
                alphaEnc[l] = Enc.SampleEnc(gadget, frng);
                alphaShare[l] = alphaEnc[l].Value;
            }
            int[] tb = Thermometer.ThermometerEncode(a.Input.T, T_M);
            int[] rb = Thermometer.ThermometerEncode(a.Input.RQuant, a.Q);
            var myBits = new int[1 + tb.Length + rb.Length];
            myBits[0] = a.Input.Allow;
            Array.Copy(tb, 0, myBits, 1, tb.Length);
            Array.Copy(rb, 0, myBits, 1 + tb.Length, rb.Length);
            if (myBits.Length != C) throw new NetWire.NetAbort("local", null, id, "input chain count mismatch");
            var outShares = new Dictionary<int, BigInteger[]>();
            foreach (int p in others)
            {
                var sh = new BigInteger[C];
                for (int c = 0; c < C; c++) sh[c] = frng.Next();
                outShares[p] = sh;
            }
            var myOwn = new BigInteger[C];
            for (int c = 0; c < C; c++)
            {
                BigInteger s = new BigInteger(myBits[c]);
                foreach (int p in others) s = Fsub(s, outShares[p][c]);
                myOwn[c] = s;
            }
            Dictionary<int, BigInteger[]> gotShares = io.Exchange<BigInteger[]>("in-share", peer =>
            {
                var outp = new List<object?>();
                foreach (BigInteger v in outShares[peer]) outp.Add(NetWire.Hx(v));
                return outp;
            }, (p, raw) => Arr(p, raw, C));
            var inputValue = new BigInteger[n * C]; // my value share of every (owner, chain)
            for (int o = 0; o < n; o++) for (int c = 0; c < C; c++) inputValue[o * C + c] = o == id ? myOwn[c] : gotShares[o][c];
            BigInteger maskShare = frng.Next(); // my share of the input-check mask

            int nT = (n - 1) * C;
            var aE = new Enc.EncShare[nT];
            var bS = new BigInteger[nT];
            var ahE = new Enc.EncShare[nT][];
            for (int t = 0; t < nT; t++)
            {
                ahE[t] = new Enc.EncShare[P];
                aE[t] = Enc.SampleEnc(gadget, frng);
                bS[t] = frng.Next();
                for (int r = 0; r < P; r++) ahE[t][r] = Enc.SampleEnc(gadget, frng);
            }
            var aS = new BigInteger[nT];
            var ahS = new BigInteger[nT][];
            for (int t = 0; t < nT; t++)
            {
                ahS[t] = new BigInteger[P];
                aS[t] = aE[t].Value;
                for (int r = 0; r < P; r++) ahS[t][r] = ahE[t][r].Value;
            }

            // ---------------------------------------------------------------- layer 1: products and the MACs of known values
            var xs1 = new List<Enc.EncShare>();
            var ys1 = new List<BigInteger>();
            var iC = new int[nT];
            int[][] iCh = Jag(nT, P);
            int[][] iMa = Jag(nT, K);
            int[][] iMb = Jag(nT, K);
            int[][][] iMah = Jag3(nT, P, K);
            for (int t = 0; t < nT; t++)
            {
                iC[t] = Push(xs1, ys1, aE[t], bS[t]);
                for (int r = 0; r < P; r++) iCh[t][r] = Push(xs1, ys1, ahE[t][r], bS[t]);
                for (int l = 0; l < K; l++) iMa[t][l] = Push(xs1, ys1, alphaEnc[l], aS[t]);
                for (int l = 0; l < K; l++) iMb[t][l] = Push(xs1, ys1, alphaEnc[l], bS[t]);
                for (int r = 0; r < P; r++) for (int l = 0; l < K; l++) iMah[t][r][l] = Push(xs1, ys1, alphaEnc[l], ahS[t][r]);
            }
            int[][] iIn = Jag(n * C, K);
            for (int q = 0; q < n * C; q++) for (int l = 0; l < K; l++) iIn[q][l] = Push(xs1, ys1, alphaEnc[l], inputValue[q]);
            var iMask = new int[K];
            for (int l = 0; l < K; l++) iMask[l] = Push(xs1, ys1, alphaEnc[l], maskShare);
            var keepItems = new HashSet<int>();
            for (int t = 0; t < nT; t++)
            {
                keepItems.Add(iC[t]);
                for (int r = 0; r < P; r++) keepItems.Add(iCh[t][r]);
            }
            Layer l1 = MulLayer("1", xs1.ToArray(), ys1.ToArray(), behKind == "offline-lie" && nT > 0 ? iC[0] : -1, keepItems);
            BigInteger[] z1 = l1.Z;

            // ---------------------------------------------------------------- layer 2: the MACs of the products
            var cS = new BigInteger[nT];
            var chS = new BigInteger[nT][];
            for (int t = 0; t < nT; t++)
            {
                chS[t] = new BigInteger[P];
                cS[t] = z1[iC[t]];
                for (int r = 0; r < P; r++) chS[t][r] = z1[iCh[t][r]];
            }
            var xs2 = new List<Enc.EncShare>();
            var ys2 = new List<BigInteger>();
            int[][] iMc = Jag(nT, K);
            int[][][] iMch = Jag3(nT, P, K);
            for (int t = 0; t < nT; t++)
            {
                for (int l = 0; l < K; l++) iMc[t][l] = Push(xs2, ys2, alphaEnc[l], cS[t]);
                for (int r = 0; r < P; r++) for (int l = 0; l < K; l++) iMch[t][r][l] = Push(xs2, ys2, alphaEnc[l], chS[t][r]);
            }
            BigInteger[] z2 = MulLayer("2", xs2.ToArray(), ys2.ToArray(), -1, null).Z;

            // ---------------------------------------------------------------- assemble, then pairwise-tag every share
            var triples = new AW[nT][];
            for (int t = 0; t < nT; t++)
            {
                var sh = new AW[3 + 2 * P];
                sh[0] = MakeAw(aS[t], iMa[t], z1);
                sh[1] = MakeAw(bS[t], iMb[t], z1);
                sh[2] = MakeAw(cS[t], iMc[t], z2);
                for (int r = 0; r < P; r++)
                {
                    sh[3 + 2 * r] = MakeAw(ahS[t][r], iMah[t][r], z1);
                    sh[4 + 2 * r] = MakeAw(chS[t][r], iMch[t][r], z2);
                }
                triples[t] = sh;
            }
            var inputs = new AW[n * C];
            for (int q = 0; q < n * C; q++) inputs[q] = MakeAw(inputValue[q], iIn[q], z1);
            AW checkMask = MakeAw(maskShare, iMask, z1);
            var alpha = new PA[K];
            for (int l = 0; l < K; l++) alpha[l] = MakePa(alphaShare[l]);
            var allPA = new List<PA>(alpha);
            foreach (AW[] row in triples) foreach (AW w in row) AddAll(allPA, w);
            foreach (AW w in inputs) AddAll(allPA, w);
            AddAll(allPA, checkMask);
            var plain = new BigInteger[allPA.Count];
            for (int u = 0; u < plain.Length; u++) plain[u] = allPA[u].X;
            (Dictionary<int, BigInteger[]> tagBy, Dictionary<int, BigInteger[]> keyBy) = TagLayer("3", plain);
            for (int u = 0; u < plain.Length; u++)
            {
                foreach (int p in others)
                {
                    allPA[u].Tag[p] = tagBy[p][u];
                    allPA[u].Key[p] = keyBy[p][u];
                }
            }
            var myPlain = new BigInteger[C];
            for (int c = 0; c < C; c++) myPlain[c] = new BigInteger(myBits[c]);
            Kept kept1 = l1.Kept;
            var fx = new Prep.PrepForensics(gadget, gadget.Length, 1 + P, t =>
            {
                var outp = new List<NetForensics.SlotDisclosure>();
                outp.Add(Slot(kept1, iC[t], aE[t], bS[t], cS[t]));
                for (int r = 0; r < P; r++) outp.Add(Slot(kept1, iCh[t][r], ahE[t][r], bS[t], chS[t][r]));
                return outp;
            });
            return new Prep("no-dealer", true, delta, alpha, triples, inputs, myPlain, checkMask, fx);
        }

        private NetForensics.SlotDisclosure Slot(Kept kept, int item, Enc.EncShare x, BigInteger y, BigInteger z)
        {
            var recv = new Dictionary<int, BigInteger[]>();
            var rho = new Dictionary<int, BigInteger[]>();
            foreach (int p in others)
            {
                recv[p] = kept.Recv[p][item];
                rho[p] = kept.Rho[p][item];
            }
            return new NetForensics.SlotDisclosure((int[])x.Bits.Clone(), y, z, recv, rho);
        }

        private PA MakePa(BigInteger x)
        {
            var t = new BigInteger[n];
            var k = new BigInteger[n];
            Array.Fill(t, BigInteger.Zero);
            Array.Fill(k, BigInteger.Zero);
            return new PA(x, t, k);
        }

        private AW MakeAw(BigInteger value, int[] macIdx, BigInteger[] z)
        {
            var m = new PA[macIdx.Length];
            for (int i = 0; i < m.Length; i++) m[i] = MakePa(z[macIdx[i]]);
            return new AW(MakePa(value), m);
        }

        private static void AddAll(List<PA> outp, AW w)
        {
            outp.Add(w.V);
            outp.AddRange(w.M);
        }

        private static int Push(List<Enc.EncShare> xs, List<BigInteger> ys, Enc.EncShare x, BigInteger y)
        {
            xs.Add(x);
            ys.Add(y);
            return xs.Count - 1;
        }

        /// <summary>
        /// The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my xs[t] and get
        /// recv[p][t] = x_t*y^p_t + sum(rho^p_t); as the OT SENDER I offer (rho_k, rho_k + gad_k*ys[t]) with fresh masks and keep
        /// sendSum[p][t] = sum(rho). So recv - sendSum over the pair is an additive sharing of x_t*y_t.
        /// </summary>
        private Rows OtRows(string layer, Item[] items, HashSet<int>? keep)
        {
            int T = items.Length;
            var recv = new Dictionary<int, BigInteger[]>();
            var sendSum = new Dictionary<int, BigInteger[]>();
            var kept = new Kept(new(), new());
            foreach (int p in others)
            {
                var r = new BigInteger[T];
                var s = new BigInteger[T];
                Array.Fill(r, BigInteger.Zero);
                Array.Fill(s, BigInteger.Zero);
                recv[p] = r;
                sendSum[p] = s;
                kept.Recv[p] = new Dictionary<int, BigInteger[]>();
                kept.Rho[p] = new Dictionary<int, BigInteger[]>();
            }
            if (T == 0 || others.Count == 0) return new Rows(recv, sendSum, kept);
            int rows = 0;
            foreach (Item it in items) rows += it.Bits.Length;
            var rowItem = new int[rows];
            var choice = new int[rows];
            var m0 = new Dictionary<int, BigInteger[]>();
            var m1 = new Dictionary<int, BigInteger[]>();
            foreach (int p in others)
            {
                m0[p] = new BigInteger[rows];
                m1[p] = new BigInteger[rows];
            }
            int off = 0;
            var itemOff = new int[T];
            for (int t = 0; t < T; t++)
            {
                Item it = items[t];
                int len = it.Bits.Length;
                itemOff[t] = off;
                bool keepIt = keep != null && keep.Contains(t);
                if (keepIt)
                {
                    foreach (int p in others)
                    {
                        var z = new BigInteger[len];
                        Array.Fill(z, BigInteger.Zero);
                        kept.Recv[p][t] = z;
                    }
                }
                for (int k = 0; k < len; k++)
                {
                    choice[off + k] = it.Bits[k];
                    rowItem[off + k] = t;
                }
                foreach (int p in others)
                {
                    BigInteger[] a0 = m0[p], a1 = m1[p];
                    BigInteger sumRho = BigInteger.Zero;
                    for (int k = 0; k < len; k++)
                    {
                        BigInteger rho = frng.Next();
                        sumRho = Fadd(sumRho, rho);
                        a0[off + k] = rho;
                        a1[off + k] = Fadd(rho, Fmul(it.Gad[k], it.Y));
                    }
                    sendSum[p][t] = sumRho;
                    if (keepIt) kept.Rho[p][t] = a0[off..(off + len)];
                }
                off += len;
            }
            int chunk = 0;
            for (int start = 0; start < rows; start += ROWS_PER_ROUND, chunk++)
            {
                int s0 = start;
                int e0 = Math.Min(rows, start + ROWS_PER_ROUND);
                int m = e0 - s0;
                int mExt = m + Ot.KAPPA + Ot.SSEC;
                string tag = "ox" + layer + "." + chunk.ToString(CultureInfo.InvariantCulture);
                var begun = new Dictionary<int, Ot.OtExtReceiver.BeginResult>();
                if (behKind == "ot-u-lie")
                {
                    // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                    foreach (int p in others) recvCh[p].TamperU = (u, rd) => { for (int i = 0; i < 64; i++) u[i] = u[i] ^ BigInteger.One; };
                }
                foreach (int p in others) begun[p] = recvCh[p].Begin(choice[s0..e0]);
                Dictionary<int, Ot.ExtRoundMsg> us = io.Exchange<Ot.ExtRoundMsg>(tag + ".u", peer => EncodeU(begun[peer].Msg, mExt), (p, raw) => DecodeU(raw, mExt));
                var ys = new Dictionary<int, Ot.OtExtSender.Response>();
                foreach (int p in others)
                {
                    int pp = p;
                    ys[pp] = OtGuard(pp, "OT extension (" + tag + ")", () => sendCh[pp].Respond(us[pp], m0[pp][s0..e0], m1[pp][s0..e0]));
                }
                Dictionary<int, Cipher> cts = io.Exchange<Cipher>(tag + ".y", peer => EncodeY(new Cipher(ys[peer].Y0, ys[peer].Y1)), (p, raw) => DecodeY(raw, m));
                foreach (int p in others)
                {
                    int pp = p;
                    BigInteger[] got = OtGuard(pp, "OT extension (" + tag + ")", () => recvCh[pp].Finish(begun[pp].Pending, cts[pp].Y0, cts[pp].Y1));
                    BigInteger[] rv = recv[pp];
                    for (int j = 0; j < m; j++)
                    {
                        int t = rowItem[s0 + j];
                        rv[t] = Fadd(rv[t], Mod(got[j]));
                        if (keep != null && keep.Contains(t)) kept.Recv[pp][t][s0 + j - itemOff[t]] = Mod(got[j]);
                    }
                }
            }
            return new Rows(recv, sendSum, kept);
        }

        /// <summary>My additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus the Gilboa OT product of every ordered pair.</summary>
        private Layer MulLayer(string layer, Enc.EncShare[] xs, BigInteger[] ys, int lieAt, HashSet<int>? keep)
        {
            var z = new BigInteger[xs.Length];
            var items = new Item[xs.Length];
            for (int t = 0; t < xs.Length; t++)
            {
                z[t] = Fmul(xs[t].Value, ys[t]);
                items[t] = new Item(xs[t].Bits, gadget, t == lieAt ? Fadd(ys[t], BigInteger.One) : ys[t]);
            }
            Rows r = OtRows(layer, items, keep);
            foreach (int p in others)
            {
                BigInteger[] rv = r.Recv[p], ss = r.SendSum[p];
                for (int t = 0; t < z.Length; t++) z[t] = Fsub(Fadd(z[t], rv[t]), ss[t]);
            }
            return new Layer(z, r.Kept);
        }

        /// <summary>
        /// Pairwise tags for my shares: for every peer j a tag T_ij (mine) and a key K_ji with T_ij = K_ij + Delta_j*x_i. One OT
        /// product of my x with j's Delta per item; each x is split as x = e + d with a fresh encoded e (a derived value has no
        /// uniform choice-bit encoding of its own), both halves multiplied with Delta and added. Returns {tag, key} by peer.
        /// </summary>
        private (Dictionary<int, BigInteger[]> Tag, Dictionary<int, BigInteger[]> Key) TagLayer(string layer, BigInteger[] xs)
        {
            var items = new Item[2 * xs.Length];
            BigInteger[] plainGadget = Enc.PlainGadget();
            for (int u = 0; u < xs.Length; u++)
            {
                Enc.EncShare e = Enc.SampleEnc(gadget, frng);
                Enc.EncShare d = Enc.PlainShare(Fsub(xs[u], e.Value));
                items[2 * u] = new Item(e.Bits, gadget, delta);
                items[2 * u + 1] = new Item(d.Bits, plainGadget, delta);
            }
            Rows r = OtRows(layer, items, null);
            var tag = new Dictionary<int, BigInteger[]>();
            var key = new Dictionary<int, BigInteger[]>();
            foreach (int p in others)
            {
                BigInteger[] rv = r.Recv[p], kv = r.SendSum[p];
                var t = new BigInteger[xs.Length];
                var k = new BigInteger[xs.Length];
                for (int u = 0; u < xs.Length; u++)
                {
                    t[u] = Fadd(rv[2 * u], rv[2 * u + 1]);
                    k[u] = Fadd(kv[2 * u], kv[2 * u + 1]);
                }
                tag[p] = t;
                key[p] = k;
            }
            return (tag, key);
        }
    }
}
