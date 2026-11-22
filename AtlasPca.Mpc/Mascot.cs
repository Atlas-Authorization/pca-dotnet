using System.Numerics;
using static AtlasPca.Mpc.Field;
using EncShare = AtlasPca.Mpc.Enc.EncShare;
using OtChannel = AtlasPca.Mpc.Ot.OtChannel;

namespace AtlasPca.Mpc;

/// <summary>
/// The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real
/// oblivious transfers (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and
/// every produced triple is certified by the sacrifice check. When a check fails the OT transcripts are searched to blame the
/// cheating party.
/// </summary>
public static class Mascot
{
    /// <summary>A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named).</summary>
    public sealed class OfflineCheatingAbort : Spdz.MacCheckAbort
    {
        readonly List<int> blamed;

        public OfflineCheatingAbort(string message, List<int> blamed)
            : base(blamed.Count == 0 ? message : message + "; offline OT transcript names party " + string.Join(", ", blamed))
        {
            this.blamed = blamed;
        }

        public List<int> Blamed() => blamed;
    }

    sealed record OtRecord(int Receiver, int Sender, BigInteger[] Msg0, BigInteger[] Msg1, BigInteger[] Received);

    sealed record ProductClaim(BigInteger[] Claimed, BigInteger[] Implied);

    /// <summary>TEST-ONLY: the productMul-th product's claimed share is shifted by delta (a cheating party lying about a product).</summary>
    public sealed record OfflineDeviation(int ProductMul, BigInteger Delta);

    /// <summary>Options (null fields mean the defaults).</summary>
    public sealed class NoDealerOptions
    {
        public bool? Sacrifice;
        public int? SacrificePartners;
        public int? MacKeys;
        public OfflineDeviation? Deviation;
        public int? StatSec;
        public bool UnsafeStatSec;
    }

    /// <summary>One operand of a multiplication request: either a plain value (BigInteger) or an encoded (value, choice bits) share.</summary>
    sealed record Req(List<object> X, BigInteger[] Y);

    sealed record Part(int[] Bits, BigInteger[] Gad);

    sealed record Piece(BigInteger Value, List<Part> Parts);

    sealed record Seg(int Q, int Start, int Len, BigInteger SenderSum);

    public sealed class NoDealerOffline : IOfflineProvider
    {
        readonly int n;
        public readonly BigInteger[] AlphaShares;
        readonly BigInteger[][] keyShares;
        readonly EncShare[][] keyEnc;
        readonly BigInteger[] gadget;
        public readonly int StatSec;
        readonly int sacrificePartners;
        readonly FieldRng rng;
        readonly BigInteger seed;
        readonly bool deterministic;
        readonly Dictionary<string, OtChannel> channels = new();
        readonly bool sacrificeOn;
        readonly OfflineDeviation? deviation;
        int productMulCount = 0;
        List<OtRecord>? log = null;
        List<ProductClaim> claims = new();

        public NoDealerOffline(int n, BigInteger? seed, NoDealerOptions? opts)
        {
            opts ??= new NoDealerOptions();
            if (n < 1) throw new ArgumentException("NoDealerOffline: n must be a positive integer");
            this.n = n;
            deterministic = seed != null;
            this.seed = seed ?? ParseHex("abcdef12345");
            rng = deterministic ? new FieldRng(this.seed) : new SecureFieldRng();
            sacrificeOn = opts.Sacrifice ?? true;
            deviation = opts.Deviation;
            int keys = opts.MacKeys ?? Spdz.MAC_KEYS;
            if (keys < 1 || keys > 16) throw new ArgumentException("NoDealerOffline: macKeys must be an integer in [1, 16]");
            StatSec = opts.StatSec ?? Enc.STAT_SEC;
            gadget = Enc.MakeGadget(StatSec, rng, opts.UnsafeStatSec);
            keyEnc = new EncShare[keys][];
            for (int l = 0; l < keys; l++)
            {
                keyEnc[l] = new EncShare[n];
                for (int i = 0; i < n; i++) keyEnc[l][i] = Enc.SampleEnc(gadget, rng);
            }
            keyShares = new BigInteger[keys][];
            for (int l = 0; l < keys; l++)
            {
                keyShares[l] = new BigInteger[n];
                for (int i = 0; i < n; i++) keyShares[l][i] = keyEnc[l][i].Value;
            }
            AlphaShares = keyShares[0];
            sacrificePartners = opts.SacrificePartners ?? Spdz.SACRIFICE_PARTNERS;
            if (sacrificePartners < 1 || sacrificePartners > 8) throw new ArgumentException("NoDealerOffline: sacrificePartners must be an integer in [1, 8]");
        }

        public int N() => n;

        /// <summary>The MAC context: the shares of each key and (for tests and the check only) their sums.</summary>
        public Spdz.MacContext MacContext()
        {
            var keys = new List<Spdz.MacKey>();
            foreach (var shares in keyShares)
            {
                var alpha = BigInteger.Zero;
                foreach (var ai in shares) alpha = Fadd(alpha, ai);
                keys.Add(new Spdz.MacKey((BigInteger[])shares.Clone(), alpha));
            }
            return new Spdz.MacContext(n, keys[0].AlphaShares, keys[0].Alpha, keys.GetRange(1, keys.Count - 1));
        }

        OtChannel Channel(int i, int j)
        {
            var key = i + "->" + j;
            if (!channels.TryGetValue(key, out var ch))
            {
                var otRng = deterministic
                    ? Ot.OtRandom(Ot.SplitMix64((seed ^ (new BigInteger(i + 1) * ParseHex("100000001b3"))) ^ (new BigInteger(j + 1) * ParseHex("1000000000"))))
                    : Ot.SecureOtRandom();
                ch = new OtChannel(otRng);
                channels[key] = ch;
            }
            return ch;
        }

        EncShare SampleShare() => Enc.SampleEnc(gadget, rng);

        /// <summary>Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request.</summary>
        BigInteger[][] MulBatch(List<Req> reqs)
        {
            foreach (var r in reqs) if (r.X.Count != n || r.Y.Length != n) throw new ArgumentException("otShareMultiply: wrong length");
            var pieces = new List<List<Piece>>();
            foreach (var r in reqs)
            {
                var row = new List<Piece>();
                foreach (var xi in r.X)
                {
                    if (xi is EncShare e0)
                    {
                        row.Add(new Piece(e0.Value, new List<Part> { new Part(e0.Bits, gadget) }));
                    }
                    else
                    {
                        var v = Mod((BigInteger)xi);
                        var e = Enc.SampleEnc(gadget, rng);
                        var d = Enc.PlainShare(Fsub(v, e.Value));
                        row.Add(new Piece(v, new List<Part> { new Part(e.Bits, gadget), new Part(d.Bits, Enc.PlainGadget()) }));
                    }
                }
                pieces.Add(row);
            }
            var z = new BigInteger[reqs.Count][];
            for (int q = 0; q < reqs.Count; q++)
            {
                z[q] = new BigInteger[n];
                for (int i = 0; i < n; i++) z[q][i] = Fmul(pieces[q][i].Value, reqs[q].Y[i]);
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (i == j) continue;
                    int rows = 0;
                    for (int q = 0; q < reqs.Count; q++) foreach (var part in pieces[q][i].Parts) rows += part.Bits.Length;
                    var bits = new int[rows];
                    var msg0 = new BigInteger[rows];
                    var msg1 = new BigInteger[rows];
                    var segs = new List<Seg>();
                    int at = 0;
                    for (int q = 0; q < reqs.Count; q++)
                    {
                        var y = Mod(reqs[q].Y[j]);
                        foreach (var part in pieces[q][i].Parts)
                        {
                            int len = part.Bits.Length;
                            var senderSum = BigInteger.Zero;
                            for (int k = 0; k < len; k++)
                            {
                                var rho = rng.Next();
                                senderSum = Fadd(senderSum, rho);
                                bits[at + k] = part.Bits[k];
                                msg0[at + k] = rho;
                                msg1[at + k] = Fadd(rho, Fmul(part.Gad[k], y));
                            }
                            segs.Add(new Seg(q, at, len, senderSum));
                            at += len;
                        }
                    }
                    var received = Channel(i, j).Extend(bits, msg0, msg1).Received;
                    log?.Add(new OtRecord(i, j, msg0, msg1, received));
                    foreach (var sg in segs)
                    {
                        var receiverSum = BigInteger.Zero;
                        for (int k = 0; k < sg.Len; k++) receiverSum = Fadd(receiverSum, Mod(received[sg.Start + k]));
                        z[sg.Q][i] = Fadd(z[sg.Q][i], receiverSum);
                        z[sg.Q][j] = Fadd(z[sg.Q][j], Fneg(sg.SenderSum));
                    }
                }
            }
            return z;
        }

        /// <summary>Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT).</summary>
        public BigInteger[] OtShareMultiply(List<object> x, BigInteger[] y) => MulBatch(new List<Req> { new Req(x, y) })[0];

        List<object> KeyReq(int l) => new List<object>(keyEnc[l]);

        static List<object> EncReq(EncShare[] shares) => new List<object>(shares);

        Spdz.AuthSV Authenticate(BigInteger[] valueShares)
        {
            var reqs = new List<Req>();
            for (int l = 0; l < keyEnc.Length; l++) reqs.Add(new Req(KeyReq(l), valueShares));
            return ToAuth(valueShares, MulBatch(reqs));
        }

        static Spdz.AuthSV ToAuth(BigInteger[] value, BigInteger[][] macs) => new(value, macs[0], macs[1..]);

        BigInteger[] ClaimProduct(BigInteger[] implied)
        {
            var z = (BigInteger[])implied.Clone();
            int idx = productMulCount++;
            if (deviation != null && deviation.ProductMul == idx) z[0] = Fadd(z[0], deviation.Delta);
            claims.Add(new ProductClaim(z, implied));
            return z;
        }

        Spdz.TripleWithPartners RawTripleWithPartners(int partners)
        {
            int K = keyEnc.Length;
            var aEnc = new EncShare[n];
            for (int i = 0; i < n; i++) aEnc[i] = SampleShare();
            var bShares = new BigInteger[n];
            for (int i = 0; i < n; i++) bShares[i] = rng.Next();
            var ahEnc = new EncShare[partners][];
            for (int r = 0; r < partners; r++)
            {
                ahEnc[r] = new EncShare[n];
                for (int i = 0; i < n; i++) ahEnc[r][i] = SampleShare();
            }
            var aVal = new BigInteger[n];
            for (int i = 0; i < n; i++) aVal[i] = aEnc[i].Value;
            var ahVal = new BigInteger[partners][];
            for (int r = 0; r < partners; r++)
            {
                ahVal[r] = new BigInteger[n];
                for (int i = 0; i < n; i++) ahVal[r][i] = ahEnc[r][i].Value;
            }
            var reqs = new List<Req> { new Req(EncReq(aEnc), bShares) };
            for (int r = 0; r < partners; r++) reqs.Add(new Req(EncReq(ahEnc[r]), bShares));
            int macStart = reqs.Count;
            for (int l = 0; l < K; l++)
            {
                reqs.Add(new Req(KeyReq(l), aVal));
                reqs.Add(new Req(KeyReq(l), bShares));
                for (int r = 0; r < partners; r++) reqs.Add(new Req(KeyReq(l), ahVal[r]));
            }
            var z1 = MulBatch(reqs);
            var cShares = ClaimProduct(z1[0]);
            var chShares = new BigInteger[partners][];
            for (int r = 0; r < partners; r++) chShares[r] = ClaimProduct(z1[1 + r]);
            int per = 2 + partners;
            var reqs2 = new List<Req>();
            for (int l = 0; l < K; l++)
            {
                reqs2.Add(new Req(KeyReq(l), cShares));
                for (int r = 0; r < partners; r++) reqs2.Add(new Req(KeyReq(l), chShares[r]));
            }
            var z2 = MulBatch(reqs2);
            int per2 = 1 + partners;
            var b = ToAuth(bShares, MacOf(z1, macStart, per, 1, K));
            var keep = new Spdz.AuthTriple(ToAuth(aVal, MacOf(z1, macStart, per, 0, K)), b, ToAuth(cShares, MacOf(z2, 0, per2, 0, K)));
            var parts = new List<Spdz.AuthTriple>();
            for (int r = 0; r < partners; r++)
                parts.Add(new Spdz.AuthTriple(ToAuth(ahVal[r], MacOf(z1, macStart, per, 2 + r, K)), b, ToAuth(chShares[r], MacOf(z2, 0, per2, 1 + r, K))));
            return new Spdz.TripleWithPartners(keep, parts);
        }

        static BigInteger[][] MacOf(BigInteger[][] z, int start, int per, int off, int K)
        {
            var o = new BigInteger[K][];
            for (int l = 0; l < K; l++) o[l] = z[start + l * per + off];
            return o;
        }

        Spdz.MacCheckAbort BlameAbort(Spdz.MacCheckAbort abort)
        {
            var blamed = new SortedSet<int>();
            if (log != null)
            {
                foreach (var r in log)
                {
                    for (int k = 0; k < r.Received.Length; k++)
                    {
                        var got = Mod(r.Received[k]);
                        if (got != r.Msg0[k] && got != r.Msg1[k])
                        {
                            blamed.Add(r.Sender);
                            break;
                        }
                    }
                }
            }
            foreach (var c in claims)
                for (int i = 0; i < c.Claimed.Length; i++) if (c.Claimed[i] != c.Implied[i]) blamed.Add(i);
            return new OfflineCheatingAbort(abort.Message, new List<int>(blamed));
        }

        /// <summary>One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off).</summary>
        public Spdz.AuthTriple GenAuthTriple()
        {
            if (!sacrificeOn) return RawTripleWithPartners(0).Keep;
            log = new List<OtRecord>();
            claims = new List<ProductClaim>();
            try
            {
                var t = RawTripleWithPartners(sacrificePartners);
                return Spdz.SacrificeVerify(new List<Spdz.TripleWithPartners> { t }, MacContext(), rng, new List<Spdz.Deviation>())[0];
            }
            catch (Spdz.MacCheckAbort e)
            {
                throw BlameAbort(e);
            }
            finally
            {
                log = null;
                claims = new List<ProductClaim>();
            }
        }

        public List<Spdz.AuthTriple> GenAuthTriples(int count)
        {
            var o = new List<Spdz.AuthTriple>();
            for (int k = 0; k < count; k++) o.Add(GenAuthTriple());
            return o;
        }

        /// <summary>An authenticated sharing of a value contributed by owner, MACed by OT under the distributed key.</summary>
        public Spdz.AuthSV AuthInput(BigInteger value, int owner)
        {
            if (owner < 0 || owner >= n) throw new ArgumentException("authInput: owner out of range");
            return Authenticate(Sharing.Share(Mod(value), n, rng));
        }

        /// <summary>Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise).</summary>
        public void CheckInputConsistency(List<Spdz.AuthSV> inputs)
        {
            if (inputs.Count == 0) return;
            foreach (var inp in inputs)
                if (inp.Value.Length != n || inp.Mac.Length != n) throw new ArgumentException("checkInputConsistency: input party count mismatch");
            var ctx = MacContext();
            var engine = new Spdz.SpdzEngine(ctx, new List<Spdz.Deviation>());
            var rShares = new BigInteger[n];
            for (int i = 0; i < n; i++) rShares[i] = rng.Next();
            var w = Authenticate(rShares);
            foreach (var inp in inputs)
            {
                var e = rng.Next();
                if (e.IsZero) e = BigInteger.One;
                w = Spdz.AddAuth(w, Spdz.ScaleAuth(inp, e));
            }
            engine.Open(w, "input-check:w");
            engine.MacCheck(rng);
        }
    }

    /// <summary>The no-dealer offline provider of n parties; a non-null seed makes every draw reproducible (tests only).</summary>
    public static NoDealerOffline MakeNoDealerOffline(int n, BigInteger? seed, NoDealerOptions? opts) => new(n, seed, opts);

    public static NoDealerOffline MakeNoDealerOffline(int n, BigInteger? seed) => new(n, seed, null);
}
