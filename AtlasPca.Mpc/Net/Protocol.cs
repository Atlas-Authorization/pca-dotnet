using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static AtlasPca.Mpc.Field;
using static AtlasPca.Mpc.NetPa;
using static AtlasPca.Mpc.NetWire;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// The DISTRIBUTED malicious-with-abort (SPDZ-style) composition protocol: same circuit and semantics as the in-process runner
/// (allow = AND, t = MAX, r = MAX via thermometers, authenticated Beaver multiplication, batched MAC-check before any output),
/// but each party is its own node holding only its own shares and every opening is a message over the TLS <see cref="Mesh"/>.
/// Rounds: prep, coin1-*, sac-rho, sac-tau, inputs (or in-check), mul0.., out, the pairwise tag rounds (dealer mode), coin-c/o,
/// sig-c/o, digest, and on a failed MAC-check a blame round. No output is decoded until the MAC-check and the transcript echo pass.
///
/// Offline modes: <c>trusted-dealer</c> (a separate node that knows every share and key; a dealer that gives a wrong triple is
/// detected by the sacrifice, one that deals inconsistent MACs is named by the blame round) and <c>no-dealer</c>
/// (the parties derive everything from OT). In both modes shares are pairwise-authenticated so an online lie is attributable.
/// There is no security proof; the echo is a hash exchange, not Byzantine agreement; the dealer is trusted for privacy.
/// </summary>
public static class Protocol
{
    public const int T_M = 3;
    internal const int DEFAULT_Q = 100;
    private const int PREP_CHUNK = 30_000;
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    public static int ChainCount(int Q) => 1 + T_M + Q;

    /// <summary>Thrown by the test-only <c>silent</c> behaviour; the host then idles with its sockets open.</summary>
    public sealed class SilentParty : Exception
    {
        public SilentParty() : base("silent") { }
    }

    /// <summary>Thrown by the test-only <c>crash</c> behaviour; the host closes the node abruptly.</summary>
    public sealed class CrashParty : Exception
    {
        public CrashParty() : base("crash") { }
    }

    /// <summary>Test-only protocol-level misbehaviour (kind: open-lie, mac-lie, bad-tag, sigma-lie, offline-lie, ot-u-lie, ot-proof-lie, equivocate, bad-coin-open, bad-sigma-open, short-array, noncanonical, crash, silent).</summary>
    public sealed record Behavior(string Kind, string? Round);

    public sealed record RoundStat(string Rd, double Ms, long BytesOut, long BytesIn);

    public sealed record PartyResult(int Id, int N, int Q, Compose.ComposedDecision Composed, List<RoundStat> Rounds, string TranscriptDigest, double WallMs, int Multiplications,
        int Opens, string OfflineMode, int MacKeys, int SacrificedTriples, int SacrificePartners, bool IdentifiableAbort);

    /// <summary>What an offline-phase implementation receives from the online driver.</summary>
    public sealed record OfflineCtx(Mesh Mesh, int Id, int N, int C, int Keys, int Partners, string SessionId, Party.DecisionVector Input, int Q, Behavior? Behavior, IExchanger Io,
        Action<string> CrashIf);

    /// <summary>The no-dealer offline phase: produces this party's <see cref="Prep"/>.</summary>
    public delegate Prep OfflineRunner(OfflineCtx ctx);

    public sealed class DealerConfig
    {
        /// <summary>Required true: the dealer sees every share and MAC key.</summary>
        public bool InsecureTrustedDealer;
        public int N;
        public int? Q;
        public Mesh? Mesh;
        /// <summary>Deterministic stream for reproducible tests; null means the CSPRNG.</summary>
        public BigInteger? Seed;
        /// <summary>TEST ONLY: a LYING dealer that authenticates a wrong product.</summary>
        public Spdz.DealerFault? Fault;
        /// <summary>TEST ONLY: a dealer that gives party 0 a wrong MAC share for this input mask number.</summary>
        public int? MacFaultAtInput;
    }

    public sealed class PartyConfig
    {
        public int Id;
        public int N;
        public int? Q;
        public Party.DecisionVector? Input;
        public Mesh? Mesh;
        /// <summary>Node id of the dealer (default n).</summary>
        public int? DealerId;
        /// <summary>"no-dealer" (default) or "trusted-dealer" (which also needs InsecureTrustedDealer).</summary>
        public string? Offline = "no-dealer";
        public bool InsecureTrustedDealer;
        public Behavior? Behavior;
        public bool UnsafeTestHooks;
        public string? SessionId;
        public int? ForensicDeadlineMs;
        /// <summary>The no-dealer offline phase; null selects the default implementation.</summary>
        public OfflineRunner? OfflineRunner;
    }

    private static int IntOf(object? o)
    {
        if (o is not Num n || !double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double d)) return int.MinValue;
        return d == Math.Round(d) && Math.Abs(d) < 1e9 ? (int)d : int.MinValue;
    }

    private static int[] PrepLayout(int n, int C, int keys, int partners, bool tagged)
    {
        int aw = AwWidth(n, keys, tagged);
        int triples = (n - 1) * C;
        int inputs = n * C;
        int nums = (tagged ? 1 : 0) + keys * PaWidth(n, tagged) + triples * NetCodec.SharingsPerTriple(partners) * aw + inputs * aw + C;
        return new[] { nums, triples, inputs };
    }

    // ---------------------------------------------------------------------------------------------- dealer

    private static PA[] DealPA(BigInteger[] x, BigInteger[] deltas, IFieldSource rng)
    {
        int n = x.Length;
        var K = new BigInteger[n][];
        for (int i = 0; i < n; i++)
        {
            K[i] = new BigInteger[n];
            for (int j = 0; j < n; j++) K[i][j] = i == j ? BigInteger.Zero : rng.Next();
        }
        var outp = new PA[n];
        for (int p = 0; p < n; p++)
        {
            var tag = new BigInteger[n];
            var key = new BigInteger[n];
            for (int j = 0; j < n; j++)
            {
                tag[j] = j == p ? BigInteger.Zero : Fadd(K[p][j], Fmul(deltas[j], x[p]));
                key[j] = j == p ? BigInteger.Zero : K[j][p];
            }
            outp[p] = new PA(x[p], tag, key);
        }
        return outp;
    }

    private static AW[] DealAW(Spdz.AuthSV sv, BigInteger[] deltas, IFieldSource rng)
    {
        int n = sv.Value.Length;
        var comps = new List<BigInteger[]> { sv.Value, sv.Mac };
        comps.AddRange(sv.ExtraMac);
        var dealt = new List<PA[]>();
        foreach (BigInteger[] c in comps) dealt.Add(DealPA(c, deltas, rng));
        var outp = new AW[n];
        for (int p = 0; p < n; p++)
        {
            var m = new PA[dealt.Count - 1];
            for (int l = 1; l < dealt.Count; l++) m[l - 1] = dealt[l][p];
            outp[p] = new AW(dealt[0][p], m);
        }
        return outp;
    }

    /// <summary>
    /// The TRUSTED DEALER role: samples the MAC keys, verification keys, sacrifice-certified authenticated triples and input
    /// masks, and ships each party only its own slice. It never sees an input bit, but it knows every key and share.
    /// </summary>
    public static void RunDealer(DealerConfig cfg)
    {
        int n = cfg.N;
        if (!cfg.InsecureTrustedDealer) throw new ArgumentException("runDealer requires insecureTrustedDealer (a dealer sees every share and MAC key; the default offline phase has no dealer)");
        Mesh mesh = cfg.Mesh ?? throw new ArgumentException("runDealer requires a mesh");
        int Q = cfg.Q ?? DEFAULT_Q;
        IFieldSource rng = FieldRandom(cfg.Seed);
        int C = ChainCount(Q);
        Spdz.MacContext ctx = Spdz.SetupMac(n, rng, Spdz.MAC_KEYS);
        List<Spdz.MacKey> keys = Spdz.MacKeysOf(ctx);
        var deltas = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            BigInteger d = rng.Next();
            while (d.IsZero) d = rng.Next();
            deltas[i] = d;
        }
        var perParty = new List<List<BigInteger>>();
        for (int p = 0; p < n; p++)
        {
            perParty.Add(new List<BigInteger>());
            perParty[p].Add(deltas[p]);
        }
        var alphaPA = new List<PA[]>();
        foreach (Spdz.MacKey k in keys) alphaPA.Add(DealPA(k.AlphaShares, deltas, rng));
        for (int p = 0; p < n; p++) foreach (PA[] a in alphaPA) perParty[p].AddRange(PaFlat(a[p], p, n, true));

        int nTriples = (n - 1) * C;
        for (int t = 0; t < nTriples; t++)
        {
            Spdz.TripleWithPartners tr = Spdz.GenTripleWithPartners(ctx, rng, Spdz.SACRIFICE_PARTNERS, cfg.Fault);
            var sharings = new List<Spdz.AuthSV> { tr.Keep.A, tr.Keep.B, tr.Keep.C };
            foreach (Spdz.AuthTriple q in tr.Partners)
            {
                sharings.Add(q.A);
                sharings.Add(q.C);
            }
            foreach (Spdz.AuthSV sv in sharings)
            {
                AW[] aws = DealAW(sv, deltas, rng);
                for (int p = 0; p < n; p++) perParty[p].AddRange(AwFlat(aws[p], p, n, true));
            }
        }
        var masksByOwner = new List<List<BigInteger>>();
        for (int p = 0; p < n; p++) masksByOwner.Add(new List<BigInteger>());
        for (int q = 0; q < n * C; q++)
        {
            int owner = q / C;
            BigInteger r = rng.Next();
            masksByOwner[owner].Add(r);
            Spdz.AuthSV sv = Spdz.AuthShare(r, ctx, rng);
            if (cfg.MacFaultAtInput != null && cfg.MacFaultAtInput.Value == q) sv.Mac[0] = Fadd(sv.Mac[0], BigInteger.One);
            AW[] aws = DealAW(sv, deltas, rng);
            for (int p = 0; p < n; p++) perParty[p].AddRange(AwFlat(aws[p], p, n, true));
        }
        for (int p = 0; p < n; p++) perParty[p].AddRange(masksByOwner[p]);

        for (int p = 0; p < n; p++)
        {
            var nums = new List<string>();
            foreach (BigInteger b in perParty[p]) nums.Add(Hx(b));
            int chunks = Math.Max(1, (nums.Count + PREP_CHUNK - 1) / PREP_CHUNK);
            var first = new JD
            {
                ["total"] = nums.Count,
                ["chunks"] = chunks,
                ["nums"] = nums.GetRange(0, Math.Min(PREP_CHUNK, nums.Count)).Cast<object?>().ToList(),
            };
            mesh.Send(p, "prep", first);
            for (int c = 1; c < chunks; c++)
                mesh.Send(p, "prep." + c, nums.GetRange(c * PREP_CHUNK, Math.Min((c + 1) * PREP_CHUNK, nums.Count) - c * PREP_CHUNK).Cast<object?>().ToList());
        }
        mesh.Finish();
    }

    // ---------------------------------------------------------------------------------------------- party

    private static byte[] Sha(params object[] parts)
    {
        using var ms = new MemoryStream();
        foreach (object p in parts)
        {
            byte[] b = p is byte[] bb ? bb : Encoding.UTF8.GetBytes((string)p);
            ms.Write(b, 0, b.Length);
            ms.WriteByte(0);
        }
        return SHA256.HashData(ms.ToArray());
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>Uniform non-zero field element <paramref name="j"/> of the public challenge stream <paramref name="label"/> derived from <paramref name="seed"/>.</summary>
    internal static BigInteger Challenge(byte[] seed, string label, int j)
    {
        for (int ctr = 0; ; ctr++)
        {
            byte[] h = Sha("chal", seed, label + ":" + j.ToString(CultureInfo.InvariantCulture) + ":" + ctr.ToString(CultureInfo.InvariantCulture));
            long x = BinaryPrimitives.ReadInt64BigEndian(h) & ((1L << 61) - 1);
            if (x != 0 && x != (1L << 61) - 1) return new BigInteger(x);
        }
    }

    private sealed record Opened(BigInteger Val, PA[] Mac);

    private sealed record BlameMsg(BigInteger[] G, BigInteger[] Gt, BigInteger[] A, BigInteger[] At);

    public static PartyResult RunParty(PartyConfig cfg) => new PartyRun(cfg).Run();

    private sealed class PartyRun : IExchanger
    {
        private readonly PartyConfig cfg;
        private readonly int id, n, Q, dealerId, C, K, P;
        private readonly Mesh mesh;
        private readonly string sessionId;
        private readonly string offlineMode;
        private readonly Behavior? beh;
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private readonly List<RoundStat> rounds = new();
        private readonly MemoryStream transcript = new();
        private readonly List<int> others = new();
        private readonly List<Opened> opened = new();
        private Prep prep = null!;
        private PaEnv env = null!;

        public PartyRun(PartyConfig cfg)
        {
            this.cfg = cfg;
            id = cfg.Id;
            n = cfg.N;
            mesh = cfg.Mesh!;
            sessionId = cfg.SessionId!;
            Q = cfg.Q ?? DEFAULT_Q;
            dealerId = cfg.DealerId ?? cfg.N;
            offlineMode = cfg.Offline ?? "no-dealer";
            C = ChainCount(Q);
            K = Spdz.MAC_KEYS;
            P = Spdz.SACRIFICE_PARTNERS;
            beh = cfg.Behavior;
            for (int i = 0; i < n; i++) if (i != id) others.Add(i);
        }

        private double Ms() => clock.Elapsed.TotalMilliseconds;

        private long[] Totals()
        {
            long o = 0, i = 0;
            foreach (Mesh.LinkStats s in mesh.Stats())
            {
                o += s.AppBytesOut;
                i += s.AppBytesIn;
            }
            return new[] { o, i };
        }

        private void CrashIf(string rd)
        {
            if (beh != null && rd == beh.Round)
            {
                if (beh.Kind == "crash") throw new CrashParty();
                if (beh.Kind == "silent") throw new SilentParty();
            }
        }

        private bool At(string kind, string rd) => beh != null && kind == beh.Kind && rd == beh.Round;

        private NetAbort BadAbort(int p, string what) => new("malformed", p, id, what);

        public Exception Bad(int p, string what) => BadAbort(p, what);

        private NetAbort Abort(NetAbort e)
        {
            mesh.Fail(e, null);
            return e;
        }

        private BigInteger[] Arr(int p, object? raw, int len)
        {
            BigInteger[]? r = UnhxArray(raw, len);
            if (r == null) throw BadAbort(p, "expected " + len + " canonical field elements");
            return r;
        }

        public Dictionary<int, T> Exchange<T>(string rd, Func<int, object?> mine, Func<int, object?, T> parse, long? timeoutMs = null) =>
            ExchangeX(rd, mine, parse, null, false, timeoutMs);

        /// <summary>One all-to-all round; <c>hashed = false</c> keeps a round (peer-specific tags, forensics) out of the echoed transcript.</summary>
        private Dictionary<int, T> ExchangeX<T>(string rd, Func<int, object?> mine, Func<int, object?, T> parse, object? common, bool hashed, long? timeoutMs)
        {
            CrashIf(rd);
            long[] a = Totals();
            double s = Ms();
            foreach (int p in others) mesh.Send(p, rd, mine(p));
            SortedDictionary<int, object?> raw = mesh.Collect(rd, others, timeoutMs);
            var parsed = new Dictionary<int, T>();
            foreach (int p in others)
            {
                try
                {
                    parsed[p] = parse(p, raw[p]);
                }
                catch (NetAbort e)
                {
                    mesh.Fail(e, null);
                    throw;
                }
                catch (Exception e)
                {
                    var ne = new NetAbort("malformed", p, id, "round '" + rd + "': " + e.Message);
                    mesh.Fail(ne, null);
                    throw ne;
                }
            }
            if (hashed)
            {
                // transcript: party order, canonical JSON of what each party broadcast in this round
                byte[] rb = Encoding.UTF8.GetBytes(rd);
                transcript.Write(rb, 0, rb.Length);
                for (int p = 0; p < n; p++)
                {
                    byte[] pb = Encoding.UTF8.GetBytes("|" + p.ToString(CultureInfo.InvariantCulture) + ":" + Stringify(p == id ? common : raw[p]));
                    transcript.Write(pb, 0, pb.Length);
                }
            }
            long[] b = Totals();
            rounds.Add(new RoundStat(rd, Ms() - s, b[0] - a[0], b[1] - a[1]));
            return parsed;
        }

        // ---- trusted-dealer prep ----
        private Prep ReceiveDealerPrep()
        {
            int[] lay = PrepLayout(n, C, K, P, true);
            object? firstRaw = mesh.Recv(dealerId, "prep");
            var nums = new List<BigInteger>();
            try
            {
                JD? first = firstRaw as JD;
                if (first == null || IntOf(first.GetValueOrDefault("total")) != lay[0]) throw BadAbort(dealerId, "bad prep size");
                int chunks = IntOf(first.GetValueOrDefault("chunks"));
                if (chunks != Math.Max(1, (lay[0] + PREP_CHUNK - 1) / PREP_CHUNK)) throw BadAbort(dealerId, "bad prep chunk count");
                nums.AddRange(Take(first.GetValueOrDefault("nums"), Math.Min(PREP_CHUNK, lay[0])));
                for (int c = 1; c < chunks; c++)
                {
                    object? part = mesh.Recv(dealerId, "prep." + c);
                    nums.AddRange(Take(part, Math.Min(PREP_CHUNK, lay[0] - c * PREP_CHUNK)));
                }
            }
            catch (NetAbort e)
            {
                throw Abort(e);
            }
            catch (Exception e)
            {
                throw Abort(new NetAbort("malformed", dealerId, id, e.Message));
            }
            int o = 0;
            BigInteger delta = nums[o++];
            if (delta.IsZero) throw Abort(new NetAbort("dealer", dealerId, id, "the dealer gave me a zero verification key"));
            int w = PaWidth(n, true);
            var alpha = new PA[K];
            for (int l = 0; l < K; l++)
            {
                alpha[l] = PaParse(nums, o, id, n, true);
                o += w;
            }
            int aw = AwWidth(n, K, true);
            int spt = NetCodec.SharingsPerTriple(P);
            var triples = new AW[lay[1]][];
            for (int t = 0; t < lay[1]; t++)
            {
                var sh = new AW[spt];
                for (int s = 0; s < spt; s++)
                {
                    sh[s] = AwParse(nums, o, id, n, K, true);
                    o += aw;
                }
                triples[t] = sh;
            }
            var inputs = new AW[lay[2]];
            for (int q = 0; q < lay[2]; q++)
            {
                inputs[q] = AwParse(nums, o, id, n, K, true);
                o += aw;
            }
            BigInteger[] myPlain = nums.GetRange(o, C).ToArray();
            return new Prep("trusted-dealer", true, delta, alpha, triples, inputs, myPlain, null, null);
        }

        private List<BigInteger> Take(object? raw, int len)
        {
            BigInteger[]? r = UnhxArray(raw, len);
            if (r == null) throw BadAbort(dealerId, "bad prep numbers");
            return new List<BigInteger>(r);
        }

        private AW AddPub(AW x, BigInteger c) => WAddPublic(env, x, c, prep.Alpha);

        private AW Not(AW x) => AddPub(WNeg(x), BigInteger.One);

        /// <summary>Open authenticated values: broadcast value shares, verify pairwise tags (dealer mode), record for the MAC-check.</summary>
        private BigInteger[] OpenMany(string rd, AW[] ws)
        {
            var sendVals = new BigInteger[ws.Length];
            var macs = new PA[ws.Length][];
            for (int i = 0; i < ws.Length; i++)
            {
                sendVals[i] = ws[i].V.X;
                macs[i] = ws[i].M;
            }
            if (beh != null && rd == beh.Round)
            {
                if (beh.Kind == "open-lie") sendVals[0] = Fadd(sendVals[0], BigInteger.One);
                if (beh.Kind == "mac-lie")
                {
                    var m0 = (PA[])macs[0].Clone();
                    m0[0] = new PA(Fadd(m0[0].X, BigInteger.One), m0[0].Tag, m0[0].Key);
                    macs[0] = m0;
                }
            }
            var common = new List<object?>();
            foreach (BigInteger v in sendVals) common.Add(Hx(v));
            Func<int, object?> mineFn = peer =>
            {
                if (At("equivocate", rd) && peer == others[0])
                {
                    var c = new List<object?>(common);
                    c[0] = Hx(Fadd(ParseHex((string)common[0]!), BigInteger.One));
                    return c;
                }
                if (At("short-array", rd)) return new List<object?>(common.GetRange(1, common.Count - 1));
                if (At("noncanonical", rd))
                {
                    var c = new List<object?>(common);
                    c[0] = Hx(PRIME);
                    return c;
                }
                return common;
            };
            Dictionary<int, BigInteger[]> got = ExchangeX(rd, mineFn, (p, raw) => Arr(p, raw, ws.Length), common, true, null);
            if (prep.Tagged)
            {
                // pairwise tags: peer-specific, so a separate un-echoed round; each receiver verifies at once
                Func<int, object?> tagMsg = peer =>
                {
                    var t = new List<object?>();
                    for (int i = 0; i < ws.Length; i++)
                    {
                        BigInteger tag = ws[i].V.Tag[peer];
                        t.Add(Hx(At("bad-tag", rd) && i == 0 ? Fadd(tag, BigInteger.One) : tag));
                    }
                    return t;
                };
                Dictionary<int, BigInteger[]> tags = ExchangeX(rd + ".t", tagMsg, (p, raw) => Arr(p, raw, ws.Length), null, false, null);
                foreach (int p in others)
                {
                    for (int i = 0; i < ws.Length; i++)
                    {
                        if (!PaVerify(env, ws[i].V, p, got[p][i], tags[p][i]))
                        {
                            throw Abort(new NetAbort("mac-check", p, id,
                                "pairwise MAC on party " + p + "'s opened share failed in round '" + rd + "' (index " + i + "): the share or its tag is not what the dealer issued"));
                        }
                    }
                }
            }
            var outp = new BigInteger[ws.Length];
            for (int i = 0; i < ws.Length; i++)
            {
                BigInteger sum = sendVals[i];
                foreach (int p in others) sum = Fadd(sum, got[p][i]);
                outp[i] = sum;
                opened.Add(new Opened(sum, macs[i]));
            }
            return outp;
        }

        /// <summary>Commit / open of a random seed, giving a joint public seed.</summary>
        private byte[] Coin(string label, bool tamperOpen)
        {
            byte[] mySeed = RandomNumberGenerator.GetBytes(32);
            string seedCommit = Hex(Sha("seed", sessionId, label, id.ToString(CultureInfo.InvariantCulture), mySeed));
            Dictionary<int, string> seedCommits = ExchangeX<string>(label + "-c", p => seedCommit, (p, raw) =>
            {
                if (raw is string s && Hex64.IsMatch(s)) return s;
                throw Bad(p, "bad commitment");
            }, seedCommit, true, null);
            Func<int, object?> openMsg = p =>
            {
                if (tamperOpen && beh != null && beh.Kind == "bad-coin-open") return Hex(RandomNumberGenerator.GetBytes(32));
                return Hex(mySeed);
            };
            Dictionary<int, byte[]> seeds = ExchangeX(label + "-o", openMsg, (p, raw) =>
            {
                if (raw is not string s || !Hex64.IsMatch(s)) throw Bad(p, "bad seed");
                byte[] sd = Convert.FromHexString(s);
                if (Hex(Sha("seed", sessionId, label, p.ToString(CultureInfo.InvariantCulture), sd)) != seedCommits[p])
                    throw new NetAbort("commitment", p, id, "party " + p + " opened a coin seed that does not match its commitment");
                return sd;
            }, Hex(mySeed), true, null);
            var parts = new object[3 + n];
            parts[0] = "joint";
            parts[1] = sessionId;
            parts[2] = label;
            for (int p = 0; p < n; p++) parts[3 + p] = p == id ? mySeed : seeds[p];
            return Sha(parts);
        }

        private string SigCommit(int p, BigInteger[] s, byte[] nonce)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++) sb.Append(i == 0 ? "" : ",").Append(Hx(s[i]));
            return Hex(Sha("sigma", sessionId, p.ToString(CultureInfo.InvariantCulture), sb.ToString(), nonce));
        }

        private static BigInteger BitOf(BigInteger x) => x == BigInteger.One ? BigInteger.One : BigInteger.Zero;

        // inputs state
        private BigInteger[] masked = Array.Empty<BigInteger>();
        private Dictionary<int, BigInteger[]> gotMasked = new();

        private AW BitShare(int owner, int k)
        {
            if (prep.Mode == "trusted-dealer")
            {
                BigInteger pub = owner == id ? masked[k] : gotMasked[owner][k];
                return AddPub(prep.Inputs[owner * C + k], pub);
            }
            return prep.Inputs[owner * C + k];
        }

        public PartyResult Run()
        {
            if (offlineMode == "trusted-dealer" && !cfg.InsecureTrustedDealer)
                throw new NetAbort("local", null, id, "offline 'trusted-dealer' requires insecureTrustedDealer (the dealer sees every share and key); the default is 'no-dealer'");
            if (beh != null && !cfg.UnsafeTestHooks) throw new NetAbort("local", null, id, "the behavior test hook requires unsafeTestHooks (test-only)");
            if (n < 1) throw new NetAbort("local", null, id, "n must be >= 1");
            Party.DecisionVector? v = cfg.Input;
            if (v == null || (v.Allow != 0 && v.Allow != 1) || v.T < 1 || v.T > 3 || v.RQuant < 0 || v.RQuant > Q)
                throw new NetAbort("local", null, id, "invalid decision vector");

            // ---- offline phase ----
            CrashIf("prep");
            double prepStart = Ms();
            long[] before = Totals();
            if (offlineMode == "trusted-dealer")
            {
                prep = ReceiveDealerPrep();
            }
            else
            {
                OfflineRunner runner = cfg.OfflineRunner ?? new OfflineRunner(OfflineNet.Run);
                prep = runner(new OfflineCtx(mesh, id, n, C, K, P, sessionId, v, Q, beh, this, CrashIf));
            }
            long[] afterPrep = Totals();
            rounds.Add(new RoundStat("prep", Ms() - prepStart, afterPrep[0] - before[0], afterPrep[1] - before[1]));
            env = new PaEnv(id, n, prep.Delta, prep.Tagged);

            // ---- sacrifice: certify every triple against its partners before it is used ----
            int nT = prep.Triples.Length;
            if (nT > 0) Sacrifice(nT);

            // ---- inputs ----
            int[] therm = Thermometer.ThermometerEncode(v.T, T_M);
            int[] rtherm = Thermometer.ThermometerEncode(v.RQuant, Q);
            var myBits = new BigInteger[C];
            myBits[0] = new BigInteger(v.Allow);
            for (int i = 0; i < T_M; i++) myBits[1 + i] = new BigInteger(therm[i]);
            for (int i = 0; i < Q; i++) myBits[1 + T_M + i] = new BigInteger(rtherm[i]);
            if (prep.Mode == "trusted-dealer")
            {
                masked = new BigInteger[C];
                var maskedMsg = new List<object?>();
                for (int k = 0; k < C; k++)
                {
                    masked[k] = Fsub(myBits[k], prep.MyPlain[k]);
                    maskedMsg.Add(Hx(masked[k]));
                }
                gotMasked = ExchangeX("inputs", p => maskedMsg, (p, raw) => Arr(p, raw, C), maskedMsg, true, null);
            }
            else
            {
                // No-dealer: inputs are already authenticated sharings; MASCOT input-consistency check (joins the batched MAC-check).
                byte[] jointIn = Coin("coin-in", false);
                AW w = prep.CheckMask!;
                for (int q = 0; q < n * C; q++) w = WAdd(w, WScale(prep.Inputs[q], Challenge(jointIn, "in", q)));
                OpenMany("in-check", new[] { w });
            }

            // ---- chains: acc_c over owners; allow uses AND, the others OR (= NOT AND NOT) ----
            var acc = new AW[C];
            for (int c = 0; c < C; c++)
            {
                AW b0 = BitShare(0, c);
                acc[c] = c != 0 ? Not(b0) : b0;
            }
            int mults = 0;
            for (int s = 1; s < n; s++)
            {
                var trs = new AW[C][];
                for (int c = 0; c < C; c++) trs[c] = prep.Triples[(s - 1) * C + c];
                var ds = new AW[C];
                var es = new AW[C];
                for (int c = 0; c < C; c++)
                {
                    AW b = BitShare(s, c);
                    AW y = c != 0 ? Not(b) : b;
                    ds[c] = WSub(acc[c], trs[c][0]);
                    es[c] = WSub(y, trs[c][1]);
                }
                var both = new AW[2 * C];
                Array.Copy(ds, 0, both, 0, C);
                Array.Copy(es, 0, both, C, C);
                BigInteger[] pub = OpenMany("mul" + (s - 1), both);
                var next = new AW[C];
                for (int c = 0; c < C; c++)
                {
                    BigInteger d = pub[c], e = pub[C + c];
                    AW z = WAdd(trs[c][2], WAdd(WScale(trs[c][1], d), WScale(trs[c][0], e)));
                    next[c] = AddPub(z, Fmul(d, e));
                }
                acc = next;
                mults += C;
            }

            // ---- outputs: allow as-is; or-chains are NOT of the product ----
            var outShares = new AW[C];
            for (int c = 0; c < C; c++) outShares[c] = c != 0 ? Not(acc[c]) : acc[c];
            BigInteger[] outVals = OpenMany("out", outShares);

            // ---- MAC-check ----
            byte[] joint = Coin("coin", true);
            var aPub = new BigInteger[K];
            var Gamma = new BigInteger[K];
            var sigma = new BigInteger[K];
            for (int l = 0; l < K; l++)
            {
                BigInteger a = BigInteger.Zero, g = BigInteger.Zero;
                for (int j = 0; j < opened.Count; j++)
                {
                    BigInteger ch = Challenge(joint, "mac" + l, j);
                    a = Fadd(a, Fmul(ch, opened[j].Val));
                    g = Fadd(g, Fmul(ch, opened[j].Mac[l].X));
                }
                aPub[l] = a;
                Gamma[l] = g;
                sigma[l] = Fsub(g, Fmul(prep.Alpha[l].X, a));
            }
            byte[] sigNonce = RandomNumberGenerator.GetBytes(32);
            var sigmaSent = (BigInteger[])sigma.Clone();
            if (beh != null && beh.Kind == "sigma-lie") sigmaSent[0] = Fadd(sigmaSent[0], BigInteger.One);
            string mySigCommit = SigCommit(id, sigmaSent, sigNonce);
            Dictionary<int, string> sigCommits = ExchangeX<string>("sig-c", p => mySigCommit, (p, raw) =>
            {
                if (raw is string s && Hex64.IsMatch(s)) return s;
                throw Bad(p, "bad commitment");
            }, mySigCommit, true, null);
            var mySigOpen = new JD { ["s"] = HexList(sigmaSent), ["nonce"] = Hex(sigNonce) };
            Dictionary<int, BigInteger[]> sigOpens = ExchangeX("sig-o", p =>
            {
                if (beh != null && beh.Kind == "bad-sigma-open")
                {
                    var s2 = (BigInteger[])sigmaSent.Clone();
                    s2[0] = Fadd(s2[0], BigInteger.One);
                    return new JD { ["s"] = HexList(s2), ["nonce"] = mySigOpen["nonce"] };
                }
                return mySigOpen;
            }, (p, raw) =>
            {
                JD? o = raw as JD;
                BigInteger[]? sv = o == null ? null : UnhxArray(o.GetValueOrDefault("s"), K);
                if (o == null || sv == null || o.GetValueOrDefault("nonce") is not string nonceHex || !Hex64.IsMatch(nonceHex)) throw Bad(p, "bad sigma opening");
                if (SigCommit(p, sv, Convert.FromHexString(nonceHex)) != sigCommits[p])
                    throw new NetAbort("commitment", p, id, "party " + p + " opened a MAC residual that does not match its commitment");
                return sv;
            }, mySigOpen, true, null);
            bool macFailed = false;
            for (int l = 0; l < K; l++)
            {
                BigInteger r = sigmaSent[l];
                foreach (int p in others) r = Fadd(r, sigOpens[p][l]);
                if (!r.IsZero) macFailed = true;
            }

            // ---- transcript echo: everyone must have seen the same broadcasts ----
            string digest = Hex(SHA256.HashData(transcript.ToArray()));
            Dictionary<int, string> digests = ExchangeX<string>("digest", p => digest, (p, raw) =>
            {
                if (raw is string s && Hex64.IsMatch(s)) return s;
                throw Bad(p, "bad digest");
            }, digest, true, null);
            foreach (int p in others)
            {
                if (digest != digests[p]) throw Abort(new NetAbort("equivocation", p, id, "transcript digest of party " + p + " differs from mine (a broadcast was inconsistent)"));
            }

            if (macFailed) Blame(aPub, Gamma, sigOpens, joint);

            // ---- only now decode ----
            var tBits = new int[T_M];
            var rBits = new int[Q];
            for (int i = 0; i < T_M; i++) tBits[i] = (int)BitOf(outVals[1 + i]);
            for (int i = 0; i < Q; i++) rBits[i] = (int)BitOf(outVals[1 + T_M + i]);
            int allow = (int)BitOf(outVals[0]);
            var composed = new Compose.ComposedDecision(allow, Math.Min(3, Math.Max(1, Thermometer.ThermometerDecode(tBits))), Thermometer.ThermometerDecode(rBits));
            mesh.Finish();
            return new PartyResult(id, n, Q, composed, rounds, digest, Ms(), mults, opened.Count, prep.Mode, K, nT, P, prep.Tagged);
        }

        private static List<object?> HexList(BigInteger[] xs)
        {
            var outp = new List<object?>();
            foreach (BigInteger x in xs) outp.Add(Hx(x));
            return outp;
        }

        private void Sacrifice(int nT)
        {
            byte[] joint1 = Coin("coin1", false);
            var rhoW = new AW[nT * P];
            for (int t = 0; t < nT; t++)
            {
                AW[] tr = prep.Triples[t];
                for (int r = 0; r < P; r++)
                {
                    BigInteger e = Challenge(joint1, "sac", t * P + r);
                    rhoW[t * P + r] = WSub(WScale(tr[0], e), tr[3 + 2 * r]);
                }
            }
            BigInteger[] rho = OpenMany("sac-rho", rhoW);
            var tauW = new AW[nT * P];
            for (int t = 0; t < nT; t++)
            {
                AW[] tr = prep.Triples[t];
                for (int r = 0; r < P; r++)
                {
                    BigInteger e = Challenge(joint1, "sac", t * P + r);
                    tauW[t * P + r] = WSub(WSub(WScale(tr[2], e), tr[3 + 2 * r + 1]), WScale(tr[1], rho[t * P + r]));
                }
            }
            BigInteger[] tau = OpenMany("sac-tau", tauW);
            int badAt = -1;
            for (int i = 0; i < tau.Length; i++) if (!tau[i].IsZero) { badAt = i; break; }
            if (badAt < 0) return;
            // Dealer-free mode: the triple is discarded, so its OT transcript can be disclosed and audited to name a party that fed a wrong operand.
            int? attributed = null;
            string note = "";
            Prep.PrepForensics? fx = prep.Mode == "no-dealer" ? prep.Forensics : null;
            if (fx != null)
            {
                int bt = badAt / P;
                List<NetForensics.SlotDisclosure> mine = fx.Disclose(bt);
                // commit first, open only once every commitment is in hand; a late or absent party times out at the shared deadline
                long deadline = cfg.ForensicDeadlineMs ?? NetForensics.DEFAULT_FORENSIC_DEADLINE_MS;
                Dictionary<int, List<NetForensics.SlotDisclosure>> got = Forensic.ExchangeDisclosures(sessionId, id, n, bt, mine, fx.Slots, fx.Rows, deadline, this);
                var all = new Dictionary<int, List<NetForensics.SlotDisclosure>>();
                for (int q = 0; q < n; q++) all[q] = q == id ? mine : got[q];
                NetForensics.AuditResult res = NetForensics.AuditDisclosures(all, fx.Gadget);
                attributed = NetForensics.BlameFrom(id, res);
                note = attributed == null
                    ? " (OT transcript audit: " + res.PairBad.Count + " inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)"
                    : " (OT transcript audit names party " + attributed.Value + ")";
            }
            bool dealer = prep.Mode == "trusted-dealer";
            int? blamed = dealer ? dealerId : (attributed ?? (n == 2 ? 1 - id : (int?)null));
            throw Abort(new NetAbort(dealer ? "dealer" : "mac-check", blamed, id,
                "triple sacrifice FAILED at triple " + (badAt / P) + " (partner " + (badAt % P) + "): c != a*b in the offline material; aborting with no output" + note,
                reason: "the triple sacrifice failed in dealer-free mode and the OT transcript audit of this party's own view names no one (a failing pair that does not involve me is not evidence I can use, and an accusation is never accepted as evidence)"));
        }

        private void Blame(BigInteger[] aPub, BigInteger[] Gamma, Dictionary<int, BigInteger[]> sigOpens, byte[] joint)
        {
            string msg = "MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output";
            if (!prep.Tagged)
            {
                throw Abort(new NetAbort("mac-check", n == 2 ? 1 - id : (int?)null, id, msg,
                    reason: "this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)"));
            }
            // every party opens its combined MAC shares with their pairwise tags; each verifier checks them
            Func<int, object?> blameMsg = peer =>
            {
                var gt = new List<object?>();
                var a = new List<object?>();
                var at = new List<object?>();
                for (int l = 0; l < K; l++)
                {
                    BigInteger g = BigInteger.Zero;
                    for (int j = 0; j < opened.Count; j++) g = Fadd(g, Fmul(Challenge(joint, "mac" + l, j), opened[j].Mac[l].Tag[peer]));
                    gt.Add(Hx(g));
                    a.Add(Hx(prep.Alpha[l].X));
                    at.Add(Hx(prep.Alpha[l].Tag[peer]));
                }
                return new JD { ["g"] = HexList(Gamma), ["gt"] = gt, ["a"] = a, ["at"] = at };
            };
            // Abort claims arriving during this round are read in link order (see Mesh.SetDeferAborts).
            mesh.SetDeferAborts(true);
            Dictionary<int, BlameMsg> blames;
            try
            {
                blames = ExchangeX("blame", blameMsg, (p, raw) =>
                {
                    JD o = raw as JD ?? new JD();
                    return new BlameMsg(Arr(p, o.GetValueOrDefault("g"), K), Arr(p, o.GetValueOrDefault("gt"), K), Arr(p, o.GetValueOrDefault("a"), K), Arr(p, o.GetValueOrDefault("at"), K));
                }, null, false, null);
            }
            finally
            {
                mesh.SetDeferAborts(false);
            }
            foreach (int p in others)
            {
                BlameMsg b = blames[p];
                for (int l = 0; l < K; l++)
                {
                    BigInteger keyCombo = BigInteger.Zero;
                    for (int j = 0; j < opened.Count; j++) keyCombo = Fadd(keyCombo, Fmul(Challenge(joint, "mac" + l, j), opened[j].Mac[l].Key[p]));
                    if (Fadd(keyCombo, Fmul(env.Delta, b.G[l])) != b.Gt[l])
                        throw Abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s MAC share (key " + l + ") does not match its pairwise tag"));
                    if (Fadd(prep.Alpha[l].Key[p], Fmul(env.Delta, b.A[l])) != b.At[l])
                        throw Abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s key share (key " + l + ") does not match its pairwise tag"));
                    if (Fsub(b.G[l], Fmul(b.A[l], aPub[l])) != sigOpens[p][l])
                        throw Abort(new NetAbort("mac-check", p, id, msg + " - party " + p + "'s opened MAC residual (key " + l + ") is not what its authenticated shares give"));
                }
            }
            // Every other party's data is consistent with its pairwise tags; so is mine: the offline material disagrees.
            if (prep.Mode == "trusted-dealer")
                throw Abort(new NetAbort("dealer", dealerId, id, msg + " - every party's shares verify, so the trusted dealer's MACs are inconsistent with its values"));
            throw Abort(new NetAbort("mac-check", n == 2 ? 1 - id : (int?)null, id,
                msg + " - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable",
                reason: "every party's shares verify under its pairwise tags, so the fault lies in the offline material, which names no party"));
        }
    }
}
