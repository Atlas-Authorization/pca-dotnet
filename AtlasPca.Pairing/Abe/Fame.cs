using System.Numerics;
using System.Text;
using AtlasPca.Pairing;
using static supranational.blst;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Abe;

/// <summary>
/// FAME (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the type-3 pairing setting, the group arithmetic
/// only (the wire format, validation and AEAD are in <see cref="Abe"/>). G1/G2 work is blst through its C# binding, GT work is blst
/// through <see cref="Gt"/>. Same equations, hashing and span program as the TypeScript reference:
/// <code>
///   Setup     MPK = (h^a1, h^a2, e(g,h)^(d1 a1 + d3), e(g,h)^(d2 a2 + d3)),  MSK = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
///   KeyGen    pow = (b1 r1, b2 r2, r1 + r2), K0 = h^pow,
///             K_y,t = (H(y,0,t)^pow0 H(y,1,t)^pow1 H(y,2,t)^pow2 g^sigma_y)^(1/a_(t+1)), K_y,2 = g^-sigma_y,
///             K'_t = (H0(0,0,t)^pow0 H0(0,1,t)^pow1 H0(0,2,t)^pow2 g^sigma')^(1/a_(t+1)) g^d_(t+1), K'_2 = g^-sigma' g^d3
///   Encrypt   C0 = (h1^s1, h2^s2, h^(s1+s2)),
///             C_i,l = H(rho(i),l,0)^s1 H(rho(i),l,1)^s2 prod_j (H0(j,l,0)^s1 H0(j,l,1)^s2)^M[i][j],  K = T1^s1 T2^s2
///   Decrypt   K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l) with the tree's Lagrange reconstruction weights
/// </code>
/// The span program is a Shamir sharing down the threshold tree (each t-of-n gate adds t-1 columns; child i gets its parent's row plus
/// i^k in the gate's k-th new column). rho must be injective: a policy naming one attribute twice is refused by the caller.
/// </summary>
public static class Fame
{
    /// <summary>Domain-separation tag of the attribute / column random oracles (RFC 9380 SSWU_RO into G1).</summary>
    public const string AttrDst = "ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1";

    static readonly P1 G1 = P1.generator();
    static readonly P2 G2 = P2.generator();

    public sealed class Mpk
    {
        public P2 H1 { get; }
        public P2 H2 { get; }
        public byte[] T1 { get; }
        public byte[] T2 { get; }
        public Mpk(P2 h1, P2 h2, byte[] t1, byte[] t2) { H1 = h1; H2 = h2; T1 = t1; T2 = t2; }
    }

    public sealed class Msk
    {
        public BigInteger[] A { get; }
        public BigInteger[] B { get; }
        public P1[] G { get; }
        public Msk(BigInteger[] a, BigInteger[] b, P1[] g) { A = a; B = b; G = g; }
    }

    public sealed class Key
    {
        public P2[] K0 { get; }
        public P1[] Kp { get; }
        public Dictionary<string, P1[]> Attrs { get; }
        public Key(P2[] k0, P1[] kp, Dictionary<string, P1[]> attrs) { K0 = k0; Kp = kp; Attrs = attrs; }
    }

    public sealed class Ciphertext
    {
        public P2[] Ct0 { get; }
        public List<P1[]> Rows { get; }
        public Ciphertext(P2[] ct0, List<P1[]> rows) { Ct0 = ct0; Rows = rows; }
    }

    /// <summary>Setup output.</summary>
    public sealed class Master
    {
        public Mpk Mpk { get; }
        public Msk Msk { get; }
        internal Master(Mpk mpk, Msk msk) { Mpk = mpk; Msk = msk; }
    }

    /// <summary>Encrypt output: the ciphertext and the KEM key (a GT element).</summary>
    public sealed class Encapsulation
    {
        public Ciphertext Ct { get; }
        public byte[] K { get; }
        internal Encapsulation(Ciphertext ct, byte[] k) { Ct = ct; K = k; }
    }

    // ---- scalar multiplication with the reference's zero rule ----

    /// <summary>k*P for k non-zero mod r; a zero scalar throws (the reference refuses it).</summary>
    static P1 Mul(P1 p, BigInteger k)
    {
        if (Bls12.Mod(k).IsZero) throw new ArithmeticException("scalar is zero");
        return Bls12.Mul(p, k);
    }

    static P2 Mul(P2 p, BigInteger k)
    {
        if (Bls12.Mod(k).IsZero) throw new ArithmeticException("scalar is zero");
        return Bls12.Mul(p, k);
    }

    /// <summary>k*P, the identity when k is zero mod r.</summary>
    static P1 MulZ(P1 p, BigInteger k) => Bls12.Mul(p, k);

    // ---- random oracles ----

    static P1 HashToG1(byte[] msg) => new P1().hash_to(msg, AttrDst, null);

    static byte[] U32(int n) => new[] { (byte)(n >>> 24), (byte)(n >>> 16), (byte)(n >>> 8), (byte)n };

    /// <summary>H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t.</summary>
    public static P1 HAttr(string attr, int l, int t)
    {
        var a = Encoding.UTF8.GetBytes(attr);
        var o = new List<byte> { 1 };
        o.AddRange(U32(a.Length));
        o.AddRange(a);
        o.Add((byte)l);
        o.Add((byte)t);
        return HashToG1(o.ToArray());
    }

    /// <summary>H0(j, l, t): the column-indexed oracle (kind byte 2).</summary>
    public static P1 HCol(int j, int l, int t)
    {
        var o = new List<byte> { 2 };
        o.AddRange(U32(j));
        o.Add((byte)l);
        o.Add((byte)t);
        return HashToG1(o.ToArray());
    }

    // ---- setup / keygen ----

    public static Master Setup(BigInteger[] a, BigInteger[] b, BigInteger[] d)
    {
        var egh = Gt.Pairing(G1, G2);
        var mpk = new Mpk(Mul(G2, a[0]), Mul(G2, a[1]),
            Gt.Pow(egh, Bls12.Add(Bls12.Mul(d[0], a[0]), d[2])), Gt.Pow(egh, Bls12.Add(Bls12.Mul(d[1], a[1]), d[2])));
        return new Master(mpk, new Msk(a, b, new[] { Mul(G1, d[0]), Mul(G1, d[1]), Mul(G1, d[2]) }));
    }

    static P1 KeyTerm(Func<int, P1> oracle, BigInteger[] pow, BigInteger sigma, BigInteger aInv)
    {
        var sum = MulZ(oracle(0), pow[0]).add(MulZ(oracle(1), pow[1])).add(MulZ(oracle(2), pow[2])).add(Mul(G1, sigma));
        return Mul(sum, aInv);
    }

    public static Key Keygen(Msk msk, IReadOnlyList<string> attrs, BigInteger[] r, IReadOnlyList<BigInteger> sigmas, BigInteger sigmaPrime)
    {
        var pow = new[] { Bls12.Mul(msk.B[0], r[0]), Bls12.Mul(msk.B[1], r[1]), Bls12.Add(r[0], r[1]) };
        var aInv = new[] { Bls12.Inv(msk.A[0]), Bls12.Inv(msk.A[1]) };
        var k0 = new[] { Mul(G2, pow[0]), Mul(G2, pow[1]), Mul(G2, pow[2]) };
        var o = new Dictionary<string, P1[]>();
        for (int i = 0; i < attrs.Count; i++)
        {
            var y = attrs[i];
            if (i >= sigmas.Count) throw new ArgumentException("fameKeygen: one sigma per attribute is required");
            var sg = sigmas[i];
            o[y] = new[]
            {
                KeyTerm(l => HAttr(y, l, 0), pow, sg, aInv[0]),
                KeyTerm(l => HAttr(y, l, 1), pow, sg, aInv[1]),
                Mul(G1, Bls12.Sub(BigInteger.Zero, sg)),
            };
        }
        var kp = new[]
        {
            KeyTerm(l => HCol(0, l, 0), pow, sigmaPrime, aInv[0]).add(msk.G[0]),
            KeyTerm(l => HCol(0, l, 1), pow, sigmaPrime, aInv[1]).add(msk.G[1]),
            Mul(G1, Bls12.Sub(BigInteger.Zero, sigmaPrime)).add(msk.G[2]),
        };
        return new Key(k0, kp, o);
    }

    // ---- span program ----

    sealed class Row
    {
        public readonly string Attr;
        public readonly Dictionary<int, BigInteger> Vec;
        public Row(string attr, Dictionary<int, BigInteger> vec) { Attr = attr; Vec = vec; }
    }

    /// <summary>Leaves in depth-first order, each with its sparse span-program row (column 0 is the secret column, always 1).</summary>
    static List<Row> BuildRows(D tree)
    {
        var rows = new List<Row>();
        var ncols = new[] { 1 };
        Walk(tree, new Dictionary<int, BigInteger> { [0] = BigInteger.One }, rows, ncols);
        return rows;
    }

    static void Walk(D node, Dictionary<int, BigInteger> vec, List<Row> rows, int[] ncols)
    {
        if (AbePolicy.IsLeaf(node))
        {
            rows.Add(new Row((string)node["attr"]!, vec));
            return;
        }
        int t = AbePolicy.T(node);
        int bas = ncols[0];
        ncols[0] += t - 1;
        var of = AbePolicy.Of(node);
        for (int idx = 0; idx < of.Count; idx++)
        {
            var cv = new Dictionary<int, BigInteger>(vec);
            BigInteger x = idx + 1, pw = BigInteger.One;
            for (int k = 1; k < t; k++)
            {
                pw = Bls12.Mul(pw, x);
                cv[bas + k - 1] = pw;
            }
            Walk(of[idx], cv, rows, ncols);
        }
    }

    internal static int LeafCount(D tree)
    {
        if (AbePolicy.IsLeaf(tree)) return 1;
        int n = 0;
        foreach (var c in AbePolicy.Of(tree)) n += LeafCount(c);
        return n;
    }

    /// <summary>First attribute named by two leaves, or null (FAME needs an injective row labelling).</summary>
    internal static string? FirstRepeatedAttribute(D tree)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in AbePolicy.Leaves(tree)) if (!seen.Add(a)) return a;
        return null;
    }

    // ---- encrypt ----

    public static Encapsulation Encrypt(Mpk mpk, D tree, BigInteger[] s)
    {
        var rows = BuildRows(tree);
        var colMemo = new Dictionary<string, P1>();
        var o = new List<P1[]>();
        foreach (var row in rows)
        {
            var tri = new P1[3];
            for (int l = 0; l < 3; l++)
            {
                var acc = Mul(HAttr(row.Attr, l, 0), s[0]).add(Mul(HAttr(row.Attr, l, 1), s[1]));
                foreach (var e in row.Vec)
                {
                    int j = e.Key, ll = l;
                    var memoKey = j + ":" + l;
                    if (!colMemo.TryGetValue(memoKey, out var col))
                    {
                        col = Mul(HCol(j, ll, 0), s[0]).add(Mul(HCol(j, ll, 1), s[1]));
                        colMemo[memoKey] = col;
                    }
                    acc = acc.add(MulZ(col, e.Value));
                }
                tri[l] = acc;
            }
            o.Add(tri);
        }
        var ct = new Ciphertext(new[] { Mul(mpk.H1, s[0]), Mul(mpk.H2, s[1]), Mul(G2, Bls12.Add(s[0], s[1])) }, o);
        return new Encapsulation(ct, Gt.Mul(Gt.Pow(mpk.T1, s[0]), Gt.Pow(mpk.T2, s[1])));
    }

    // ---- decrypt ----

    /// <summary>A decryption plan: a leaf row, or a gate with the chosen children and their evaluation points.</summary>
    sealed class Plan
    {
        public readonly int Row;
        public readonly List<BigInteger>? Xs;
        public readonly List<Plan>? Subs;
        public Plan(int row) { Row = row; }
        public Plan(List<BigInteger> xs, List<Plan> subs) { Row = -1; Xs = xs; Subs = subs; }
    }

    /// <summary>Bottom-up, the first t satisfiable children of every gate; null when the subtree is not satisfied.</summary>
    static Plan? PlanOf(D node, Func<string, bool> has, int offset)
    {
        if (AbePolicy.IsLeaf(node)) return has((string)node["attr"]!) ? new Plan(offset) : null;
        int t = AbePolicy.T(node);
        var xs = new List<BigInteger>();
        var subs = new List<Plan>();
        int off = offset;
        var of = AbePolicy.Of(node);
        for (int i = 0; i < of.Count; i++)
        {
            var sub = PlanOf(of[i], has, off);
            if (sub != null)
            {
                xs.Add(i + 1);
                subs.Add(sub);
            }
            if (subs.Count >= t) break;
            off += LeafCount(of[i]);
        }
        return subs.Count < t ? null : new Plan(xs, subs);
    }

    static bool Weights(Plan p, BigInteger w, Dictionary<int, BigInteger> o)
    {
        if (p.Subs == null)
        {
            o[p.Row] = w;
            return true;
        }
        var lambda = LagrangeAtZero(p.Xs!);
        if (lambda == null) return false;
        for (int i = 0; i < p.Subs.Count; i++) if (!Weights(p.Subs[i], Bls12.Mul(w, lambda[i]), o)) return false;
        return true;
    }

    /// <summary>Lagrange coefficients L_i(0) over Z_r; null on an empty set, a zero point, or coinciding points.</summary>
    internal static List<BigInteger>? LagrangeAtZero(IReadOnlyList<BigInteger> xs)
    {
        if (xs.Count == 0) return null;
        var seen = new HashSet<BigInteger>();
        foreach (var x in xs)
        {
            var xr = Bls12.Mod(x);
            if (xr.IsZero || !seen.Add(xr)) return null;
        }
        var o = new List<BigInteger>();
        for (int i = 0; i < xs.Count; i++)
        {
            BigInteger num = BigInteger.One, den = BigInteger.One;
            for (int j = 0; j < xs.Count; j++)
            {
                if (j == i) continue;
                num = Bls12.Mul(num, xs[j]);
                den = Bls12.Mul(den, Bls12.Sub(xs[j], xs[i]));
            }
            o.Add(Bls12.Mul(num, Bls12.Inv(den)));
        }
        return o;
    }

    /// <summary>Row index -> reconstruction weight over the rows the key can use; null when the attribute set does not satisfy the tree.</summary>
    static Dictionary<int, BigInteger>? ReconstructionWeights(D tree, Func<string, bool> has)
    {
        var p = PlanOf(tree, has, 0);
        if (p == null) return null;
        var o = new Dictionary<int, BigInteger>();
        return Weights(p, BigInteger.One, o) ? o : null;
    }

    /// <summary>The KEM key, or null when the key does not satisfy the tree (or a pairing input is the identity).</summary>
    public static byte[]? Decrypt(Key key, D tree, Ciphertext ct)
    {
        var rows = AbePolicy.Leaves(tree);
        if (rows.Count != ct.Rows.Count) return null;
        var w = ReconstructionWeights(tree, key.Attrs.ContainsKey);
        if (w == null) return null;
        var g1 = new List<P1>();
        var g2 = new List<P2>();
        for (int l = 0; l < 3; l++)
        {
            var ctProd = Bls12.Id1();
            var keyProd = key.Kp[l].dup();
            foreach (var e in w)
            {
                if (!key.Attrs.TryGetValue(rows[e.Key], out var comp)) return null;
                var cRow = ct.Rows[e.Key];
                ctProd = ctProd.add(MulZ(cRow[l], e.Value));
                keyProd = keyProd.add(MulZ(comp[l], e.Value));
            }
            g1.Add(keyProd);
            g2.Add(ct.Ct0[l]);
            g1.Add(ctProd.dup().neg());
            g2.Add(key.K0[l]);
        }
        try { return Gt.PairingProduct(g1, g2); }
        catch (ArgumentException) { return null; }
    }
}
