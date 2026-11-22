using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace AtlasPca.Mpc;

/// <summary>
/// Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four
/// little-endian u32 words (an int[] holds unsigned words), and the batched tweakable correlation-robust hash
/// H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128 truncated to 64 bits.
/// </summary>
public static class Otx
{
    /// <summary>Number of bit columns of the IKNP matrix (kappa).</summary>
    public const int COLS = 128;

    static readonly byte[] TagPrgKey = Encoding.UTF8.GetBytes("atlas-pca-mpc/ot-prg-aes");
    static readonly byte[] TagCrhKey = Encoding.UTF8.GetBytes("atlas-pca-mpc/ot-crh-aes-fixed-key");
    static readonly byte[] TagTweakDomain = Encoding.UTF8.GetBytes("atlas-pca-mpc/ot-crh-tweak-domain/v2");

    static byte[] Sha256(params byte[][] chunks)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var c in chunks) h.AppendData(c);
        return h.GetHashAndReset();
    }

    /// <summary>Little-endian bytes of a non-negative bigint, exactly len bytes (the low bytes).</summary>
    public static byte[] BigToBytes(BigInteger v, int len) => Ec.LeBytes(v, len);

    /// <summary>The bigint with the given little-endian bytes.</summary>
    public static BigInteger BytesToBig(byte[] b) => new(b, isUnsigned: true, isBigEndian: false);

    static byte[] PrgKey(byte[] seed) => Sha256(TagPrgKey, seed)[..16];

    static int[] LeWords(byte[] b, int off, int n)
    {
        var o = new int[n];
        for (int i = 0; i < n; i++)
        {
            int p = off + 4 * i;
            o[i] = b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);
        }
        return o;
    }

    static byte[] LeBytes(int[] w, int n)
    {
        var o = new byte[4 * n];
        for (int i = 0; i < n; i++)
        {
            o[4 * i] = (byte)w[i];
            o[4 * i + 1] = (byte)(w[i] >>> 8);
            o[4 * i + 2] = (byte)(w[i] >>> 16);
            o[4 * i + 3] = (byte)(w[i] >>> 24);
        }
        return o;
    }

    static byte[] AesEcb(byte[] key, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(data, PaddingMode.None);
    }

    /// <summary>nwords u32 words of the PRG stream of seed from AES block startBlock (high tail bits unmasked): AES-128-CTR keystream, big-endian counter.</summary>
    public static int[] PrgColumn(byte[] seed, long startBlock, int nwords)
    {
        int blocks = (nwords * 4 + 15) / 16;
        var iv = new byte[16];
        for (int i = 0; i < 8; i++) iv[15 - i] = (byte)(startBlock >>> (8 * i));
        var ctr = new SicBlockCipher(new AesEngine());
        ctr.Init(true, new ParametersWithIV(new KeyParameter(PrgKey(seed)), iv));
        var zero = new byte[16];
        var ks = new byte[blocks * 16];
        for (int k = 0; k < blocks; k++) ctr.ProcessBlock(zero, 0, ks, k * 16);
        return LeWords(ks, 0, nwords);
    }

    /// <summary>Clears the bits at positions >= nbits in a little-endian word column.</summary>
    public static void MaskTail(int[] col, int nbits)
    {
        int full = nbits >>> 5;
        int rem = nbits & 31;
        if (rem != 0) col[full] &= (1 << rem) - 1;
        for (int i = rem != 0 ? full + 1 : full; i < col.Length; i++) col[i] = 0;
    }

    /// <summary>In-place transpose of a 32x32 bit matrix held as 32 u32 words from off.</summary>
    public static void Transpose32(int[] a, int off)
    {
        int m = 0x0000ffff;
        for (int j = 16; j != 0; j >>>= 1, m = m ^ (m << j))
        {
            for (int k = 0; k < 32; k = (k + j + 1) & ~j)
            {
                int t = ((a[off + k] >>> j) ^ a[off + k + j]) & m;
                a[off + k] ^= t << j;
                a[off + k + j] ^= t;
            }
        }
    }

    /// <summary>Transposes COLS bit-columns (each W words, concatenated) into rows rows of four words.</summary>
    public static int[] TransposeCols(int[] cols, int W, int rows)
    {
        var o = new int[rows * 4];
        var tmp = new int[32];
        int blocks = (rows + 31) >>> 5;
        for (int rb = 0; rb < blocks; rb++)
        {
            for (int cb = 0; cb < 4; cb++)
            {
                for (int c = 0; c < 32; c++) tmp[c] = cols[(cb * 32 + c) * W + rb];
                Transpose32(tmp, 0);
                int lim = Math.Min(32, rows - rb * 32);
                for (int r = 0; r < lim; r++) o[(rb * 32 + r) * 4 + cb] = tmp[r];
            }
        }
        return o;
    }

    /// <summary>acc ^= the four-word element at v[vo..].</summary>
    public static void GfXorInto(int[] acc, int[] v, int vo)
    {
        acc[0] ^= v[vo];
        acc[1] ^= v[vo + 1];
        acc[2] ^= v[vo + 2];
        acc[3] ^= v[vo + 3];
    }

    /// <summary>acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1).</summary>
    public static void GfMulX(int[] acc)
    {
        int carry = acc[3] >>> 31;
        acc[3] = (acc[3] << 1) | (acc[2] >>> 31);
        acc[2] = (acc[2] << 1) | (acc[1] >>> 31);
        acc[1] = (acc[1] << 1) | (acc[0] >>> 31);
        acc[0] = (acc[0] << 1) ^ (carry != 0 ? 0x87 : 0);
    }

    /// <summary>XORs into acc chi[j] (four words) for every set bit j of the word column col[off..off+len).</summary>
    public static void AccumColumn(int[] col, int off, int len, int[] chi, int[] acc)
    {
        for (int w = 0; w < len; w++)
        {
            int x = col[off + w];
            int bas = w << 5;
            while (x != 0)
            {
                int j = bas + BitOperations.TrailingZeroCount(x);
                int o = j << 2;
                acc[0] ^= chi[o];
                acc[1] ^= chi[o + 1];
                acc[2] ^= chi[o + 2];
                acc[3] ^= chi[o + 3];
                x &= x - 1;
            }
        }
    }

    /// <summary>sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles.</summary>
    public static int[] KosCombine(int[] cols, int W, int[] chi)
    {
        var acc = new int[4];
        var part = new int[4];
        for (int i = COLS - 1; i >= 0; i--)
        {
            GfMulX(acc);
            Array.Fill(part, 0);
            AccumColumn(cols, i * W, W, chi, part);
            GfXorInto(acc, part, 0);
        }
        return acc;
    }

    public static int[] GfFromBig(BigInteger v)
    {
        var o = new int[4];
        for (int i = 0; i < 4; i++) o[i] = unchecked((int)(uint)((v >> (32 * i)) & 0xffffffffu));
        return o;
    }

    public static BigInteger GfToBig(int[] w, int off)
    {
        var v = BigInteger.Zero;
        for (int i = 3; i >= 0; i--) v = (v << 32) | (uint)w[off + i];
        return v;
    }

    public static BigInteger GfToBig(int[] w) => GfToBig(w, 0);

    static byte[] CrhKey() => Sha256(TagCrhKey)[..16];

    /// <summary>The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words.</summary>
    public static int[] OtTweakDomain(byte[] binding) => LeWords(Sha256(TagTweakDomain, binding), 0, 2);

    /// <summary>Tweak of a hash call: channel-global row offset plus the 2-word session domain.</summary>
    public sealed record OtTweak(long Offset, int[] Domain);

    /// <summary>H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash).</summary>
    public static int[] TmmoCrh(int[] rows, int n, OtTweak? tweak)
    {
        long offset = tweak == null ? 0 : tweak.Offset;
        int[] dom = tweak == null ? new int[2] : tweak.Domain;
        if (offset < 0 || offset > (1L << 53) - 1) throw new ArgumentException("tmmoCrh: tweak offset must be a non-negative safe integer");
        if (dom.Length != 2) throw new ArgumentException("tmmoCrh: tweak domain must be 2 words");
        var key = CrhKey();
        var a = AesEcb(key, LeBytes(rows, n * 4));
        var aw = LeWords(a, 0, n * 4);
        var b = new int[n * 4];
        for (int j = 0; j < n; j++)
        {
            int o = j * 4;
            long v = offset + j;
            b[o] = aw[o] ^ (int)v;
            b[o + 1] = aw[o + 1] ^ (int)(v >>> 32);
            b[o + 2] = aw[o + 2] ^ dom[0];
            b[o + 3] = aw[o + 3] ^ dom[1];
        }
        var cw = LeWords(AesEcb(key, LeBytes(b, n * 4)), 0, n * 4);
        var outw = new int[n * 2];
        for (int j = 0; j < n; j++)
        {
            outw[2 * j] = cw[4 * j] ^ aw[4 * j];
            outw[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1];
        }
        return outw;
    }

    /// <summary>The 64-bit value of the two words at index j of a TmmoCrh output.</summary>
    public static BigInteger Word64(int[] h, int j) => new(((ulong)(uint)h[2 * j + 1] << 32) | (uint)h[2 * j]);

    internal static int[] WordsFromLeBytes(byte[] b, int nwords) => LeWords(b, 0, nwords);
}
