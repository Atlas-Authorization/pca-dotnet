// Intel PCS collateral for the genuine DCAP TDX quote path: signed TCB info and QE identity (ECDSA-P256 over the exact bytes of the
// signed value, under the TCB Signing certificate whose issuer chain ends at the pinned Intel SGX Root CA), the PCK and Root CA CRLs,
// the evaluated TCB status and a status policy. Offline given the collateral bytes; fails closed on missing, stale, malformed,
// unsigned or revoked collateral. The CRL reader is shared with the NVIDIA CRL checks.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

internal sealed class CollateralPolicy
{
    public List<string> AcceptStatuses = new();
    public bool HasAccept, HasMinEval;
    public double MinEval;
}

internal sealed class IntelCollateral
{
    public string TcbInfoJson = "", TcbInfoChain = "", QeIdentityJson = "", QeIdentityChain = "";
    public byte[] PckCrl = Array.Empty<byte>(), RootCrl = Array.Empty<byte>();

    internal static IntelCollateral FromWire(JD m)
    {
        string S(string k) => m.GetValueOrDefault(k) as string ?? "";
        return new IntelCollateral
        {
            TcbInfoJson = S("tcbInfoJson"), TcbInfoChain = S("tcbInfoIssuerChainPem"), QeIdentityJson = S("qeIdentityJson"), QeIdentityChain = S("qeIdentityIssuerChainPem"),
            PckCrl = AttestEvidence.Bytes(m, "pckCrlDer") ?? Array.Empty<byte>(), RootCrl = AttestEvidence.Bytes(m, "rootCrlDer") ?? Array.Empty<byte>(),
        };
    }
}

internal sealed class CollateralResult
{
    public bool Ok;
    public string Reason = "", Status = "";
    public List<string> AdvisoryIds = new();
}

internal sealed class ParsedCrl
{
    public byte[] Tbs = Array.Empty<byte>(), SigDer = Array.Empty<byte>();
    public long ThisUpdate, NextUpdate;
    public bool HasNext;
    public HashSet<string> Revoked = new(StringComparer.Ordinal);
}

internal static class AttestIntelCollateral
{
    static readonly string[] TcbStatusOrder = { "UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked" };
    static readonly string[] DefaultAccepted = { "UpToDate", "SWHardeningNeeded" };

    // ---- CRL reading (lenient lengths, as the reference)

    internal static DerTlv TlvLenient(byte[] b, int off, int limit)
    {
        if (off + 2 > limit) throw new AttestError("DER truncated");
        byte tag = b[off];
        long l = b[off + 1];
        int p = off + 2;
        if ((l & 0x80) != 0)
        {
            int n = (int)(l & 0x7f);
            if (n == 0 || n > 4 || p + n > limit) throw new AttestError("DER bad length");
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + b[p + i];
            p += n;
        }
        if (p + l > limit) throw new AttestError("DER overrun");
        return new DerTlv(tag, p, (int)(p + l));
    }

    static readonly Regex UtcTimeRe = new(@"^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z", RegexOptions.CultureInvariant);
    static readonly Regex GenTimeRe = new(@"^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\z", RegexOptions.CultureInvariant);

    static int Grp(Match m, int g) => int.Parse(m.Groups[g].Value, CultureInfo.InvariantCulture);

    /// <summary>Date.UTC (fields roll over; a year 0..99 means 19YY).</summary>
    static long DateUtc(int y, int mo, int d, int h, int mi, int s) => AttestDer.EpochMs(y is >= 0 and <= 99 ? y + 1900 : y, mo, d, h, mi, s);

    static long CrlTime(byte[] b, DerTlv t)
    {
        var s = Encoding.Latin1.GetString(b, t.Start, t.End - t.Start);
        switch (t.Tag)
        {
            case 0x17:
                {
                    var m = UtcTimeRe.Match(s);
                    if (!m.Success) throw new AttestError("bad UTCTime");
                    int yy = Grp(m, 1);
                    int y = yy >= 50 ? 1900 + yy : 2000 + yy;
                    return DateUtc(y, Grp(m, 2), Grp(m, 3), Grp(m, 4), Grp(m, 5), Grp(m, 6));
                }
            case 0x18:
                {
                    var m = GenTimeRe.Match(s);
                    if (!m.Success) throw new AttestError("bad GeneralizedTime");
                    return DateUtc(Grp(m, 1), Grp(m, 2), Grp(m, 3), Grp(m, 4), Grp(m, 5), Grp(m, 6));
                }
        }
        throw new AttestError("not a DER time");
    }

    internal static string NormSerial(string s) => s.ToLowerInvariant().TrimStart('0');

    internal static ParsedCrl ParseCrl(byte[] der)
    {
        var outer = TlvLenient(der, 0, der.Length);
        if (outer.Tag != 0x30 || outer.End != der.Length) throw new AttestError("CRL: bad outer SEQUENCE");
        var tbsT = TlvLenient(der, outer.Start, outer.End);
        if (tbsT.Tag != 0x30) throw new AttestError("CRL: bad TBSCertList");
        var crl = new ParsedCrl { Tbs = der[outer.Start..tbsT.End] };
        var algT = TlvLenient(der, tbsT.End, outer.End);
        var sigT = TlvLenient(der, algT.End, outer.End);
        if (sigT.Tag != 0x03 || sigT.End != outer.End) throw new AttestError("CRL: bad signature");
        if (sigT.Start + 1 <= sigT.End) crl.SigDer = der[(sigT.Start + 1)..sigT.End];
        int p = tbsT.Start;
        var t = TlvLenient(der, p, tbsT.End);
        if (t.Tag == 0x02)
        {
            p = t.End;
            t = TlvLenient(der, p, tbsT.End);
        }
        p = t.End; // signature AlgorithmIdentifier
        var iss = TlvLenient(der, p, tbsT.End);
        if (iss.Tag != 0x30) throw new AttestError("CRL: bad issuer");
        var tu = TlvLenient(der, iss.End, tbsT.End);
        crl.ThisUpdate = CrlTime(der, tu);
        int q = tu.End;
        if (q < tbsT.End)
        {
            var n = TlvLenient(der, q, tbsT.End);
            if (n.Tag == 0x17 || n.Tag == 0x18)
            {
                crl.NextUpdate = CrlTime(der, n);
                crl.HasNext = true;
                q = n.End;
            }
            if (q < tbsT.End)
            {
                n = TlvLenient(der, q, tbsT.End);
                if (n.Tag == 0x30)
                {
                    int e = n.Start;
                    while (e < n.End)
                    {
                        var ent = TlvLenient(der, e, n.End);
                        var ser = TlvLenient(der, ent.Start, ent.End);
                        if (ser.Tag != 0x02) throw new AttestError("CRL: bad revoked entry");
                        crl.Revoked.Add(NormSerial(AttestUtil.Hex(der[ser.Start..ser.End])));
                        e = ent.End;
                    }
                }
            }
        }
        if (!crl.HasNext) throw new AttestError("CRL: missing nextUpdate");
        return crl;
    }

    /// <summary>verify('sha256', tbs, issuerKey, sig): ECDSA (DER) or RSA PKCS#1 v1.5 under the issuer key.</summary>
    internal static bool CrlSigOk(byte[] tbs, byte[] sig, CertKey k)
    {
        try
        {
            if (k.Ec != null) return k.Ec.VerifyHash(AttestUtil.Sha256(tbs), sig, DSASignatureFormat.Rfc3279DerSequence);
            if (k.Rsa != null) return k.Rsa.VerifyHash(AttestUtil.Sha256(tbs), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception) { }
        return false;
    }

    /// <summary>Verifies a DER CRL under the issuer key at nowMs. The revoked serials (lowercase hex, no leading zeros), or the reason.</summary>
    internal static (HashSet<string>? Revoked, string Why) VerifyCrl(byte[] der, CertKey issuer, long nowMs)
    {
        ParsedCrl crl;
        try { crl = ParseCrl(der); }
        catch (AttestError e) { return (null, "CRL parse failed: " + e.Message); }
        if (!CrlSigOk(crl.Tbs, crl.SigDer, issuer)) return (null, "CRL signature does not verify under the issuer");
        if (nowMs < crl.ThisUpdate) return (null, "CRL thisUpdate is in the future");
        if (nowMs > crl.NextUpdate) return (null, "CRL is stale (nextUpdate passed)");
        return (crl.Revoked, "");
    }

    // ---- signed JSON documents

    static int SkipJsSpace(string s, int i)
    {
        while (i < s.Length && AttestUtil.IsJsSpace(s[i])) i++;
        return i;
    }

    /// <summary>The exact source text of the JSON object following <c>"&lt;name&gt;":</c> in a top-level object.</summary>
    internal static string? RawJsonObject(string text, string name)
    {
        int i = SkipJsSpace(text, 0);
        if (i >= text.Length || text[i] != '{') return null;
        i = SkipJsSpace(text, i + 1);
        var key = "\"" + name + "\"";
        if (!text.AsSpan(i).StartsWith(key, StringComparison.Ordinal)) return null;
        i = SkipJsSpace(text, i + key.Length);
        if (i >= text.Length || text[i] != ':') return null;
        i = SkipJsSpace(text, i + 1);
        if (i >= text.Length || text[i] != '{') return null;
        int start = i, depth = 0;
        bool inStr = false;
        for (; i < text.Length; i++)
        {
            char ch = text[i];
            if (inStr)
            {
                if (ch == '\\') i++;
                else if (ch == '"') inStr = false;
            }
            else if (ch == '"') inStr = true;
            else if (ch == '{') depth++;
            else if (ch == '}')
            {
                depth--;
                if (depth == 0) return text[start..(i + 1)];
            }
        }
        return null;
    }

    static readonly Regex Sig128Re = new(@"^[0-9a-fA-F]{128}\z", RegexOptions.CultureInvariant);

    /// <summary>Verifies a PCS document: the body under <paramref name="name"/>, or the failure text.</summary>
    internal static (JD? Body, string Why) VerifySignedJson(string text, string name, CertKey k)
    {
        var raw = RawJsonObject(text, name);
        if (raw == null) return (null, name + " not found / malformed");
        object? doc;
        try { doc = Pca.ParseJson(text); }
        catch (Exception) { return (null, name + " document is not valid JSON"); }
        var top = doc as JD;
        var sig = top?.GetValueOrDefault("signature") as string ?? "";
        if (!Sig128Re.IsMatch(sig)) return (null, name + " signature missing or malformed");
        bool ok = false;
        if (k.Ec != null)
        {
            try { ok = k.Ec.VerifyHash(AttestUtil.Sha256(Encoding.UTF8.GetBytes(raw)), Convert.FromHexString(sig), DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            catch (Exception) { ok = false; }
        }
        if (!ok) return (null, name + " signature does not verify under the TCB Signing certificate");
        if (top!.GetValueOrDefault(name) is not JD body) return (null, name + " is not an object");
        return (body, "");
    }

    /// <summary>Date.parse for the ISO-8601 forms PCS documents use (epoch ms), null otherwise.</summary>
    internal static long? JsDateParse(string s)
    {
        foreach (var f in new[] { "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFFFK", "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mmK", "yyyy-MM-dd" })
            if (DateTimeOffset.TryParseExact(s, f, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)) return t.ToUnixTimeMilliseconds();
        return null;
    }

    static string CheckFresh(JD body, string what, long nowMs)
    {
        long? issue = body.GetValueOrDefault("issueDate") is string a ? JsDateParse(a) : null;
        long? next = body.GetValueOrDefault("nextUpdate") is string b ? JsDateParse(b) : null;
        if (issue == null || next == null) return what + ": issueDate/nextUpdate missing";
        if (nowMs < issue) return what + ": issueDate is in the future";
        if (nowMs > next) return what + ": stale (nextUpdate passed)";
        return "";
    }

    // ---- status evaluation

    static int StatusRank(string s) => Array.IndexOf(TcbStatusOrder, s);

    static string? AsTcbStatus(object? v) => v is string s && StatusRank(s) >= 0 ? s : null;

    static string WorstStatus(string a, string b) => StatusRank(a) >= StatusRank(b) ? a : b;

    static List<double>? SvnList(object? v)
    {
        if (v is not JL arr || arr.Count != 16) return null;
        var o = new List<double>();
        foreach (var c in arr)
        {
            if (c is not JD rec || AttestUtil.AsFinite(rec.GetValueOrDefault("svn")) is not double f) return null;
            o.Add(f);
        }
        return o;
    }

    static readonly Regex HexRe = new(@"^[0-9a-fA-F]+\z", RegexOptions.CultureInvariant);

    static byte[]? HexBytesN(object? v, int n) => v is string s && s.Length == n * 2 && HexRe.IsMatch(s) ? Convert.FromHexString(s) : null;

    static List<string> AdvisoryList(JD level) => (level.GetValueOrDefault("advisoryIDs") as JL ?? new JL()).OfType<string>().ToList();

    static bool MaskedEq(ReadOnlySpan<byte> value, byte[] mask, byte[] expected)
    {
        for (int i = 0; i < value.Length; i++) if (((value[i] & mask[i]) ^ (expected[i] & mask[i])) != 0) return false;
        return true;
    }

    /// <summary>levels.find(l => isRecord(l) &amp;&amp; isRecord(l.tcb) &amp;&amp; typeof l.tcb.isvsvn === 'number' &amp;&amp; l.tcb.isvsvn &lt;= svn).</summary>
    static JD? FindLevel(object? levels, double svn)
    {
        foreach (var x in levels as JL ?? new JL())
            if (x is JD l && l.GetValueOrDefault("tcb") is JD tcb && AttestUtil.AsFinite(tcb.GetValueOrDefault("isvsvn")) is double f && f <= svn) return l;
        return null;
    }

    sealed record TcbEval(string Platform = "", string Module = "", List<string>? Advisories = null, string Err = "");

    static TcbEval EvaluateTcb(JD info, byte[] pckSgx, int pckPcesvn, byte[] teeTcbSvn, byte[] mrSignerSeam, byte[] seamAttributes)
    {
        var levels = info.GetValueOrDefault("tcbLevels") as JL ?? new JL();
        if (levels.Count == 0) return new TcbEval(Err: "TCB info has no tcbLevels");
        int minor = teeTcbSvn[1];
        string moduleStatus = "UpToDate";
        var adv = new HashSet<string>(StringComparer.Ordinal);
        object? modMrSigner, modAttr, modMask;
        if (minor > 0)
        {
            var id = $"TDX_{minor:X2}";
            JD? ident = null;
            if (info.GetValueOrDefault("tdxModuleIdentities") is JL ids)
                foreach (var x in ids) if (x is JD r && r.GetValueOrDefault("id") is string rid && rid == id) { ident = r; break; }
            if (ident == null) return new TcbEval(Err: $"TDX module identity {id} not present in TCB info");
            modMrSigner = ident.GetValueOrDefault("mrsigner"); modAttr = ident.GetValueOrDefault("attributes"); modMask = ident.GetValueOrDefault("attributesMask");
            var hit = FindLevel(ident.GetValueOrDefault("tcbLevels"), teeTcbSvn[0]);
            if (hit == null) return new TcbEval(Err: $"TDX module {id} SVN {teeTcbSvn[0]} is below every known level");
            var st = AsTcbStatus(hit.GetValueOrDefault("tcbStatus"));
            if (st == null) return new TcbEval(Err: "TDX module level has an unknown tcbStatus");
            moduleStatus = st;
            foreach (var a in AdvisoryList(hit)) adv.Add(a);
        }
        else
        {
            if (info.GetValueOrDefault("tdxModule") is not JD m) return new TcbEval(Err: "TCB info missing tdxModule");
            modMrSigner = m.GetValueOrDefault("mrsigner"); modAttr = m.GetValueOrDefault("attributes"); modMask = m.GetValueOrDefault("attributesMask");
        }
        var exMr = HexBytesN(modMrSigner, 48); var exAttr = HexBytesN(modAttr, 8); var mask = HexBytesN(modMask, 8);
        if (exMr == null || exAttr == null || mask == null) return new TcbEval(Err: "TDX module identity fields malformed");
        if (!exMr.AsSpan().SequenceEqual(mrSignerSeam)) return new TcbEval(Err: "TD report MRSIGNERSEAM does not match the TDX module identity");
        if (!MaskedEq(seamAttributes, mask, exAttr)) return new TcbEval(Err: "TD report SEAM attributes do not match the TDX module identity");
        int fromIdx = minor > 0 ? 2 : 0;
        foreach (var x in levels)
        {
            var l = x as JD;
            var tcb = l?.GetValueOrDefault("tcb") as JD;
            if (l == null || tcb == null) return new TcbEval(Err: "malformed TCB level");
            var sgx = SvnList(tcb.GetValueOrDefault("sgxtcbcomponents")); var tdx = SvnList(tcb.GetValueOrDefault("tdxtcbcomponents"));
            var pce = AttestUtil.AsFinite(tcb.GetValueOrDefault("pcesvn"));
            if (sgx == null || tdx == null || pce == null) return new TcbEval(Err: "malformed TCB level components");
            var st = AsTcbStatus(l.GetValueOrDefault("tcbStatus"));
            if (st == null) return new TcbEval(Err: "TCB level has an unknown tcbStatus");
            bool match = pckPcesvn >= pce;
            for (int i = 0; match && i < 16; i++) if (pckSgx[i] < sgx[i]) match = false;
            for (int i = fromIdx; match && i < 16; i++) if (teeTcbSvn[i] < tdx[i]) match = false;
            if (!match) continue;
            foreach (var a in AdvisoryList(l)) adv.Add(a);
            var list = adv.ToList();
            list.Sort(StringComparer.Ordinal);
            return new TcbEval(st, moduleStatus, list);
        }
        return new TcbEval(Err: "platform TCB is below every level in the TCB info");
    }

    sealed record QeEval(string Status = "", List<string>? Advisories = null, string Err = "");

    static QeEval EvaluateQe(JD ident, byte[] qe)
    {
        if (ident.GetValueOrDefault("id") is not "TD_QE") return new QeEval(Err: "QE identity id is not TD_QE");
        if (AttestUtil.AsFinite(ident.GetValueOrDefault("version")) is not double ver || ver != 2) return new QeEval(Err: "unsupported QE identity version");
        var miscsel = HexBytesN(ident.GetValueOrDefault("miscselect"), 4); var miscMask = HexBytesN(ident.GetValueOrDefault("miscselectMask"), 4);
        var attr = HexBytesN(ident.GetValueOrDefault("attributes"), 16); var attrMask = HexBytesN(ident.GetValueOrDefault("attributesMask"), 16);
        var mrsigner = HexBytesN(ident.GetValueOrDefault("mrsigner"), 32); var prodId = AttestUtil.AsFinite(ident.GetValueOrDefault("isvprodid"));
        if (miscsel == null || miscMask == null || attr == null || attrMask == null || mrsigner == null || prodId == null) return new QeEval(Err: "QE identity fields malformed");
        if (qe.Length != 384) return new QeEval(Err: "QE report has wrong length");
        if (!MaskedEq(qe.AsSpan(16, 4), miscMask, miscsel)) return new QeEval(Err: "QE MISCSELECT does not match the QE identity");
        if (!MaskedEq(qe.AsSpan(48, 16), attrMask, attr)) return new QeEval(Err: "QE ATTRIBUTES do not match the QE identity");
        if (!qe.AsSpan(128, 32).SequenceEqual(mrsigner)) return new QeEval(Err: "QE MRSIGNER does not match the QE identity");
        int prod = qe[256] | (qe[257] << 8), isvsvn = qe[258] | (qe[259] << 8);
        if (prod != prodId) return new QeEval(Err: "QE ISVPRODID does not match the QE identity");
        var hit = FindLevel(ident.GetValueOrDefault("tcbLevels"), isvsvn);
        if (hit == null) return new QeEval(Err: "QE ISVSVN is below every known level");
        var st = AsTcbStatus(hit.GetValueOrDefault("tcbStatus"));
        if (st == null) return new QeEval(Err: "QE level has an unknown tcbStatus");
        return new QeEval(st, AdvisoryList(hit));
    }

    /// <summary>Verifies a PCS issuer chain (leaf first) to the pinned root, validity at nowMs and that no certificate is on the Root CA
    /// CRL. The leaf's key, or the failure text.</summary>
    static (CertKey? Key, string Why) SignerKeyFromChain(string chainPem, string pin, long nowMs, HashSet<string> rootRevoked)
    {
        var chain = AttestIntel.VerifyPckChain(chainPem, pin, nowMs);
        if (chain.Validity) return (null, "issuer chain certificate outside its validity period");
        if (!chain.Ok || chain.Leaf == null) return (null, "issuer chain invalid: " + chain.Reason);
        try
        {
            foreach (var b in AttestCerts.PemBlocks(chainPem))
            {
                var c = AttestCerts.FromPem(b);
                if (!AttestDer.DerValidAt(c.Raw, nowMs, 0)) return (null, "issuer chain certificate outside its validity period");
                if (rootRevoked.Contains(c.SerialHex)) return (null, "issuer chain certificate is revoked by the Intel Root CA CRL");
            }
            return (AttestCerts.KeyOf(chain.Leaf), "");
        }
        catch (AttestError e) { return (null, "collateral verification error (fail closed): " + e.Message); }
    }

    /// <summary>Verifies the quote and then its PCS collateral at nowMs: the evaluated TCB status and the policy decision.</summary>
    internal static CollateralResult Verify(byte[] quote, IntelCollateral? c, long nowMs, CollateralPolicy? pol, string pin, bool allowDebug)
    {
        static CollateralResult Fail(string r) => new() { Reason = r };
        if (c == null || c.TcbInfoJson.Length == 0 || c.QeIdentityJson.Length == 0 || c.PckCrl.Length == 0 || c.RootCrl.Length == 0 || c.TcbInfoChain.Length == 0 || c.QeIdentityChain.Length == 0)
            return Fail("collateral incomplete (fail closed)");
        var bas = AttestIntel.VerifyGenuineTdxQuote(quote, pin, nowMs, null, allowDebug);
        if (!bas.Ok || bas.Pck == null || bas.Fmspc.Length == 0) return Fail("quote invalid: " + bas.Reason);
        try
        {
            var q = AttestIntel.ParseQuote(quote);
            var quoteCerts = AttestCerts.PemBlocks(q.PckChainPem).Select(AttestCerts.FromPem).ToList();
            foreach (var x in quoteCerts) if (!AttestDer.DerValidAt(x.Raw, nowMs, 0)) return Fail("PCK chain certificate outside its validity period");
            AttCert? leaf = null, ca = null, root = null;
            foreach (var x in quoteCerts)
            {
                bool issues = quoteCerts.Any(y => y.RawIssuer.AsSpan().SequenceEqual(x.RawSubject));
                if (!issues) { leaf = x; break; }
            }
            if (leaf == null) return Fail("PCK leaf not found");
            foreach (var x in quoteCerts) if (x.RawSubject.AsSpan().SequenceEqual(leaf.RawIssuer)) { ca = x; break; }
            if (ca == null) return Fail("PCK CA not found in the quote chain");
            foreach (var x in quoteCerts) if (x.SelfIssued) { root = x; break; }
            if (root == null) return Fail("Intel root not found in the quote chain");
            var rootKey = AttestCerts.KeyOf(root);
            var caKey = AttestCerts.KeyOf(ca);
            var (rootRevoked, why) = VerifyCrl(c.RootCrl, rootKey, nowMs);
            if (why.Length > 0) return Fail("Intel Root CA CRL: " + why);
            var (pckRevoked, why2) = VerifyCrl(c.PckCrl, caKey, nowMs);
            if (why2.Length > 0) return Fail("PCK CRL: " + why2);
            if (rootRevoked!.Contains(ca.SerialHex)) return Fail("PCK CA certificate is revoked by the Intel Root CA CRL");
            if (pckRevoked!.Contains(leaf.SerialHex)) return Fail("PCK leaf certificate is revoked by the PCK CRL");

            var (tcbKey, why3) = SignerKeyFromChain(c.TcbInfoChain, pin, nowMs, rootRevoked);
            if (why3.Length > 0) return Fail("TCB info: " + why3);
            var (info, why4) = VerifySignedJson(c.TcbInfoJson, "tcbInfo", tcbKey!);
            if (why4.Length > 0) return Fail("TCB info: " + why4);
            var stale = CheckFresh(info!, "TCB info", nowMs);
            if (stale.Length > 0) return Fail(stale);
            if (info!.GetValueOrDefault("id") is not "TDX") return Fail("TCB info is not a TDX v3 document");
            if (AttestUtil.AsFinite(info.GetValueOrDefault("version")) is not double v || v != 3) return Fail("TCB info is not a TDX v3 document");
            if (info.GetValueOrDefault("fmspc") is not string fm || fm.ToLowerInvariant() != bas.Fmspc) return Fail("TCB info FMSPC does not match the quote PCK");

            var (qeKey, why5) = SignerKeyFromChain(c.QeIdentityChain, pin, nowMs, rootRevoked);
            if (why5.Length > 0) return Fail("QE identity: " + why5);
            var (qeBody, why6) = VerifySignedJson(c.QeIdentityJson, "enclaveIdentity", qeKey!);
            if (why6.Length > 0) return Fail("QE identity: " + why6);
            var stale2 = CheckFresh(qeBody!, "QE identity", nowMs);
            if (stale2.Length > 0) return Fail(stale2);

            double infoNum = AttestUtil.AsFinite(info.GetValueOrDefault("tcbEvaluationDataNumber")) ?? -1;
            double qeNum = AttestUtil.AsFinite(qeBody!.GetValueOrDefault("tcbEvaluationDataNumber")) ?? -1;
            if (infoNum < 0 || qeNum < 0) return Fail("tcbEvaluationDataNumber missing");
            if (pol != null && pol.HasMinEval && (infoNum < pol.MinEval || qeNum < pol.MinEval)) return Fail("tcbEvaluationDataNumber below policy minimum");

            var body = q.TdReportBody;
            var tcb = EvaluateTcb(info, bas.Pck.Sgx, bas.Pck.Pcesvn, body[0..16], body[64..112], body[112..120]);
            if (tcb.Err.Length > 0) return Fail("TCB evaluation: " + tcb.Err);
            var qe = EvaluateQe(qeBody, q.QeReportBody);
            if (qe.Err.Length > 0) return Fail("QE identity: " + qe.Err);
            var status = WorstStatus(WorstStatus(tcb.Platform, tcb.Module), qe.Status);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var ids = new List<string>();
            foreach (var a in tcb.Advisories!.Concat(qe.Advisories!)) if (seen.Add(a)) ids.Add(a);
            ids.Sort(StringComparer.Ordinal);
            var res = new CollateralResult { Status = status, AdvisoryIds = ids };
            var accepted = pol != null && pol.HasAccept ? pol.AcceptStatuses : DefaultAccepted.ToList();
            if (!accepted.Contains(status)) { res.Reason = $"TCB status {status} is not accepted by policy"; return res; }
            res.Ok = true;
            return res;
        }
        catch (AttestError e) { return Fail("collateral verification error (fail closed): " + e.Message); }
    }
}
