// The in-core post-quantum quorum certificate (pq-threshold.ts): a set of n registered post-quantum signers (suite, optional Ed25519 key, PQ key), a
// threshold t and a diversity commitment k (minimum hash-based signers), proofs of >= t independent per-signer signatures over a domain-separated message,
// and rotation chains between sets. Values are the JSON tree (a reference throw is an exception; an absent member is "undefined").
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class PqQuorum
{
    public const int MaxSigners = 256, MaxChain = 1024;
    const string SetDomain = "atlas-pca/pq-quorum-set/v1", MsgDomain = "atlas-pca/pq-quorum-msg/v1\0", RotationKind = "pq-quorum-rotation";
    const int EdPkBytes = 32;

    /// <summary>One registered post-quantum suite: whether it carries an Ed25519 half, its primitive and the member of a key bag that holds its PQ key.</summary>
    sealed record QSuite(bool Hybrid, Pq.Prim Prim, string KeyMember)
    {
        public bool HashBased => Prim is Pq.Prim.Slh128f or Pq.Prim.Slh256s;
        public int PkBytes => Pq.Lens(Prim).Pk;
        public int SigBytes => Hybrid ? Pq.Ed25519SignatureBytes : Pq.Lens(Prim).Sig;
        public int PqSigBytes => Hybrid ? Pq.Lens(Prim).Sig : 0;
    }

    // the closed registry of the reference (SIG_SUITES) without ed25519: the LESS suites read their key from slhDsa256sPub, as the reference does
    static readonly Dictionary<string, QSuite> Suites = new(StringComparer.Ordinal)
    {
        ["ml-dsa-65"] = new(false, Pq.Prim.MlDsa65, "mlDsaPub"),
        ["hybrid-ed25519-ml-dsa-65"] = new(true, Pq.Prim.MlDsa65, "mlDsaPub"),
        ["hybrid-nested-ed25519-ml-dsa-65"] = new(true, Pq.Prim.MlDsa65, "mlDsaPub"),
        ["slh-dsa-sha2-128f"] = new(false, Pq.Prim.Slh128f, "slhDsaPub"),
        ["hybrid-ed25519-slh-dsa-sha2-128f"] = new(true, Pq.Prim.Slh128f, "slhDsaPub"),
        ["ml-dsa-87"] = new(false, Pq.Prim.MlDsa87, "mlDsa87Pub"),
        ["hybrid-ed25519-ml-dsa-87"] = new(true, Pq.Prim.MlDsa87, "mlDsa87Pub"),
        ["slh-dsa-sha2-256s"] = new(false, Pq.Prim.Slh256s, "slhDsa256sPub"),
        ["hybrid-ed25519-slh-dsa-sha2-256s"] = new(true, Pq.Prim.Slh256s, "slhDsa256sPub"),
        ["fn-dsa-512"] = new(false, Pq.Prim.FnDsa512, "fnDsa512Pub"),
        ["fn-dsa-1024"] = new(false, Pq.Prim.FnDsa1024, "fnDsa1024Pub"),
        ["less-cat1"] = new(false, Pq.Prim.Less, "slhDsa256sPub"),
        ["hybrid-ed25519-less-cat1"] = new(true, Pq.Prim.Less, "slhDsa256sPub"),
    };

    sealed record Entry(string Alg, string? Ed, string Pq)
    {
        public string Key => $"{Alg}|{Ed ?? ""}|{Pq}";
        public QSuite Suite => Suites[Alg];
    }

    /// <summary>A loaded set. <c>T</c> and <c>K</c> keep the numbers as given (a -0 is refused by the canonical form when the id is derived).</summary>
    sealed record QSet(object T, object K, List<Entry> Signers, string Id);

    // ---- JavaScript value helpers

    static readonly object Undef = new();
    static bool Has(object? v) => !ReferenceEquals(v, Undef);

    static object? Prop(object? o, string k)
    {
        if (o == null || !Has(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static object? PropOpt(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;

    static object? At(object? c, object? key)
    {
        if (c == null || !Has(c)) throw new InvalidOperationException("Cannot read properties of " + (c == null ? "null" : "undefined"));
        var k = !Has(key) ? "undefined" : JsJson.ToJsString(key);
        if (c is L l) return uint.TryParse(k, out var i) && i.ToString() == k && i < l.Count ? l[(int)i] : Undef;
        return c is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static bool IsSafeInt(object? x) => IntentJs.IsSafeInteger(x);
    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;
    static object Int(long v) => IntentJs.OfLong(v);

    static byte[] Sha384(byte[] b) => SHA384.HashData(b);

    static D Bad(string reason, object? detail = null)
    {
        var d = new D { ["ok"] = false, ["reason"] = reason };
        if (detail != null) d["detail"] = detail;
        return d;
    }

    static D BadSet() => new() { ["ok"] = false, ["reason"] = "bad-set" };

    // ---- sets

    static Entry? Normalize(object? alg, bool edPresent, object? ed, object? pq)
    {
        if (alg is not string a || !Suites.TryGetValue(a, out var s)) return null;
        if (Pca.B64uDecode(pq, s.PkBytes) == null) return null;
        if (s.Hybrid)
        {
            if (Pca.B64uDecode(ed, EdPkBytes) == null) return null;
            return new Entry(a, (string)ed!, (string)pq!);
        }
        return edPresent ? null : new Entry(a, null, (string)pq!);
    }

    static string ComputeId(object t, object k, List<Entry> signers) => Pca.B64u(Sha384(Pca.Canon(new D
    {
        ["d"] = SetDomain, ["t"] = t, ["k"] = k,
        ["s"] = signers.Select(e => (object?)new D { ["a"] = e.Alg, ["e"] = e.Ed, ["p"] = e.Pq }).ToList(),
    })));

    static QSet? Finalize(List<Entry> entries, object? t, object? k)
    {
        int n = entries.Count;
        if (n < 1 || n > MaxSigners) return null;
        if (!IsSafeInt(t) || Dv(t) < 1 || Dv(t) > n) return null;
        if (!IsSafeInt(k) || Dv(k) < 0 || Dv(k) > Dv(t)) return null;
        var sorted = entries.OrderBy(e => e.Key, StringComparer.Ordinal).ToList();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in sorted)
            foreach (var c in e.Ed == null ? new[] { e.Pq } : new[] { e.Ed, e.Pq })
                if (!seen.Add(c)) return null;
        if (sorted.Count(e => e.Suite.HashBased) < Dv(k)) return null;
        return new QSet(t!, k!, sorted, ComputeId(t!, k!, sorted));
    }

    static D SetJson(QSet s) => new()
    {
        ["t"] = s.T, ["minHashBased"] = s.K,
        ["signers"] = s.Signers.Select(e =>
        {
            var d = new D { ["alg"] = e.Alg };
            if (e.Ed != null) d["ed"] = e.Ed;
            d["pq"] = e.Pq;
            return (object?)d;
        }).ToList(),
        ["id"] = s.Id,
    };

    static D Ok(QSet? s) => s == null ? BadSet() : new D { ["ok"] = true, ["set"] = SetJson(s) };

    /// <summary>A set from the public keys of its signers: <c>signers</c> is a list of <c>{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?,
    /// fnDsa1024Pub?}}</c>, <c>t</c> the threshold and <c>minHashBased</c> the diversity commitment (absent: 0). <c>{ok, set}</c> or <c>{ok: false, reason: "bad-set"}</c>.</summary>
    public static D BuildQuorumSet(object? signers, object? t, object? minHashBased = null, bool minGiven = false) => Ok(BuildSet(signers, t, minGiven ? minHashBased : Int(0)));

    static QSet? BuildSet(object? signers, object? t, object? k)
    {
        try
        {
            if (signers is not L list) return null;
            var entries = new List<Entry>();
            foreach (var s in list)
            {
                if (s is not D sd || sd.GetValueOrDefault("keys") is not D keys) return null;
                if (sd.GetValueOrDefault("alg") is not string alg || !Suites.TryGetValue(alg, out var suite)) return null;
                var e = Normalize(alg, keys.ContainsKey("edPub"), keys.GetValueOrDefault("edPub"), keys.GetValueOrDefault(suite.KeyMember));
                if (e == null) return null;
                entries.Add(e);
            }
            return Finalize(entries, t, k);
        }
        catch (Exception) { return null; }
    }

    static QSet? Load(object? x)
    {
        try
        {
            if (x is not D xd || xd.GetValueOrDefault("signers") is not L signers || xd.GetValueOrDefault("id") is not string id) return null;
            var entries = new List<Entry>();
            foreach (var s in signers)
            {
                if (s is not D sd) return null;
                var e = Normalize(sd.GetValueOrDefault("alg"), sd.ContainsKey("ed"), sd.GetValueOrDefault("ed"), sd.GetValueOrDefault("pq"));
                if (e == null) return null;
                entries.Add(e);
            }
            var r = Finalize(entries, xd.GetValueOrDefault("t"), xd.GetValueOrDefault("minHashBased"));
            if (r == null) return null;
            for (int i = 0; i < r.Signers.Count; i++) if (r.Signers[i].Key != entries[i].Key) return null;
            return r.Id == id ? r : null;
        }
        catch (Exception) { return null; }
    }

    /// <summary>A set from its wire form: the id is re-derived and must match, and the wire order must already be canonical. <c>{ok, set}</c> or <c>{ok: false, reason: "bad-set"}</c>.</summary>
    public static D LoadQuorumSet(object? x) => Ok(Load(x));

    public static D Constants() => new() { ["PQ_QUORUM_MAX_SIGNERS"] = Int(MaxSigners), ["PQ_QUORUM_MAX_CHAIN"] = Int(MaxChain) };

    // ---- the signed message

    /// <summary>The bytes every signer signs: <c>"atlas-pca/pq-quorum-msg/v1\0" || SHA-384(canonical({set_id, epoch, action}))</c>. The arguments are not validated (any JSON
    /// value); only a value the strict canonical form refuses throws.</summary>
    public static byte[] QuorumMessage(object? setId, object? epoch, object? actionDigest) =>
        [.. Encoding.UTF8.GetBytes(MsgDomain), .. Sha384(Pca.Canon(new D { ["set_id"] = setId, ["epoch"] = epoch, ["action"] = actionDigest }))];

    /// <summary>The digest of an approval message: base64url(SHA-384(message)).</summary>
    public static string QuorumActionDigest(byte[] message) => Pca.B64u(Sha384(message));

    /// <summary>One signer's share: <c>{i, sig, pq_sig?}</c>. <paramref name="set"/> is a set object (not re-validated). Throws on an index outside the set, missing key material
    /// or a value the canonical form refuses.</summary>
    public static D SignQuorumShare(object? set, object? index, object? epoch, object? actionDigest, SuiteSecretKeys keys)
    {
        var e = At(Prop(set, "signers"), index);
        if (!Has(e) || e == null) throw new ArgumentOutOfRangeException(nameof(index), "signQuorumShare: no such signer index");
        var msg = QuorumMessage(Prop(set, "id"), epoch, actionDigest);
        var p = PqSuites.SignWithSuite(Prop(e, "alg"), keys, msg);
        var share = new D { ["i"] = index, ["sig"] = p.Sig };
        if (p.PqSig != null) share["pq_sig"] = p.PqSig;
        return share;
    }

    static L Spread(object? xs) => xs switch
    {
        L l => new L(l),
        string s => EnumerateRunes(s),
        _ => throw new InvalidOperationException("shares is not iterable"),
    };

    static L EnumerateRunes(string s) { var l = new L(); foreach (var r in s.EnumerateRunes()) l.Add(r.ToString()); return l; }

    /// <summary>A proof from shares: <c>{set_id, sigs}</c>; the shares are copied untouched.</summary>
    public static D AssembleQuorumProof(object? set, object? shares)
    {
        var id = Prop(set, "id");
        var sigs = Spread(shares);
        var d = new D();
        if (Has(id)) d["set_id"] = id;
        d["sigs"] = sigs;
        return d;
    }

    // ---- verification

    /// <summary>Verify a quorum proof: <c>{ok, signers, count, hashBased}</c> or <c>{ok: false, reason, detail?}</c>. <paramref name="input"/> is <c>{set, proof, epoch,
    /// actionDigest, expectedSetId?, requireHashBased?}</c>; never throws.</summary>
    public static D VerifyQuorum(object? input)
    {
        try
        {
            if (input is not D inp) return Bad("malformed");
            var set = Load(inp.GetValueOrDefault("set"));
            if (set == null) return Bad("bad-set");
            if (inp.TryGetValue("expectedSetId", out var exp) && !(exp is string es && es == set.Id)) return Bad("set-mismatch");
            var epoch = inp.GetValueOrDefault("epoch");
            if (!IntentJs.IsNonNeg(epoch) || inp.GetValueOrDefault("actionDigest") is not string digest) return Bad("malformed");
            if (inp.GetValueOrDefault("proof") is not D p || p.GetValueOrDefault("set_id") is not string psid || p.GetValueOrDefault("sigs") is not L sigs) return Bad("malformed");
            if (psid != set.Id) return Bad("set-mismatch");
            if (sigs.Count > set.Signers.Count) return Bad("too-many-signatures");
            var msg = QuorumMessage(set.Id, epoch, digest);
            var seen = new SortedSet<int>();
            int hashBased = 0;
            foreach (var raw in sigs)
            {
                if (raw is not D r || r.GetValueOrDefault("sig") is not string sig) return Bad("malformed");
                var iv = r.GetValueOrDefault("i");
                if (!IntentJs.IsNonNeg(iv) || Dv(iv) >= set.Signers.Count) return Bad("unknown-signer");
                int i = (int)Dv(iv);
                if (seen.Contains(i)) return Bad("duplicate-signer", Int(i));
                seen.Add(i);
                var e = set.Signers[i];
                var hasPqSig = r.ContainsKey("pq_sig");
                if (e.Suite.Hybrid != hasPqSig) return Bad("bad-signature", Int(i));
                if (!PqSuites.VerifyWithSuite(e.Alg, e.Ed, e.Pq, msg, sig, r.GetValueOrDefault("pq_sig"))) return Bad("bad-signature", Int(i));
                if (e.Suite.HashBased) hashBased++;
            }
            if (seen.Count < Dv(set.T)) return Bad("below-threshold");
            var req = inp.GetValueOrDefault("requireHashBased");
            double k = Math.Max(Dv(set.K), req == null ? 0 : JsJson.ToJsNumber(req));
            if (!(Math.Abs(k) <= IntentJs.MaxSafe && k == Math.Floor(k)) || k < 0) return Bad("malformed");
            if (hashBased < k) return Bad("diversity-unmet");
            return new D { ["ok"] = true, ["signers"] = seen.Select(i => Int(i)).Cast<object?>().ToList(), ["count"] = Int(seen.Count), ["hashBased"] = Int(hashBased) };
        }
        catch (Exception) { return Bad("malformed"); }
    }

    /// <summary>True only for a valid quorum proof over <paramref name="message"/> (bytes) at <paramref name="epoch"/>; <paramref name="opts"/> carries <c>expectedSetId</c> and
    /// <c>requireHashBased</c>. Never throws.</summary>
    public static bool VerifyQuorumApproval(object? set, object? proof, byte[]? message, object? epoch, object? opts)
    {
        try
        {
            if (message == null) return false;
            var input = new D { ["set"] = set, ["proof"] = proof, ["epoch"] = epoch, ["actionDigest"] = QuorumActionDigest(message) };
            foreach (var k in new[] { "expectedSetId", "requireHashBased" }) if (opts is D o && o.TryGetValue(k, out var v)) input[k] = v;
            return VerifyQuorum(input).GetValueOrDefault("ok") is true;
        }
        catch (Exception) { return false; }
    }

    // ---- rotation

    /// <summary>What a rotation certificate's quorum signs: base64url(SHA-384(canonical({kind, to_set_id, to_epoch}))).</summary>
    public static string RotationActionDigest(object? toSetId, object? toEpoch) =>
        Pca.B64u(Sha384(Pca.Canon(new D { ["kind"] = RotationKind, ["to_set_id"] = toSetId, ["to_epoch"] = toEpoch })));

    static object? PlusOne(object? v) => v switch
    {
        string s => s + "1",
        null => Int(1),
        bool b => Int(b ? 2 : 1),
        _ => IntentJs.NumOf(v) is double d ? NumberOut(d + 1) : null,
    };

    static object NumberOut(double d) => double.IsFinite(d) ? Facade.JsNumber(d) : d;

    /// <summary>A rotation certificate <c>{from_set_id, from_epoch, to_set, to_epoch, proof}</c> (<c>to_epoch = from_epoch + 1</c> with JavaScript's <c>+</c>).</summary>
    public static D BuildRotationCert(object? from, object? fromEpoch, object? to, object? shares) => new()
    {
        ["from_set_id"] = Prop(from, "id"), ["from_epoch"] = fromEpoch, ["to_set"] = to, ["to_epoch"] = PlusOne(fromEpoch), ["proof"] = AssembleQuorumProof(from, shares),
    };

    /// <summary>One signer's share of a rotation: a quorum share over <see cref="RotationActionDigest"/> of the successor and <c>fromEpoch + 1</c>.</summary>
    public static D SignRotationShare(object? from, object? index, object? fromEpoch, object? to, SuiteSecretKeys keys) =>
        SignQuorumShare(from, index, fromEpoch, RotationActionDigest(Prop(to, "id"), PlusOne(fromEpoch)), keys);

    /// <summary>Walk a rotation chain from a genesis set and epoch: <c>{ok, set, epoch, length}</c> or <c>{ok: false, reason, at}</c> (at -1 for a failure before the first link).</summary>
    public static D VerifyRotationChain(object? genesisSet, object? genesisEpoch, object? chain)
    {
        static D Fail(string reason, int at) => new() { ["ok"] = false, ["reason"] = reason, ["at"] = IntentJs.OfLong(at) };
        try
        {
            var g = Load(genesisSet);
            if (g == null || !IntentJs.IsNonNeg(genesisEpoch)) return Fail("bad-set", -1);
            if (chain is not L links) return Fail("malformed", -1);
            if (links.Count > MaxChain) return Fail("chain-too-long", -1);
            var cur = g;
            long epoch = IntentJs.Lng(genesisEpoch);
            for (int n = 0; n < links.Count; n++)
            {
                if (links[n] is not D c || c.GetValueOrDefault("from_set_id") is not string fromId || !IntentJs.IsNonNeg(c.GetValueOrDefault("from_epoch")) || !IntentJs.IsNonNeg(c.GetValueOrDefault("to_epoch")))
                    return Fail("malformed", n);
                if (fromId != cur.Id) return Fail("chain-broken", n);
                long toEpoch = IntentJs.Lng(c["to_epoch"]);
                if (IntentJs.Lng(c["from_epoch"]) != epoch) return Fail("non-monotone-epoch", n);
                if (toEpoch != epoch + 1) return Fail("non-monotone-epoch", n);
                var next = Load(c.GetValueOrDefault("to_set"));
                if (next == null) return Fail("bad-rotation", n);
                if (next.Id == cur.Id) return Fail("bad-rotation", n);
                var v = VerifyQuorum(new D
                {
                    ["set"] = SetJson(cur), ["proof"] = c.GetValueOrDefault("proof"), ["epoch"] = Int(epoch), ["actionDigest"] = RotationActionDigest(next.Id, c["to_epoch"]), ["expectedSetId"] = cur.Id,
                });
                if (v["ok"] is not true) return Fail((string)v["reason"]!, n);
                cur = next;
                epoch = toEpoch;
            }
            return new D { ["ok"] = true, ["set"] = SetJson(cur), ["epoch"] = Int(epoch), ["length"] = Int(links.Count) };
        }
        catch (Exception) { return Fail("malformed", -1); }
    }

    static bool StrictEq(object? a, object? b)
    {
        if (!Has(a) || !Has(b)) return !Has(a) && !Has(b);
        if (a == null || b == null) return a == null && b == null;
        if (a is string x) return b is string y && x == y;
        if (a is bool p) return b is bool q && p == q;
        return IntentJs.NumOf(a) is double m && IntentJs.NumOf(b) is double n && m == n;
    }

    /// <summary>Two certificates rotate the same set at the same epoch to different successors (a structural comparison; no signature is looked at).</summary>
    public static bool IsRotationFork(object? a, object? b)
    {
        if (a is not D ad || b is not D bd || ad.GetValueOrDefault("to_set") is not D at || bd.GetValueOrDefault("to_set") is not D bt) return false;
        return StrictEq(PropOpt(a, "from_set_id"), PropOpt(b, "from_set_id")) && StrictEq(PropOpt(a, "from_epoch"), PropOpt(b, "from_epoch"))
            && at.GetValueOrDefault("id") is string ai && bt.GetValueOrDefault("id") is string bi && ai != bi;
    }

    // ---- size

    static long ShareBytes(object? e)
    {
        var alg = Prop(e, "alg");
        if (alg is "ed25519") return Pq.Ed25519SignatureBytes;
        if (alg is not string a || !Suites.TryGetValue(a, out var s)) throw new InvalidOperationException("Cannot read properties of undefined (reading 'sigBytes')");
        return s.SigBytes + s.PqSigBytes;
    }

    /// <summary>The size of a proof in bytes: <c>{minBytes, maxBytes, chosenBytes?, t, compact: false}</c> (the t smallest and the t largest shares; the chosen signer indices when
    /// given, an unknown index counting 0).</summary>
    public static D QuorumProofSize(object? set, object? indices = null, bool indicesGiven = false)
    {
        var signers = Prop(set, "signers") as L ?? throw new InvalidOperationException("set.signers.map is not a function");
        var sizes = signers.Select(ShareBytes).OrderBy(x => x).ToList();
        var tv = Prop(set, "t");
        long Sum(IEnumerable<long> xs) => xs.Sum();
        long min, max;
        if (IntentJs.NumOf(tv) is double t)
        {
            var tt = (long)Math.Truncate(t);
            long n = sizes.Count;
            // slice(0, t) and slice(n - t) with JavaScript's clamping of negative and oversized bounds
            long Clamp(long x) => x < 0 ? Math.Max(0, n + x) : Math.Min(x, n);
            min = Sum(sizes.Skip(0).Take((int)Clamp(tt)));
            var start = Clamp(n - tt);
            max = Sum(sizes.Skip((int)start));
        }
        else { min = Sum(sizes); max = min; }
        var r = new D { ["minBytes"] = Int(min), ["maxBytes"] = Int(max), ["t"] = tv, ["compact"] = false };
        if (indicesGiven)
        {
            if (indices is not L idx) throw new InvalidOperationException("indices.map is not a function");
            r["chosenBytes"] = Int(idx.Sum(i => At(signers, i) is { } s && Has(s) ? ShareBytes(s) : 0));
        }
        return r;
    }
}
