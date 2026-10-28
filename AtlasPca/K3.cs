// K3 operational-plane artifacts, VERIFICATION side: signed policy bundles, hash-chained decision logs (signed heads, Merkle inclusion,
// streamed batches), list-authorized receipts and cursors, and grant-management amendments / revocations / need approvals. A port of
// packages/pca-grants/src/{bundle,list-authorized,grant-resource,sig}.ts (the TypeScript is authoritative). Every signature is Ed25519
// (strict) over DOMAIN-PREFIX bytes || strict canonical JSON of the body (the NUL that ends most domains is part of the domain).
// Every function is total: malformed input returns the failure value, never an exception.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Result of <see cref="K3.VerifyBundle"/>: on success Revision / Digest / Signers, else Code and Reason.</summary>
public sealed record BundleVerdict(bool Ok, long Revision, string? Digest, IReadOnlyList<string> Signers, string? Code, string? Reason);
/// <summary>Result of <see cref="K3.VerifyBatch"/>: on success the new cursor, else the reason.</summary>
public sealed record BatchVerdict(bool Ok, long Next, string? LastCommit, string? Reason);
/// <summary>Result of <see cref="K3.VerifyListCursor"/>: on success the inner cursor (may be null) and skip, else Reason (<c>malformed</c>, <c>signature</c> or <c>bind</c>).</summary>
public sealed record CursorVerdict(bool Ok, string? Inner, long Skip, string? Reason);
/// <summary>Result of a grant-management verification: <c>Ok</c> with the facts that apply, else the error <c>Code</c>.</summary>
public sealed record GrantVerdict(bool Ok, string? Code, bool Widens = false, string? Scope = null, Dictionary<string, object?>? Authority = null);

public static class K3
{
    public const string BundleDomain = "atlas-pca/policy-bundle/v1\0";
    public const string BundleRefDomain = "atlas-pca/policy-bundle-ref/v1";
    public const string RecordDomain = "atlas-pca/decision-record/v1";
    public const string LogHeadDomain = "atlas-pca/decision-log-head/v1\0";
    public const string ListReceiptDomain = "atlas-pca/list-receipt/v1\0";
    public const string ListCursorDomain = "atlas-pca/list-cursor/v1\0";
    public const string ObjectsDomain = "atlas-pca/list-objects/v1";
    public const string GrantAmendDomain = "atlas-pca/grant-amend/v1\0";
    public const string GrantRevokeDomain = "atlas-pca/grant-revoke/v1\0";
    public const string NeedApproveDomain = "atlas-pca/need-approve/v1\0";
    const int MaxList = 4096;

    static object? Get(object? o, string k) => IntentJs.Get(o, k);
    static bool Str(object? x, int max = 512) => x is string s && s.Length > 0 && s.Length <= max;
    static bool IsOne(object? x) => x is Num n && n.Raw == "1";
    static double Val(object? n) => double.Parse(((Num)n!).Raw, NumberStyles.Float, CultureInfo.InvariantCulture);
    static string Raw(object? n) => n is Num x ? x.Raw : "undefined";
    static JD Without(JD d, string key) => d.Where(kv => kv.Key != key).ToDictionary(kv => kv.Key, kv => kv.Value);

    // ---------------------------------------------------------------------------------------------------- policy bundles

    static readonly Regex VersionRe = new(@"^[0-9]{1,6}(\.[0-9]{1,6}){0,3}\z", RegexOptions.CultureInvariant);

    /// <summary>The content address of a bundle (the signatures are not part of it); null when it cannot be canonicalized.</summary>
    public static string? BundleDigest(object? bundle)
    {
        try { return bundle is JD b ? Pca.HashCanonical(new JD { ["d"] = BundleRefDomain, ["b"] = Without(b, "sigs") }) : null; }
        catch (Exception) { return null; }
    }

    static double VersionPart(string s) => s.Length == 0 ? 0 : s.All(char.IsAsciiDigit) ? double.Parse(s, CultureInfo.InvariantCulture) : double.NaN;

    /// <summary>Dotted numeric version order: -1, 0 or 1 (a part that is not a number reads as greater, like the reference).</summary>
    public static int CompareVersion(string a, string b)
    {
        var pa = a.Split('.'); var pb = b.Split('.');
        for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            double d = (i < pa.Length ? VersionPart(pa[i]) : 0) - (i < pb.Length ? VersionPart(pb[i]) : 0);
            if (d != 0) return d < 0 ? -1 : 1;
        }
        return 0;
    }

    static bool StrList(object? o) => o is JL l && l.Count <= MaxList && l.All(x => Str(x, 128));

    /// <summary>Null when the bundle is well formed, else the reason.</summary>
    public static string? BundleShapeError(object? bo)
    {
        if (bo is not JD b || !IsOne(Get(b, "v")) || Get(b, "kind") is not "pca-policy-bundle") return "not a policy bundle";
        if (!Pca.SafeNat(Get(b, "revision"), out var rev) || rev < 1 || !Pca.SafeNat(Get(b, "issued_at"), out _)) return "bad revision or time";
        if (rev == 1 ? b.ContainsKey("prev") : !Str(Get(b, "prev"), 128)) return "prev must be absent at revision 1 and present after";
        if (!StrList(Get(b, "grants"))) return "bad grants";
        if (!StrList(Get(b, "template_digests"))) return "bad template_digests";
        foreach (var k in new[] { "schema_digest", "constitution_digest", "flow_rules_digest" })
            if (b.ContainsKey(k) && !Str(b[k], 128)) return "bad " + k;
        if (Get(b, "min_verifier_version") is not string mv || !VersionRe.IsMatch(mv)) return "bad min_verifier_version";
        return null;
    }

    static BundleVerdict BundleFail(string code, string reason) => new(false, 0, null, Array.Empty<string>(), code, reason);

    /// <summary>Verify a k-of-n signed bundle against the pinned <paramref name="signers"/>; <paramref name="last"/> is the newest accepted
    /// (revision, digest): a lower revision is a rollback, the next one must chain by <c>prev</c>.</summary>
    public static BundleVerdict VerifyBundle(object? bo, IReadOnlyCollection<string> signers, long threshold, string verifierVersion, (long Revision, string Digest)? last = null)
    {
        try
        {
            var e = BundleShapeError(bo);
            if (e != null) return BundleFail("malformed", e);
            var bundle = (JD)bo!;
            if (Get(bundle, "sigs") is not JL sigs || sigs.Count > 64 || threshold < 1) return BundleFail("malformed", "bad sigs or threshold");
            var body = Without(bundle, "sigs");
            var good = new List<string>();
            foreach (var s in sigs)
                if (s is JD sd && Get(sd, "signer") is string sg && signers.Contains(sg) && !good.Contains(sg) && Pca.VerifyDomain(BundleDomain, body, sg, Get(sd, "sig"))) good.Add(sg);
            if (good.Count < threshold) return BundleFail("below_threshold", $"{good.Count} valid pinned signature(s), need {threshold}");
            var minV = (string)bundle["min_verifier_version"]!;
            if (!VersionRe.IsMatch(verifierVersion) || CompareVersion(verifierVersion, minV) < 0) return BundleFail("verifier_too_old", $"needs verifier >= {minV}");
            Pca.SafeNat(bundle["revision"], out var rev);
            var digest = BundleDigest(bundle);
            if (digest == null) return BundleFail("malformed", "bad sigs or threshold");
            if (last is { } l)
            {
                if (rev < l.Revision) return BundleFail("rollback", $"revision {rev} < accepted {l.Revision}");
                if (rev == l.Revision && digest != l.Digest) return BundleFail("broken_chain", "same revision, different content");
                if (rev == l.Revision + 1 && Get(bundle, "prev") as string != l.Digest) return BundleFail("broken_chain", "prev does not chain to the accepted revision");
            }
            return new BundleVerdict(true, rev, digest, good, null, null);
        }
        catch (Exception) { return BundleFail("malformed", "bad sigs or threshold"); }
    }

    // ---------------------------------------------------------------------------------------------------- decision records

    /// <summary>The commit of a decision record (what the hash chain and the Merkle log commit to); null when it cannot be canonicalized.</summary>
    public static string? RecordCommit(object? record)
    {
        try { return Pca.HashCanonical(new JD { ["d"] = RecordDomain, ["r"] = record }); }
        catch (Exception) { return null; }
    }

    /// <summary>A signed log head by <paramref name="signer"/> over exactly its content (unknown members are signed too).</summary>
    public static bool VerifyLogHead(object? head, string signer)
    {
        try
        {
            if (head is not JD h || !IsOne(Get(h, "v")) || Get(h, "signer") is not string hs || hs != signer || !Pca.SafeNat(Get(h, "size"), out _)
                || !Pca.SafeNat(Get(h, "issued_at"), out _) || Get(h, "root") is not string || Get(h, "last_commit") is not string) return false;
            return Pca.VerifyDomain(LogHeadDomain, Without(h, "sig"), signer, Get(h, "sig"));
        }
        catch (Exception) { return false; }
    }

    /// <summary>Offline: <paramref name="record"/> is in the log the signed <paramref name="head"/> commits to (the leaf is the canonical
    /// bytes of the commit string), and the head is by the pinned signer.</summary>
    public static bool VerifyRecordInclusion(object? record, object? proof, object? head, string signer)
    {
        try
        {
            if (!VerifyLogHead(head, signer)) return false;
            var commit = RecordCommit(record);
            return commit != null && Pca.VerifyInclusion((string)((JD)head!)["root"]!, proof as JD, commit);
        }
        catch (Exception) { return false; }
    }

    static BatchVerdict BatchFail(string reason) => new(false, 0, null, reason);

    /// <summary>Receiver side of the decision stream: contiguous sequence from the receiver's (<paramref name="next"/>, <paramref name="lastCommit"/>),
    /// an intact hash chain, a head by the pinned signer and, when the batch reaches the head, a matching last commit. Returns the new cursor.</summary>
    public static BatchVerdict VerifyBatch(object? batch, long next, string lastCommit, string signer)
    {
        try
        {
            if (batch is not JD b) return BatchFail("malformed batch");
            var fromRaw = Get(b, "from");
            if (!(Pca.SafeNat(fromRaw, out var f) && f == next)) return BatchFail($"gap or replay: batch starts at {Raw(fromRaw)}, expected {next}");
            var head = Get(b, "head");
            if (!VerifyLogHead(head, signer)) return BatchFail("head not signed by the pinned log signer");
            if (Get(b, "records") is not JL records) return BatchFail("malformed batch");
            var last = lastCommit;
            var n = next;
            foreach (var ro in records)
            {
                if (ro is not JD r) return BatchFail("malformed batch");
                if (!(Pca.SafeNat(Get(r, "seq"), out var seq) && seq == n) || !(Get(r, "prev") is string pv && pv == last)) return BatchFail($"chain broken at seq {Raw(Get(r, "seq"))}");
                var c = RecordCommit(r);
                if (c == null) return BatchFail("malformed batch");
                last = c;
                n++;
            }
            var h = (JD)head!;
            Pca.SafeNat(h["size"], out var size);
            if (n > size) return BatchFail("batch is longer than the signed head");
            if (n == size && last != (string)h["last_commit"]!) return BatchFail("batch end does not match the signed head");
            return new BatchVerdict(true, n, last, null);
        }
        catch (Exception) { return BatchFail("malformed batch"); }
    }

    // ---------------------------------------------------------------------------------------------------- list-authorized

    /// <summary>The digest of the returned object ids, in order.</summary>
    public static string? ObjectsDigest(IReadOnlyList<string> objects)
    {
        try { return Pca.HashCanonical(new JD { ["d"] = ObjectsDomain, ["o"] = objects.Cast<object?>().ToList() }); }
        catch (Exception) { return null; }
    }

    /// <summary>A signed list receipt by <paramref name="signer"/>; with <paramref name="objects"/> the count and objects digest must match too.</summary>
    public static bool VerifyListReceipt(object? receipt, string signer, IReadOnlyList<string>? objects = null)
    {
        try
        {
            if (receipt is not JD r || !IsOne(Get(r, "v")) || Get(r, "signer") is not string rs || rs != signer || !Str(Get(r, "subject")) || !Str(Get(r, "resource_type"))
                || !Pca.SafeNat(Get(r, "count"), out var count) || !Pca.SafeNat(Get(r, "issued_at"), out _)) return false;
            if (!Pca.VerifyDomain(ListReceiptDomain, Without(r, "sig"), signer, Get(r, "sig"))) return false;
            return objects == null || (objects.Count == count && ObjectsDigest(objects) is { } od && od == Get(r, "objects_digest") as string);
        }
        catch (Exception) { return false; }
    }

    /// <summary>What a page cursor is bound to. <paramref name="inputs"/>: <c>{subject, resourceType, filterId, policyDigest, limit, relation?: {relation}}</c>; null when malformed.</summary>
    public static string? ListBind(object? inputs)
    {
        try
        {
            if (inputs is not JD b) return null;
            foreach (var k in new[] { "subject", "resourceType", "filterId", "policyDigest", "limit" }) if (!b.ContainsKey(k)) return null;
            return Pca.HashCanonical(new JD
            {
                ["s"] = b["subject"], ["t"] = b["resourceType"], ["f"] = b["filterId"], ["p"] = b["policyDigest"], ["r"] = Get(Get(b, "relation"), "relation"), ["l"] = b["limit"],
            });
        }
        catch (Exception) { return null; }
    }

    static CursorVerdict CursorFail(string reason) => new(false, null, 0, reason);

    /// <summary>Verify a page cursor: shape, signature by <paramref name="signer"/> and (when <paramref name="bind"/> inputs are given) that it
    /// was issued for exactly those inputs.</summary>
    public static CursorVerdict VerifyListCursor(object? token, string signer, object? bind = null)
    {
        try
        {
            if (token is not string tok) return CursorFail("malformed");
            var parts = tok.Split('.');
            JD? c = null;
            try
            {
                var raw = parts[0].Length > 0 ? Pca.B64uDecode(parts[0]) : null;
                if (raw != null) c = Pca.ParseJson(Encoding.UTF8.GetString(raw)) as JD;
            }
            catch (Exception) { return CursorFail("malformed"); }
            if (parts.Length > 2 || c == null || parts.Length < 2 || parts[1].Length == 0 || !IsOne(Get(c, "v")) || Get(c, "bind") is not string cb
                || !Pca.SafeNat(Get(c, "skip"), out var skip) || (c.ContainsKey("inner") && Get(c, "inner") is not string)) return CursorFail("malformed");
            if (Get(c, "signer") is not string cs || cs != signer || !Pca.VerifyDomain(ListCursorDomain, c, signer, parts[1])) return CursorFail("signature");
            if (bind != null && cb != ListBind(bind)) return CursorFail("bind");
            return new CursorVerdict(true, Get(c, "inner") as string, skip, null);
        }
        catch (Exception) { return CursorFail("malformed"); }
    }

    // ---------------------------------------------------------------------------------------------------- grant management

    static List<string> Strs(JD a, string k) => ((JL)a[k]!).Select(x => (string)x!).ToList();
    static JD? Limits(JD a) => Get(a, "limits") as JD;
    static double Exp(JD a) => a.ContainsKey("expires_at") ? Val(a["expires_at"]) : double.PositiveInfinity;

    /// <summary>A well-formed authority: <c>{verbs[], resources[], limits?: {name: number >= 0}, expires_at?}</c>.</summary>
    public static bool AuthorityOk(object? ao)
    {
        try
        {
            if (ao is not JD a) return false;
            if (Get(a, "verbs") is not JL v || v.Count > 256 || !v.All(x => Str(x, 128))) return false;
            if (Get(a, "resources") is not JL r || r.Count > 1024 || !r.All(x => Str(x, 512))) return false;
            if (a.ContainsKey("limits") && (a["limits"] is not JD l || !l.Values.All(x => x is Num n && Pca.NumberError(n.Raw) == null && Val(n) >= 0))) return false;
            return !a.ContainsKey("expires_at") || Pca.SafeNat(a["expires_at"], out _);
        }
        catch (Exception) { return false; }
    }

    static bool ResCovers(string p, string r) => p.EndsWith('*') ? r.StartsWith(p[..^1], StringComparison.Ordinal) : p == r;
    static bool ResSubset(List<string> small, List<string> big) =>
        small.All(s => big.Any(b => ResCovers(b, s) && (!s.EndsWith('*') || b.EndsWith('*') || b == s)));

    // a <= b: everything a allows, b allows
    static bool Le(JD a, JD b)
    {
        if (!Strs(a, "verbs").All(Strs(b, "verbs").Contains) || !ResSubset(Strs(a, "resources"), Strs(b, "resources"))) return false;
        var al = Limits(a); var bl = Limits(b);
        if (al != null)
            foreach (var (k, v) in al)
                if (bl != null && bl.TryGetValue(k, out var bv) && !(Val(v) <= Val(bv))) return false;
        if (bl != null)
            foreach (var k in bl.Keys)
                if (al == null || !al.ContainsKey(k)) return false;
        return Exp(a) <= Exp(b);
    }

    /// <summary>The order of two authorities: <c>narrower</c>, <c>equal</c>, <c>wider</c> or <c>incomparable</c> (also the answer for malformed input: fail closed).</summary>
    public static string CompareAuthority(JD oldA, JD newA)
    {
        try
        {
            bool nle = Le(newA, oldA), ole = Le(oldA, newA);
            return nle && ole ? "equal" : nle ? "narrower" : ole ? "wider" : "incomparable";
        }
        catch (Exception) { return "incomparable"; }
    }

    static JL Sorted(JD a, string k)
    {
        var l = Strs(a, k);
        l.Sort(StringComparer.Ordinal); // UTF-16 code unit order, like the reference's default sort
        return l.Cast<object?>().ToList();
    }

    /// <summary>The content address of an authority (verb and resource order do not matter); null when malformed.</summary>
    public static string? AuthorityDigest(object? ao)
    {
        try
        {
            if (ao is not JD a) return null;
            var copy = new JD(a) { ["verbs"] = Sorted(a, "verbs"), ["resources"] = Sorted(a, "resources") };
            return Pca.HashCanonical(new JD { ["d"] = "atlas-pca/authority/v1", ["a"] = copy });
        }
        catch (Exception) { return null; }
    }

    static JL Union(JD a, JD b, string k) => Strs(a, k).Concat(Strs(b, k)).Distinct(StringComparer.Ordinal).Cast<object?>().ToList();

    /// <summary>Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept.</summary>
    public static JD MergeAuthority(JD a, JD d)
    {
        var limits = new JD();
        var al = Limits(a); var dl = Limits(d);
        if (al != null)
            foreach (var (k, v) in al) limits[k] = dl != null && dl.TryGetValue(k, out var dv) && Val(dv) > Val(v) ? dv : v;
        var res = new JD { ["verbs"] = Union(a, d, "verbs"), ["resources"] = Union(a, d, "resources") };
        if (limits.Count > 0) res["limits"] = limits;
        if (a.ContainsKey("expires_at")) res["expires_at"] = d.ContainsKey("expires_at") && Val(d["expires_at"]) > Val(a["expires_at"]) ? d["expires_at"] : a["expires_at"];
        return res;
    }

    /// <summary>The body a grant amendment signature covers.</summary>
    public static JD AmendMessage(JD grant, string action, JD authority) =>
        new() { ["grant"] = Get(grant, "id"), ["rev"] = Get(grant, "rev"), ["action"] = action, ["authority"] = AuthorityDigest(authority) };

    /// <summary>The body a grant revocation signature covers.</summary>
    public static JD GrantRevokeMessage(object? id, string scope) => new() { ["grant"] = id, ["scope"] = scope };

    /// <summary>The body a need-approval signature covers.</summary>
    public static JD NeedApproveMessage(JD needRequest, object? rev, object? approved) =>
        new() { ["need"] = Get(needRequest, "id"), ["grant"] = Get(needRequest, "grant_id"), ["rev"] = rev, ["approved"] = approved };

    static GrantVerdict Bad(string code) => new(false, code);

    /// <summary>Decide an amendment against the current grant facts (<c>{id, rev, principal, agent, status, authority}</c>). Check order is
    /// normative: request shape, authority shape, grant active, classification, signature, then step-up for a widening.
    /// <paramref name="stepUpOk"/> is the already-evaluated step-up verdict.</summary>
    public static GrantVerdict VerifyAmendment(JD cur, object? request, bool stepUpOk)
    {
        try
        {
            if (request is not JD r || Get(r, "action") is not string action || action is not ("narrow" or "merge" or "replace")) return Bad("bad_request");
            if (Get(r, "authority") is not JD ra || !AuthorityOk(ra)) return Bad("bad_request");
            if (Get(cur, "status") is not "active") return Bad("not_active");
            if (Get(cur, "authority") is not JD ca) return Bad("bad_request");
            var next = action == "merge" ? MergeAuthority(ca, ra) : ra;
            var order = CompareAuthority(ca, next);
            bool widens = order is "wider" or "incomparable";
            if (!widens && action == "narrow" && order == "equal") return Bad("not_narrower");
            if (widens && action == "narrow") return Bad("not_narrower");
            var by = Get(r, "signed_by") as string;
            var sig = Get(r, "sig");
            if (sig is not string || (by != "holder" && by != "principal")) return Bad("signature_required");
            if (widens && by != "principal") return Bad("signature_required");
            var signer = by == "principal" ? Get(cur, "principal") : Get(cur, "agent");
            if (!Pca.VerifyDomain(GrantAmendDomain, AmendMessage(cur, action, ra), signer, sig)) return Bad("bad_signature");
            if (widens && !stepUpOk) return Bad("step_up_required");
            return new GrantVerdict(true, null, widens, null, next);
        }
        catch (Exception) { return Bad("bad_request"); }
    }

    /// <summary>Decide a revocation's authority: the principal's signature over (grant id, scope). <paramref name="root"/> is <c>{id, principal}</c>.</summary>
    public static GrantVerdict VerifyRevokeSignature(JD root, object? scope, object? sig)
    {
        try
        {
            if (scope is not ("grant" or "agent" or "subtree")) return Bad("bad_request");
            var sc = (string)scope;
            if (!Pca.VerifyDomain(GrantRevokeDomain, GrantRevokeMessage(Get(root, "id"), sc), Get(root, "principal"), sig)) return Bad("bad_signature");
            return new GrantVerdict(true, null, false, sc);
        }
        catch (Exception) { return Bad("bad_request"); }
    }

    static bool SameStr(object? a, object? b) => a is string x && b is string y && x == y;

    /// <summary>Decide a needs approval: principal signature over (need, grant, rev, approved), same count, each approved need names the same verb
    /// and resource with amounts only LOWERED and only when adjustable, then step-up. On success <c>Authority</c> is the merged authority.</summary>
    public static GrantVerdict VerifyNeedApproval(JD needRequest, JD grant, object? approved, object? sig, bool stepUpOk)
    {
        try
        {
            if (Get(needRequest, "status") is not "pending") return Bad("conflict");
            if (!Pca.VerifyDomain(NeedApproveDomain, NeedApproveMessage(needRequest, Get(grant, "rev"), approved), Get(grant, "principal"), sig)) return Bad("bad_signature");
            if (approved is not JL ap || Get(needRequest, "needs") is not JL needs || ap.Count != needs.Count) return Bad("need_not_lowered_only");
            var verbs = new JL(); var resources = new JL(); var limits = new JD();
            for (int i = 0; i < ap.Count; i++)
            {
                if (ap[i] is not JD a || needs[i] is not JD want) return Bad("need_not_lowered_only");
                if (!SameStr(Get(a, "verb"), Get(want, "verb")) || !SameStr(Get(a, "resource"), Get(want, "resource"))) return Bad("need_not_lowered_only");
                if (Get(a, "limits") is JD al)
                    foreach (var (k, v) in al)
                    {
                        var w = Get(Get(want, "limits"), k);
                        if (w == null || Val(v) > Val(w)) return Bad("need_not_lowered_only");
                        if (Val(v) < Val(w) && Get(want, "adjustable") is not true) return Bad("need_not_adjustable");
                    }
                verbs.Add(Get(a, "verb"));
                resources.Add(Get(a, "resource"));
                // a limit the need names but the principal omitted is not granted at all
                if (Get(a, "limits") is JD al2)
                    foreach (var (k, v) in al2) if (!limits.TryGetValue(k, out var cur) || Val(v) > Val(cur)) limits[k] = v;
            }
            var delta = new JD { ["verbs"] = verbs, ["resources"] = resources };
            if (limits.Count > 0) delta["limits"] = limits;
            if (!stepUpOk) return Bad("step_up_required");
            if (Get(grant, "authority") is not JD ga) return Bad("bad_request");
            return new GrantVerdict(true, null, false, null, MergeAuthority(ga, delta));
        }
        catch (Exception) { return Bad("bad_request"); }
    }
}
