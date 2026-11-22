// LIST-AUTHORIZED: "which objects of this type may this agent touch?". Authority = capability AND relationship: the capability decides,
// a relation source can only narrow. Every page is charged to a read accumulator (scanned AND returned objects), pages are bound by a
// signed cursor, and the result carries a signed receipt (packages/pca-grants list-authorized.ts). Verification is K3.
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Grants;

/// <summary>One page of candidate object ids and the cursor of the next page (null or empty: no more).</summary>
public sealed record CandidatePage(IReadOnlyList<string> Objects, string? Next = null);

/// <summary>Candidates for one resource type: a page of at most <c>limit</c> objects after <c>cursor</c>.</summary>
public delegate CandidatePage CandidateSource(string type, string? cursor, int limit);

/// <summary>A relationship source (OpenFGA, SpiceDB, your own tuples). <c>Check</c> only ever narrows; <c>ListObjects</c> is optional.</summary>
public sealed class RelationSource
{
    public required Func<string, string, string, bool> Check { get; init; }
    /// <summary>(subject, relation, type, cursor, limit).</summary>
    public Func<string, string, string, string?, int, CandidatePage>? ListObjects { get; init; }
}

/// <summary>Charges reads against a budget keyed by (subject, type). False when the charge would exceed the cap.</summary>
public interface IReadAccumulator { bool Charge(string key, long units, long now); }

/// <summary>Reference accumulator: <c>cap</c> units per <c>windowMs</c> fixed window per key.</summary>
public sealed class WindowReadAccumulator : IReadAccumulator
{
    readonly long cap, windowMs;
    readonly Dictionary<string, (long Start, long N)> used = new(StringComparer.Ordinal);
    public WindowReadAccumulator(long cap, long windowMs) { this.cap = cap; this.windowMs = windowMs; }

    public bool Charge(string key, long units, long now)
    {
        var cur = used.TryGetValue(key, out var e) && !(now - e.Start >= windowMs) ? e : (Start: now, N: 0L);
        if (cur.N + units > cap) return false;
        used[key] = (cur.Start, cur.N + units);
        return true;
    }
}

/// <summary>Refusal of a list request; <c>Code</c> is read_budget_exhausted, bad_cursor or bad_limit.</summary>
public sealed class ListError : CodedException { public ListError(string code, string message) : base(code, message) { } }

public sealed class ListAuthorizedArgs
{
    public required string Subject { get; init; }
    public required string ResourceType { get; init; }
    /// <summary>The capability: true iff the grant permits the object. The relationship never widens it.</summary>
    public required Func<string, bool> Permits { get; init; }
    public required CandidateSource Candidates { get; init; }
    public (RelationSource Source, string Relation)? Relation { get; init; }
    public required string FilterId { get; init; }
    public required string PolicyDigest { get; init; }
    public required string FreshAtDigest { get; init; }
    public string? Cursor { get; init; }
    public required long Limit { get; init; }
    public required IReadAccumulator Reads { get; init; }
    public required long Now { get; init; }
    public required EdKey SigningKey { get; init; }
    /// <summary>Max candidates scanned per call (default 4x limit, at most 1000).</summary>
    public long? MaxScan { get; init; }
}

public static class ListAuthorized
{
    public const int MaxPageLimit = 500;

    /// <summary>Adapt a relation source's list-objects into a candidate source for one subject and relation.</summary>
    public static CandidateSource CandidatesFromRelation(RelationSource rel, string subject, string relation)
    {
        var list = rel.ListObjects ?? throw new InvalidOperationException("candidatesFromRelation: the relation source has no listObjects");
        return (type, cursor, limit) => list(subject, relation, type, cursor, limit);
    }

    static JD BindInputs(ListAuthorizedArgs a)
    {
        var b = new JD { ["subject"] = a.Subject, ["resourceType"] = a.ResourceType, ["filterId"] = a.FilterId, ["policyDigest"] = a.PolicyDigest };
        if (a.Relation is { } r) b["relation"] = new JD { ["relation"] = r.Relation };
        b["limit"] = G.N(a.Limit);
        return b;
    }

    static string EncCursor(string? inner, long skip, string bind, string signer, EdKey key)
    {
        var c = new JD { ["v"] = new Num("1") };
        if (inner != null) c["inner"] = inner;
        c["skip"] = G.N(skip);
        c["bind"] = bind;
        c["signer"] = signer;
        // JSON.stringify of the same object: members in insertion order
        var json = "{\"v\":1" + (inner != null ? ",\"inner\":" + G.JsonStr(inner) : "") + ",\"skip\":" + skip + ",\"bind\":" + G.JsonStr(bind) + ",\"signer\":" + G.JsonStr(signer) + "}";
        return Pca.B64u(Encoding.UTF8.GetBytes(json)) + "." + Sig.SignBody(K3.ListCursorDomain, c, key);
    }

    /// <summary>One page of the authorized objects of a type: <c>{objects, next_cursor?, receipt}</c>. Throws <see cref="ListError"/>.</summary>
    public static JD Run(ListAuthorizedArgs a)
    {
        if (a.Limit < 1 || a.Limit > MaxPageLimit) throw new ListError("bad_limit", $"limit must be 1..{MaxPageLimit}");
        var limit = (int)a.Limit;
        var signer = a.SigningKey.Id;
        var bindInputs = BindInputs(a);
        var bind = K3.ListBind(bindInputs) ?? throw new InvalidOperationException("listBind: not canonical");
        string? inner = null;
        long skipIn = 0;
        if (a.Cursor != null)
        {
            var c = K3.VerifyListCursor(a.Cursor, signer, bindInputs);
            if (!c.Ok) throw new ListError("bad_cursor", c.Reason == "bind" ? "subject, type, filter, policy or limit changed between pages" : "the page cursor is malformed, forged or from another signer");
            inner = c.Inner;
            skipIn = c.Skip;
        }
        var maxScan = Math.Min(a.MaxScan ?? a.Limit * 4, 1000);
        var key = Pca.HashCanonical(new JD { ["s"] = a.Subject, ["t"] = a.ResourceType });
        var outp = new List<string>();
        long scanned = 0;
        var pageStart = inner;
        var skip = skipIn;
        (string? Inner, long Skip)? resume = null;
        for (; ; )
        {
            var pg = a.Candidates(a.ResourceType, pageStart, limit);
            var objs = pg.Objects.Take(limit).ToList();
            if (!a.Reads.Charge(key, Math.Max(objs.Count - skip, 1), a.Now)) throw new ListError("read_budget_exhausted", "the read budget for this subject and type is exhausted");
            long i = skip;
            for (; i < objs.Count && outp.Count < limit; i++)
            {
                scanned++;
                var o = objs[(int)i];
                if (!a.Permits(o)) continue;
                if (a.Relation is { } rel && !rel.Source.Check(a.Subject, rel.Relation, o)) continue;
                outp.Add(o);
            }
            if (i < objs.Count) { resume = (pageStart, i); break; }
            if (string.IsNullOrEmpty(pg.Next) || objs.Count == 0) break;
            pageStart = pg.Next;
            skip = 0;
            if (outp.Count >= limit || scanned >= maxScan) { resume = (pg.Next, 0); break; }
        }
        var receipt = new JD
        {
            ["v"] = new Num("1"), ["subject"] = a.Subject, ["resource_type"] = a.ResourceType, ["policy_digest"] = a.PolicyDigest, ["fresh_at"] = a.FreshAtDigest,
            ["filter_digest"] = a.FilterId, ["count"] = G.N(outp.Count), ["objects_digest"] = K3.ObjectsDigest(outp) ?? throw new InvalidOperationException("objectsDigest"),
            ["issued_at"] = G.N(a.Now), ["signer"] = signer,
        };
        var result = new JD { ["objects"] = outp.Cast<object?>().ToList() };
        if (resume is { } r2) result["next_cursor"] = EncCursor(r2.Inner, r2.Skip, bind, signer, a.SigningKey);
        var signed = new JD(receipt);
        signed["sig"] = Sig.SignBody(K3.ListReceiptDomain, receipt, a.SigningKey);
        result["receipt"] = signed;
        return result;
    }
}
