using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A sorted, size-bound revocation set: the ids a mesh domain commits to with <c>rev_root</c> (the issuing side of <see cref="Mesh"/>).</summary>
public sealed class MeshRevocationSet
{
    readonly List<string> _ids = new();

    public MeshRevocationSet() { }

    public MeshRevocationSet(IEnumerable<string> initial) { foreach (var id in initial) Revoke(id); }

    public int Size => _ids.Count;

    int LowerBound(string id)
    {
        int lo = 0, hi = _ids.Count;
        while (lo < hi)
        {
            int mid = (int)((uint)(lo + hi) >> 1);
            if (IntentJs.CompareUtf8(_ids[mid], id) < 0) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    /// <summary>Idempotent. Returns true when newly revoked.</summary>
    public bool Revoke(string id)
    {
        if (id == null) throw new ArgumentException("revoke: id must be a string");
        int lo = LowerBound(id);
        if (lo < _ids.Count && _ids[lo] == id) return false;
        _ids.Insert(lo, id);
        return true;
    }

    public bool Has(string id)
    {
        int lo = LowerBound(id);
        return lo < _ids.Count && _ids[lo] == id;
    }

    /// <summary>Sorted revoked ids (copy).</summary>
    public List<string> List() => new(_ids);

    /// <summary>Proof that <paramref name="id"/> is NOT in the set: {size, lo?, hi?}, the bracketing leaves {id, proof}. Throws when the id IS revoked.</summary>
    public D NonMembershipProof(string id)
    {
        if (Has(id)) throw new InvalidOperationException("nonMembershipProof: id is revoked");
        int n = _ids.Count;
        int lo = LowerBound(id);
        var hs = _ids.Select(x => Pca.LeafHash(x)).ToList();
        var p = new D { ["size"] = IntentJs.OfLong(n) };
        if (lo > 0) p["lo"] = Leaf(hs, lo - 1);
        if (lo < n) p["hi"] = Leaf(hs, lo);
        return p;
    }

    D Leaf(List<byte[]> hs, int i)
    {
        var path = new L();
        MerkleLog.Prove(hs, i, path);
        var proof = new D { ["index"] = IntentJs.OfLong(i), ["size"] = IntentJs.OfLong(hs.Count), ["path"] = path };
        return new D { ["id"] = _ids[i], ["proof"] = proof };
    }

    /// <summary>The size-bound root.</summary>
    public string Root() => IntentRevocation.RevsetRoot(_ids);
}
