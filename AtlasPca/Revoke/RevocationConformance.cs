// Conformance cases for a revocation store (packages/pca-revoke conformance.ts). Run them against your own store:
//
//   foreach (var c in RevocationConformance.RevocationStoreCases(() => new MyStore())) await c.Run();
//
// Each case throws when the store breaks the contract. A store that passes keeps (kind, value) keys apart, replaces rather than duplicates, hands out snapshots, and loses
// nothing under interleaved writes. Durability across a restart is checked with a reopen function.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Revoke;

/// <summary>One conformance case: a name and an async body that throws when the store breaks the contract.</summary>
public sealed record RevocationStoreCase(string Name, Func<Task> Run);

public static class RevocationConformance
{
    static D Entry(string kind, string value, D? extra = null)
    {
        var e = new D { ["kind"] = kind, ["value"] = value, ["reason"] = $"r-{kind}-{value}", ["revokedAt"] = 1000L };
        if (kind == "prefix") e["prefix"] = value.Split(',').Cast<object?>().ToList();
        if (extra != null) foreach (var (k, v) in extra) e[k] = v;
        return e;
    }

    static string C(object? v) => Pca.Canonicalize(v is IEnumerable<D> ds ? ds.Cast<object?>().ToList() : v); // a typed list of entries prints as the JSON array it is

    static List<D> Sorted(IEnumerable<D> xs) => xs.OrderBy(e => (string)e["kind"]! + (string)e["value"]!, StringComparer.Ordinal).ToList();

    static void Check(bool ok, string what)
    {
        if (!ok) throw new InvalidOperationException(what);
    }

    static void Same(object? expected, object? actual)
    {
        if (C(expected) != C(actual)) throw new InvalidOperationException($"expected {C(expected)}, got {C(actual)}");
    }

    /// <summary>The store contract as cases. <paramref name="make"/> returns a fresh, empty store each call; <paramref name="reopen"/>, for a store that persists, returns a NEW
    /// store over the same backing location as the previous one (omit it to skip the durability case).</summary>
    public static IReadOnlyList<RevocationStoreCase> RevocationStoreCases(Func<IRevocationStore> make, Func<IRevocationStore, IRevocationStore>? reopen = null)
    {
        var cases = new List<RevocationStoreCase>
        {
            new("starts empty", async () =>
            {
                Check((await make().All()).Count == 0, "a fresh store was not empty");
                Check(await make().Get("cap", "x") == null, "a fresh store returned an entry");
            }),
            new("add then get returns the whole entry, including notBefore", async () =>
            {
                var s = make();
                var e = Entry("cap", "c1", new D { ["notBefore"] = 5000L });
                await s.Add(e);
                Same(e, await s.Get("cap", "c1"));
            }),
            new("the same value under different kinds is kept apart", async () =>
            {
                var s = make();
                await s.Add(Entry("cap", "k"));
                await s.Add(Entry("holder", "k"));
                await s.Add(Entry("issuer", "k"));
                Check((await s.All()).Count == 3, "the same value under three kinds did not give three entries");
                Check(await s.Remove("holder", "k"), "the holder entry was not removed");
                Check((await s.Get("cap", "k"))?["kind"] as string == "cap", "removing the holder entry hid the cap entry");
                Check((await s.Get("issuer", "k"))?["kind"] as string == "issuer", "removing the holder entry hid the issuer entry");
                Check(await s.Get("holder", "k") == null, "the removed holder entry was still returned");
            }),
            new("add at an existing key replaces, it does not duplicate", async () =>
            {
                var s = make();
                await s.Add(Entry("cap", "c", new D { ["reason"] = "first" }));
                await s.Add(Entry("cap", "c", new D { ["reason"] = "second" }));
                Check((await s.All()).Count == 1, "a second add at one key duplicated the entry");
                Check((await s.Get("cap", "c"))?["reason"] as string == "second", "the second add did not replace the first");
            }),
            new("remove reports whether something was removed, and only once", async () =>
            {
                var s = make();
                await s.Add(Entry("cap", "c"));
                Check(await s.Remove("cap", "c"), "the first remove reported nothing removed");
                Check(!await s.Remove("cap", "c"), "the second remove reported a removal");
                Check(!await s.Remove("cap", "never-added"), "removing an unknown key reported a removal");
            }),
            new("prefix paths that differ stay distinct", async () =>
            {
                var s = make();
                await s.Add(Entry("prefix", "a,b"));
                await s.Add(Entry("prefix", "a"));
                await s.Add(Entry("prefix", "b,a"));
                Check((await s.All()).Count == 3, "prefix entries with different paths were merged");
                Check(await s.Remove("prefix", "a"), "the prefix entry was not removed");
                Same(new L { "a,b", "b,a" }, Sorted(await s.All()).Select(e => e["value"]).ToList());
            }),
            new("all() is a snapshot: changing it does not change the store", async () =>
            {
                var s = make();
                await s.Add(Entry("cap", "c"));
                var snap = (await s.All()).ToList();
                snap.RemoveAt(snap.Count - 1);
                snap.Add(Entry("cap", "forged"));
                Check((await s.All()).Count == 1, "changing the snapshot changed the store");
                Check(await s.Get("cap", "forged") == null, "an entry added to the snapshot reached the store");
            }),
            new("clear drops everything", async () =>
            {
                var s = make();
                await s.Add(Entry("cap", "c"));
                await s.Add(Entry("prefix", "a,b"));
                await s.Clear();
                Check((await s.All()).Count == 0, "clear left entries behind");
                Check(await s.Get("cap", "c") == null, "clear left an entry readable");
            }),
            new("interleaved adds and removes from many tasks lose nothing", async () =>
            {
                var s = make();
                const int pairs = 100;
                await Task.WhenAll(Enumerable.Range(0, pairs).Select(p => Task.Run(async () =>
                {
                    await s.Add(Entry("cap", $"c{2 * p}"));
                    await s.Add(Entry("cap", $"c{2 * p + 1}"));
                    await s.Remove("cap", $"c{2 * p}");
                })));
                var left = new HashSet<string>((await s.All()).Select(e => (string)e["value"]!), StringComparer.Ordinal);
                Check(left.Count == pairs, $"{left.Count} entries were left (want {pairs})");
                for (var i = 0; i < 2 * pairs; i++) Check(left.Contains($"c{i}") == (i % 2 == 1), $"c{i} was {(left.Contains($"c{i}") ? "kept" : "lost")} wrongly");
            }),
        };
        if (reopen != null)
            cases.Add(new("entries survive reopening the store", async () =>
            {
                var s = make();
                var a = Entry("cap", "durable", new D { ["notBefore"] = 9000L });
                var b = Entry("prefix", "r,m");
                await s.Add(a);
                await s.Add(b);
                await s.Add(Entry("holder", "gone"));
                await s.Remove("holder", "gone");
                var again = reopen(s);
                Same(Sorted(new[] { a, b }), Sorted(await again.All()));
            }));
        return cases;
    }
}
