// A durable IRevocationStore backed by one JSON file. Every change is written to a temporary file, flushed to disk, then moved over the
// real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two processes must not share one file.
// Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes the constructor throw. Silently
// starting empty would un-revoke everything.
using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Revoke;

public sealed class FileRevocationStore : IRevocationStore
{
    static readonly string[] Kinds = ["cap", "holder", "issuer", "prefix"];
    readonly string _path;
    readonly object _gate = new(); // writers run one at a time: a change is applied, flushed, and only then does the next start
    readonly List<string> _order = new();
    readonly Dictionary<string, D> _mem = new();

    public FileRevocationStore(string path)
    {
        _path = path;
        if (!File.Exists(path)) return;
        const string unreadable = "FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty";
        const string invalid = "FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty";
        object? parsed;
        try { parsed = Pca.ParseJson(File.ReadAllText(path, new System.Text.UTF8Encoding(false, true))); }
        catch (Exception) { throw new InvalidOperationException(unreadable); }
        if (parsed is not D top || !top.TryGetValue("entries", out var list) || list is not L entries || !entries.All(Valid)) throw new InvalidOperationException(invalid);
        foreach (var e in entries.Cast<D>())
        {
            var k = InMemoryRevocationStore.Key((string)e["kind"]!, (string)e["value"]!);
            if (!_mem.ContainsKey(k)) _order.Add(k);
            _mem[k] = e;
        }
    }

    static bool Fin(object? v) => v is Num n && double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d);

    static bool Valid(object? o)
    {
        if (o is not D e) return false;
        if (!e.TryGetValue("kind", out var kind) || kind is not string ks || !Kinds.Contains(ks)) return false;
        if (!e.TryGetValue("value", out var value) || value is not string vs || vs.Length == 0) return false;
        if (!e.TryGetValue("reason", out var reason) || reason is not string) return false;
        if (!e.TryGetValue("revokedAt", out var at) || !Fin(at)) return false;
        if (e.TryGetValue("notBefore", out var nb) && !Fin(nb)) return false;
        if (ks == "prefix")
        {
            if (!e.TryGetValue("prefix", out var p) || p is not L pl || pl.Count == 0 || pl.Any(x => x is not string s || s.Length == 0)) return false;
            if (string.Join(",", pl.Cast<string>()) != vs) return false;
        }
        return true;
    }

    void Flush()
    {
        var tmp = _path + ".tmp";
        var json = JsJson.Stringify(new D { ["v"] = new Num("1"), ["entries"] = _order.Select(k => (object?)_mem[k]).ToList() });
        using (var fs = OwnerOnly.CreateFile(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = new System.Text.UTF8Encoding(false).GetBytes(json);
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
        }
        File.Move(tmp, _path, true);
    }

    /// <summary>Apply <paramref name="change"/> to memory and flush; on a failed flush put memory back, so memory never claims more than disk.</summary>
    T Write<T>(Func<T> change)
    {
        lock (_gate)
        {
            var before = _order.ToDictionary(k => k, k => _mem[k]);
            var order = _order.ToList();
            var @out = change();
            try { Flush(); }
            catch
            {
                _mem.Clear(); _order.Clear();
                foreach (var k in order) { _order.Add(k); _mem[k] = before[k]; }
                throw;
            }
            return @out;
        }
    }

    public Task Add(D entry)
    {
        var k = InMemoryRevocationStore.Key(RevokeApi.Text(entry, "kind"), RevokeApi.Text(entry, "value"));
        try { Write(() => { if (!_mem.ContainsKey(k)) _order.Add(k); _mem[k] = entry; return 0; }); return Task.CompletedTask; }
        catch (Exception e) { return Task.FromException(e); }
    }

    public Task<bool> Remove(string kind, string value)
    {
        var k = InMemoryRevocationStore.Key(kind, value);
        try { return Task.FromResult(Write(() => _mem.Remove(k) && _order.Remove(k))); }
        catch (Exception e) { return Task.FromException<bool>(e); }
    }

    public Task<D?> Get(string kind, string value)
    {
        lock (_gate) return Task.FromResult(_mem.GetValueOrDefault(InMemoryRevocationStore.Key(kind, value)));
    }

    public Task<IReadOnlyList<D>> All()
    {
        lock (_gate) return Task.FromResult<IReadOnlyList<D>>(_order.Select(k => _mem[k]).ToList());
    }

    public Task Clear()
    {
        try { Write(() => { _mem.Clear(); _order.Clear(); return 0; }); return Task.CompletedTask; }
        catch (Exception e) { return Task.FromException(e); }
    }
}
