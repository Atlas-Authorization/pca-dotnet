using System.IO.Compression;
using System.Text;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>The blob table of a corpus with a top-level <c>blobs</c> member (any string over 400 characters in args or out is <c>{"$blob": id}</c>): the table is read from the corpus header line, and
/// <see cref="Hydrate"/> puts the strings back.</summary>
static class BlobCorpus
{
    static readonly Dictionary<string, D> Tables = new();

    public static D Blobs(string module)
    {
        lock (Tables)
        {
            if (Tables.TryGetValue(module, out var t)) return t;
            var d = AppContext.BaseDirectory;
            for (int i = 0; i < 12 && d != null; i++, d = Path.GetDirectoryName(d))
            {
                var f = Path.Combine(d, "test-data", module + ".json.gz");
                if (!File.Exists(f)) f = Path.Combine(d, "AtlasPca.Corpus.Tests", "test-data", module + ".json.gz");
                if (!File.Exists(f)) continue;
                using var r = new StreamReader(new GZipStream(File.OpenRead(f), CompressionMode.Decompress), new UTF8Encoding(false));
                var head = r.ReadLine() ?? throw new InvalidDataException(f + ": empty oracle");
                var doc = (D)FixtureJson.Parse(head + "]}")!;
                return Tables[module] = doc.GetValueOrDefault("blobs") as D ?? new D();
            }
            throw new FileNotFoundException("test-data/" + module + ".json.gz");
        }
    }

    /// <summary>A deep copy of <paramref name="x"/> with every {"$blob": id} replaced by the string stored under <paramref name="blobs"/>[id].</summary>
    public static object? Hydrate(object? x, D blobs) => x switch
    {
        L l => l.Select(e => Hydrate(e, blobs)).ToList(),
        D m when m.Count == 1 && m.TryGetValue("$blob", out var id) && id is string sid => blobs.TryGetValue(sid, out var v) ? v : throw new InvalidOperationException("unknown blob " + sid),
        D m => m.ToDictionary(kv => kv.Key, kv => Hydrate(kv.Value, blobs)),
        _ => x,
    };
}
