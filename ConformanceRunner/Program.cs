using AtlasPca;

// Usage: dotnet run --project ConformanceRunner [conformance-dir]
var dir = args.Length > 0 ? args[0] : "";
if (dir == "")
{
    // Walk up from the working directory and the build output until conformance/vectors.json is found.
    foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
    {
        for (var d = new DirectoryInfo(start); d != null && dir == ""; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "conformance", "vectors.json"))) dir = Path.Combine(d.FullName, "conformance");
    }
}
var doc = (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(dir, "vectors.json")))!;
int fails = 0, total = 0;
void Bad(string m) { fails++; Console.WriteLine("FAIL " + m); }

var vs = (List<object?>)doc["vectors"]!;
foreach (var x in vs)
{
    var v = (Dictionary<string, object?>)x!;
    var name = (string)v["name"]!; total++;
    var got = Pca.VerifyPcactnCore((Dictionary<string, object?>)v["pcactn"]!, (Dictionary<string, object?>)v["grant"]!);
    var exp = (Dictionary<string, object?>)v["expect"]!;
    bool ok = got.Allow == (bool)exp["allow"]!;
    foreach (var (k, w) in (Dictionary<string, object?>)exp["checks"]!)
        if (got.Checks[k] != (bool)w!) ok = false;
    if (ok) Console.WriteLine("ok   " + name); else Bad($"{name} allow={got.Allow} ({got.Reason})");
}

var prim = (Dictionary<string, object?>)doc["primitives"]!;
foreach (var x in (List<object?>)prim["canonical"]!)
{
    var c = (Dictionary<string, object?>)x!; total++;
    var s = Pca.Canonicalize(c["value"]);
    if (s != (string)c["expect"]! || Pca.HashCanonical(c["value"]) != (string)c["hash"]!) Bad("canonical " + c["expect"]);
}
foreach (var x in (List<object?>)prim["merkle"]!)
{
    var m = (Dictionary<string, object?>)x!; total++;
    var leaves = (List<object?>)m["leaves"]!;
    var root = Pca.MerkleRoot(leaves);
    if (root != (string)m["root"]!) { Bad("merkle root"); continue; }
    var proofs = (List<object?>)m["proofs"]!;
    for (int i = 0; i < proofs.Count; i++)
        if (!Pca.VerifyInclusion(root, (Dictionary<string, object?>)proofs[i]!, leaves[i])) Bad("merkle proof " + i);
}
total++;
if (Pca.ParamsDigest(null) != (string)prim["params_digest_empty"]!) Bad("params_digest_empty");

Console.WriteLine($"{total - fails}/{total} passed ({vs.Count} vectors)");
return fails == 0 ? 0 : 1;
