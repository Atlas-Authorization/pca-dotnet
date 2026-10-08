using AtlasPca;

// Usage: dotnet run --project ConformanceRunner [conformance-dir]
// Runs the wire-format-v2 conformance suite (packages/pca/conformance/vectors.json): the core PCActn
// vectors, the v2.1 agent-leaf threshold-share binding, and the PQ transparency/authority artifacts.
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
// vectors.json is a trusted fixture (contains deliberately non-canonical already-parsed values): plain parse.
var doc = (Dictionary<string, object?>)Pca.ParseJson(File.ReadAllText(Path.Combine(dir, "vectors.json")))!;
int fails = 0, total = 0;
void Bad(string m) { fails++; Console.WriteLine("FAIL " + m); }
if (!(doc["format"] is Num f && f.Raw == "2")) { Console.WriteLine("vectors.json is not format 2"); return 2; }

// The signature suites this .NET verifier implements for a GENUINE crypto verdict — the leaf signature
// (requires:"pq"), non-leaf capability-chain hops (requires:"pq-nonleaf"), the threshold-share binding, and
// the PQ artifacts. These are the THREE cross-impl suites every conformant verifier must agree on: classical
// Ed25519, pure-lattice ML-DSA-65 (FIPS-204, via BouncyCastle MLDsaSigner), and the hybrid Ed25519+ML-DSA-65.
// The other 7 registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested
// hybrid) are NOT wired in .NET, so any vector needing a real signature verdict under them is SKIPPED
// explicitly, per-suite — never silently passed.
var supportedSuites = new HashSet<string> { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" };

static string AlgOf(Dictionary<string, object?> o) =>
    o.TryGetValue("alg", out var a) && a is string s ? s : "ed25519";

// The concrete suite a vector exercises that .NET does NOT implement, if any: the leaf `alg` for
// requires:"pq", or the first non-ed25519 capability-hop `alg` for requires:"pq-nonleaf". null for core
// vectors and for vectors that stay entirely within the supported suites.
string? UnsupportedSuite(Dictionary<string, object?> v)
{
    if (!v.TryGetValue("pcactn", out var po) || po is not Dictionary<string, object?> p) return null; // raw/core vectors
    var req = v.TryGetValue("requires", out var r) ? r as string : null;
    if (req == "pq")
    {
        var a = AlgOf(p);
        return supportedSuites.Contains(a) ? null : a;
    }
    if (req == "pq-nonleaf" && p.TryGetValue("cap_chain", out var cc) && cc is List<object?> chain)
    {
        foreach (var hv in chain)
            if (hv is Dictionary<string, object?> hop)
            {
                var a = AlgOf(hop);
                if (!supportedSuites.Contains(a)) return a;
            }
    }
    return null;
}

// A terminal {wire:false} verdict is suite-AGNOSTIC: an unknown `alg` (or a `pq_sig` whose size the suite
// cannot admit) is rejected at the wire stage regardless of whether we implement the suite, which IS the
// correct contract verdict. So these negatives still RUN and pass even for an unimplemented suite.
static bool TerminalWireFalse(Dictionary<string, object?> checks) =>
    checks.Count == 1 && checks.TryGetValue("wire", out var w) && w is bool b && !b;

var vs = (List<object?>)doc["vectors"]!;
var skippedBySuite = new SortedDictionary<string, int>();
foreach (var x in vs)
{
    var v = (Dictionary<string, object?>)x!;
    var name = (string)v["name"]!;
    var exp = (Dictionary<string, object?>)v["expect"]!;
    var expChecks = (Dictionary<string, object?>)exp["checks"]!;
    // SUITE-AWARE skip: only skip a vector whose expected verdict needs a real crypto verdict under a suite
    // .NET does not implement. A terminal {wire:false} negative is run regardless.
    var sus = UnsupportedSuite(v);
    if (sus != null && !TerminalWireFalse(expChecks))
    {
        skippedBySuite[sus] = skippedBySuite.GetValueOrDefault(sus) + 1;
        continue;
    }
    total++;
    var ctx = (Dictionary<string, object?>)v["context"]!;
    long now = long.Parse(((Num)ctx["now"]!).Raw);
    var aud = (string)ctx["aud"]!;
    var grant = (Dictionary<string, object?>)v["grant"]!;
    Verdict got = v.ContainsKey("pcactn_json")
        ? Pca.VerifyRaw((string)v["pcactn_json"]!, grant, now, aud)
        : Pca.VerifyPcactnCore(v["pcactn"], grant, now, aud);
    bool ok = got.Allow == (bool)exp["allow"]! && got.Checks.Count == expChecks.Count;
    foreach (var (k, w) in expChecks)
        if (!got.Checks.TryGetValue(k, out var g) || g != (bool)w!) ok = false;
    if (ok) Console.WriteLine("ok   " + name);
    else Bad($"{name} allow={got.Allow} checks=[{string.Join(",", got.Checks.Select(kv => kv.Key + "=" + kv.Value))}] ({got.Reason})");
}
int vectorSkipped = skippedBySuite.Values.Sum();

// ================= primitives =================
var prim = (Dictionary<string, object?>)doc["primitives"]!;
foreach (var x in (List<object?>)prim["canonical"]!)
{
    var c = (Dictionary<string, object?>)x!; total++;
    var s = Pca.Canonicalize(c["value"]);
    if (s != (string)c["expect"]! || Pca.HashCanonical(c["value"]) != (string)c["hash"]!) Bad("canonical " + c["expect"]);
}
foreach (var x in (List<object?>)prim["json_parse"]!)
{
    var c = (Dictionary<string, object?>)x!; total++;
    var input = (string)c["input"]!; bool accept = (bool)c["accept"]!;
    bool got; string? canon = null;
    try { canon = Pca.Canonicalize(Pca.ParseStrict(input)); got = true; } catch (Exception) { got = false; }
    bool ok = got == accept && (!accept || !c.ContainsKey("canonical") || canon == (string)c["canonical"]!);
    if (!ok) Bad($"json_parse accept={got} want={accept} input={input.Replace("\n", "\\n")}");
}
foreach (var x in (List<object?>)prim["b64u"]!)
{
    var c = (Dictionary<string, object?>)x!; total++;
    int? len = c.TryGetValue("len", out var l) && l is Num ln ? int.Parse(ln.Raw) : null;
    bool got = Pca.B64uDecode((string)c["input"]!, len) != null;
    if (got != (bool)c["valid"]!) Bad($"b64u valid={got} want={c["valid"]} input={c["input"]}");
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

// ================= v2.1 agent-leaf threshold-share binding =================
// Every primitives.threshold_share[] entry MUST verify over the v2.1 signerSetHash||t-bound share message iff
// `valid`. The verifier RECOMPUTES signerSetHash from the signer set (never trusting the precomputed field).
// In particular the PRE-v2.1 bare agent share and a cross-signer-set replay MUST be REJECTED.
int shareAccepted = 0, shareRejected = 0;
bool bareRejected = false, wrongSetRejected = false;
foreach (var x in (List<object?>)prim["threshold_share"]!)
{
    var s = (Dictionary<string, object?>)x!; total++;
    var sname = (s.TryGetValue("name", out var n) ? n as string : null) ?? (string)s["role"]!;
    bool want = !s.TryGetValue("valid", out var vo) || vo is not bool vb || vb;
    bool got = Pca.VerifyThresholdShare(s);
    if (got != want) Bad($"threshold_share {sname}: verified={got} want valid={want}");
    if (want) shareAccepted++; else shareRejected++;
    if (sname == "agent-bare-rejected" && !got) bareRejected = true;
    if (sname == "agent-bound-wrong-set" && !got) wrongSetRejected = true;
}
total++; // assertion: the pre-v2.1 bare agent share MUST be rejected
if (!bareRejected) Bad("v2.1 binding: the pre-v2.1 bare agent share (agent-bare-rejected) MUST be rejected");
total++; // assertion: a cross-signer-set agent share replay MUST be rejected
if (!wrongSetRejected) Bad("v2.1 binding: a cross-signer-set agent share replay (agent-bound-wrong-set) MUST be rejected");

// ================= PQ transparency / authority artifacts (shared agility seam) =================
int artRan = 0;
var artSkippedBySuite = new SortedDictionary<string, int>();
foreach (var x in (List<object?>)prim["pq_artifact"]!)
{
    var a = (Dictionary<string, object?>)x!;
    var alg = a.TryGetValue("alg", out var av) ? av as string : null;
    var artifact = a.TryGetValue("artifact", out var art) ? art as string : "?";
    if (alg == null || !supportedSuites.Contains(alg))
    {
        var key = alg ?? "(none)";
        artSkippedBySuite[key] = artSkippedBySuite.GetValueOrDefault(key) + 1;
        continue;
    }
    total++; artRan++;
    var msg = Pca.B64uDecode((string)a["message"]!); // strict base64url, no fixed length
    bool want = !a.TryGetValue("valid", out var vo) || vo is not bool vb || vb;
    bool got = msg != null && Pca.VerifySuiteSig(alg, a.GetValueOrDefault("ed_pub"),
        a.GetValueOrDefault("pq_pk"), msg, a.GetValueOrDefault("sig"), a.GetValueOrDefault("pq_sig"));
    if (got != want) Bad($"pq_artifact {artifact}/{alg}: verified={got} want={want}");
}
int artSkipped = artSkippedBySuite.Values.Sum();

// ================= report =================
Console.WriteLine();
Console.WriteLine($"PCActn vectors: ran {vs.Count - vectorSkipped}/{vs.Count}, skipped {vectorSkipped}");
foreach (var (suite, n) in skippedBySuite)
    Console.WriteLine($"  skipped {n} vector(s) requiring unimplemented suite \"{suite}\"");
Console.WriteLine($"threshold shares: {shareAccepted} valid accepted, {shareRejected} invalid rejected " +
    "(incl. v2.1 bare-agent-share + cross-signer-set replay)");
Console.WriteLine($"  v2.1 bare-agent-share rejected: {bareRejected}; cross-signer-set replay rejected: {wrongSetRejected}");
Console.WriteLine($"pq artifacts: ran {artRan}, skipped {artSkipped}");
foreach (var (suite, n) in artSkippedBySuite)
    Console.WriteLine($"  skipped {n} pq artifact(s) under unimplemented suite \"{suite}\"");
Console.WriteLine();
Console.WriteLine($"{total - fails}/{total} checks passed ({vs.Count - vectorSkipped} vectors ran, {vectorSkipped} vectors skipped)");
return fails == 0 ? 0 : 1;
