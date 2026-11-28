// "pca actions build|sign" as pure functions: from defs to the unsigned schema, the pack, policy cards, ontology fragment, MCP tool map and
// generated TypeScript declarations, plus pack signing and the consistency check.
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class ActionBuild
{
    public const int MaxPackDefs = 4096;
    public static readonly string PackSignDomain = Actions.PackDigestDomain + "\0";

    /// <summary>Every output of a build. Throws on a pack above the unsharded limit, an empty pack, a duplicate verb or a unit conflict (never a partial build).</summary>
    public static D BuildArtifacts(IEnumerable<D> defsIn, D cfg, Dictionary<string, D> reg, Func<D, bool>? attestationVerified = null)
    {
        var defs = defsIn.OrderBy(d => (string)d["verb"]!, StringComparer.Ordinal).ToList();
        if (defs.Count > MaxPackDefs) throw new InvalidOperationException($"a pack above {MaxPackDefs} defs must be sharded ({defs.Count} given)");
        for (int i = 1; i < defs.Count; i++)
            if ((string)defs[i]["verb"]! == (string)defs[i - 1]["verb"]!) throw new InvalidOperationException($"verb '{defs[i]["verb"]}' appears twice");
        if (defs.Count == 0) throw new ActionKitError("empty_pack", "a pack has at least one def");
        var root = Actions.PackRoot(defs.Select(Actions.DefDigest).ToList());
        var meta = new D { ["site"] = cfg["site"], ["aud"] = cfg["aud"], ["version"] = cfg["version"], ["pack"] = new D { ["ns"] = cfg["ns"], ["version"] = cfg["version"], ["root"] = root } };
        var schema = ActionDerive.ToSchemaDoc(defs, reg, meta, attestationVerified);
        var pack = new D
        {
            ["v"] = 1L, ["kind"] = "pca-action-pack", ["ns"] = cfg["ns"], ["version"] = cfg["version"], ["stability"] = cfg["stability"], ["traits_digest"] = Actions.TraitsDigest(reg),
            ["roles_digest"] = Actions.TablesDigest(), ["rules_digest"] = ActionLint.LintRulesDigest(), ["root"] = root, ["defs"] = new L(defs), ["prev"] = null, ["evolution"] = new L(),
        };
        var cards = new L(defs.Select(d => (object?)ActionDerive.CardOf(d, ActionEffective.EffectiveWith(d, reg, attestationVerified), reg)));
        var tools = new D();
        foreach (var d in defs)
            if (Ak.G(Ak.G(d, "bindings"), "mcp") is D mcp)
                tools[Ak.JsStr(mcp["tool"])] = new D { ["verb"] = d["verb"], ["annotations"] = ActionDerive.McpAnnotationsOf(d, ActionEffective.EffectiveWith(d, reg, attestationVerified)) };
        return new D { ["schema"] = schema, ["pack"] = pack, ["cards"] = cards, ["ontology"] = ActionDerive.ToOntology(defs, reg, attestationVerified), ["mcp"] = new D { ["tools"] = tools }, ["types"] = GenerateTypes(defs) };
    }

    /// <summary>The ToolActionMap of the defs' MCP bindings: tool name and arguments to {verb, resource}, or null.</summary>
    public static Func<string, D, D?> ToolActionMapOf(IEnumerable<D> defs)
    {
        var m = new Dictionary<string, D>();
        foreach (var d in defs) if (Ak.G(Ak.G(d, "bindings"), "mcp") is D mcp) m[Ak.JsStr(mcp["tool"])] = d;
        return (tool, args) =>
        {
            if (!m.TryGetValue(tool, out var d)) return null;
            var r = ActionDerive.OperationOf(d, new D { ["params"] = args });
            if (r["ok"] is not true) return null;
            var op = (D)r["op"]!;
            return new D { ["verb"] = op["verb"], ["resource"] = op["resource"] };
        };
    }

    // ---- generated types
    static string Pascal(string s) => string.Join("", s.Split('.', '_').Select(x => x.Length == 0 ? x : (x[0] == 'ß' ? "SS" : x[..1].ToUpperInvariant()) + x[1..]));
    static Regex IdentRe => Rx.Get(@"\A[A-Za-z_][A-Za-z0-9_]*\z", RegexOptions.CultureInvariant);
    static string Key(string k) => IdentRe.IsMatch(k) ? k : JsJson.Stringify(k);

    static string TsType(D p)
    {
        switch (Ak.S(p, "type"))
        {
            case "integer": case "duration": return "number";
            case "boolean": return "boolean";
            case "set":
                {
                    var vs = string.Join(" | ", Ak.Lst(p, "values").Select(JsJson.Stringify));
                    return $"Array<{(vs.Length > 0 ? vs : "string")}>";
                }
            case "array": return Ak.S(p, "items") == "integer" ? "number[]" : "string[]";
            default: return Ak.G(p, "values") is L vals ? string.Join(" | ", vals.Select(JsJson.Stringify)) : "string";
        }
    }

    sealed class Node { public D? Leaf; public readonly Dictionary<string, Node> Kids = new(); }

    static string Render(Node n, string indent)
    {
        var lines = new List<string>();
        foreach (var k in n.Kids.Keys.OrderBy(x => x, StringComparer.Ordinal))
        {
            var c = n.Kids[k];
            if (c.Leaf != null) lines.Add($"{indent}{Key(k)}{(Ak.G(c.Leaf, "required") is false ? "?" : "")}: {TsType(c.Leaf)};");
            else lines.Add($"{indent}{Key(k)}: {{\n{Render(c, indent + "  ")}\n{indent}}};");
        }
        return string.Join("\n", lines);
    }

    /// <summary>TypeScript declarations for typed call sites: one params interface per verb, ActionParams and ActionVerb.</summary>
    public static string GenerateTypes(IEnumerable<D> defs)
    {
        var outp = new List<string> { "// Generated by `pca actions build`. Do not edit.", "" };
        var names = new List<string>();
        foreach (var d in defs.OrderBy(x => (string)x["verb"]!, StringComparer.Ordinal))
        {
            var root = new Node();
            var ps = (D)d["params"]!;
            foreach (var name in ps.Keys.OrderBy(x => x, StringComparer.Ordinal))
            {
                var n = root;
                var segs = name.Split('.');
                for (int i = 0; i < segs.Length; i++)
                {
                    if (!n.Kids.ContainsKey(segs[i])) n.Kids[segs[i]] = new Node();
                    n = n.Kids[segs[i]];
                    if (i == segs.Length - 1) n.Leaf = (D)ps[name]!;
                }
            }
            var iface = Pascal((string)d["verb"]!) + "Params";
            names.Add($"  {JsJson.Stringify(d["verb"])}: {iface};");
            outp.AddRange(new[] { $"export interface {iface} {{", Render(root, "  "), "}", "" });
        }
        outp.Add("export interface ActionParams {");
        outp.AddRange(names);
        outp.AddRange(new[] { "}", "", "export type ActionVerb = keyof ActionParams;", "" });
        return string.Join("\n", outp);
    }

    // ---- pack signing and consistency
    static byte[] PackMessage(D p) => IntentJs.Message(PackSignDomain, p);

    /// <summary>Null when the pack is internally consistent: every def valid and unique, the Merkle root and digests recomputed.</summary>
    public static string? PackConsistencyError(object? po, Dictionary<string, D> reg)
    {
        try
        {
            if (po is not D p) return "the pack must be an object";
            if (!(Ak.G(p, "kind") is string kind && kind == "pca-action-pack") || !(IntentJs.NumOf(Ak.G(p, "v")) is double v && v == 1.0)) return "not a pca-action-pack v1";
            if (Ak.G(p, "defs") is not L defs || defs.Count > MaxPackDefs) return "defs must be a list within the unsharded limit";
            var seen = new HashSet<string>();
            foreach (var d in defs)
            {
                var e = Actions.ValidateDef(d);
                if (e != null) return $"def {(d is D dd && dd.GetValueOrDefault("verb") != null ? Ak.JsStr(dd["verb"]) : "?")}: {e}";
                var verb = (string)((D)d!)["verb"]!;
                if (!seen.Add(verb)) return $"verb '{verb}' is defined twice";
            }
            if (!JsX.StrictEq(Ak.G(p, "root"), Actions.PackRoot(defs.Select(d => Actions.DefDigest((D)d!)).ToList()))) return "the pack root does not match its defs";
            if (!JsX.StrictEq(Ak.G(p, "traits_digest"), Actions.TraitsDigest(reg))) return "traits_digest does not match the trait registry";
            return null;
        }
        catch (Exception e) { return "malformed pack: " + e.Message; }
    }

    /// <summary>Sign a pack as the registry (Ed25519, 32-byte secret). Refuses an inconsistent pack.</summary>
    public static D SignPack(D pack, string kid, byte[] secret, Dictionary<string, D> reg)
    {
        var bad = PackConsistencyError(pack, reg);
        if (bad != null) throw new InvalidOperationException("signPack: " + bad);
        var body = new D(pack); body.Remove("sig");
        var o = new D(body) { ["sig"] = new D { ["alg"] = "ed25519", ["kid"] = kid, ["value"] = Pca.B64u(EdKey.FromSeed(secret).Sign(PackMessage(body))) } };
        return o;
    }

    public static D PackKeyOf(string kid, byte[] secret) => new() { ["kid"] = kid, ["alg"] = "ed25519", ["pk"] = EdKey.FromSeed(secret).Id };

    /// <summary>Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never throws. {ok: true} or {ok: false, reason}.</summary>
    public static D VerifyPack(object? pack, L keys, Dictionary<string, D> reg)
    {
        D Fail(string r) => new() { ["ok"] = false, ["reason"] = r };
        try
        {
            var bad = PackConsistencyError(pack, reg);
            if (bad != null) return Fail(bad);
            var p = (D)pack!;
            var body = new D(p); body.Remove("sig");
            if (Ak.G(p, "sig") is not D sig || Ak.S(sig, "alg") != "ed25519" || Ak.G(sig, "kid") is not string kid || Ak.G(sig, "value") is not string value) return Fail("missing or malformed signature");
            var k = keys.Select(x => x as D).FirstOrDefault(x => x != null && JsX.StrictEq(Ak.G(x, "kid"), kid));
            if (k == null) return Fail($"no registry key with kid '{kid}'");
            if (Ak.S(k, "alg") != "ed25519" || Pca.B64uDecode(Ak.G(k, "pk"), 32) == null) return Fail("the registry key entry is malformed");
            return IntentJs.VerifyEd(k["pk"], PackMessage(body), value) ? new D { ["ok"] = true } : Fail("pack signature invalid");
        }
        catch (Exception e) { return Fail("pack verification error: " + e.Message); }
    }
}
