// The command line of the policy-safety gate.
//   pca-policy-ci <files...> [--max-severity error|warn|info] [--format text|github] [--quiet] [--schema file] [--lint-rules-pin file]
//   pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
//   pca-policy-ci test <policy.json> <tests.json> [--require-digest]
//   pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]
// Each file is a JSON policy (envelope, grant, compiled policy, {predicates, caveats}) or a JSON array treated as a delegation chain. Exits non-zero
// when a finding reaches --max-severity (default error); 2 is unusable input.
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using static AtlasPca.PolicyCi.CiJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

public static class CiCli
{
    static readonly string[] Severities = { "error", "warn", "info" };

    /// <summary>Parses the gate's own arguments: <c>{args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}}</c> or <c>{error}</c>.</summary>
    public static D ParseArgs(IReadOnlyList<string> argv)
    {
        var files = new L();
        string maxSeverity = "error", format = "text";
        bool quiet = false, help = false;
        string? schema = null, lintRulesPin = null;
        var sevMsg = "--max-severity expects one of " + string.Join('|', Severities);
        D Err(string m) => Obj(("error", m));

        for (int i = 0; i < argv.Count; i++)
        {
            var a = argv[i];
            if (a == "--help" || a == "-h") help = true;
            else if (a == "--quiet" || a == "-q") quiet = true;
            else if (a == "--lint-rules-pin")
            {
                var v = ++i < argv.Count ? argv[i] : null;
                if (v == null || v.StartsWith('-')) return Err("--lint-rules-pin expects a file");
                lintRulesPin = v;
            }
            else if (a == "--max-severity")
            {
                var v = ++i < argv.Count ? argv[i] : null;
                if (v == null || !Severities.Contains(v)) return Err(sevMsg);
                maxSeverity = v;
            }
            else if (a.StartsWith("--max-severity=", StringComparison.Ordinal))
            {
                var v = a["--max-severity=".Length..];
                if (!Severities.Contains(v)) return Err(sevMsg);
                maxSeverity = v;
            }
            else if (a == "--schema")
            {
                var v = ++i < argv.Count ? argv[i] : null;
                if (v == null) return Err("--schema expects a file");
                schema = v;
            }
            else if (a.StartsWith("--schema=", StringComparison.Ordinal)) schema = a["--schema=".Length..];
            else if (a == "--format")
            {
                var v = ++i < argv.Count ? argv[i] : null;
                if (v != "text" && v != "github") return Err("--format expects 'text' or 'github'");
                format = v;
            }
            else if (a.StartsWith("--format=", StringComparison.Ordinal))
            {
                var v = a["--format=".Length..];
                if (v != "text" && v != "github") return Err("--format expects 'text' or 'github'");
                format = v;
            }
            else if (a.StartsWith('-')) return Err($"unknown option '{a}'");
            else files.Add(a);
        }
        var args = Obj(("files", files), ("maxSeverity", maxSeverity), ("format", format), ("quiet", quiet), ("help", help));
        if (schema != null) args["schema"] = schema;
        if (lintRulesPin != null) args["lintRulesPin"] = lintRulesPin;
        return Obj(("args", args));
    }

    public const string Help =
        "pca-policy-ci — statically catch unsafe PCA policies before they ship.\n\n" +
        "Usage:\n" +
        "  pca-policy-ci <files...> [options]\n" +
        "  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]\n" +
        "  pca-policy-ci test <policy.json> <tests.json> [--require-digest]\n" +
        "  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]\n\n" +
        "Options:\n" +
        "  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)\n" +
        "  --format <text|github>            Output format (default: text; 'github' = workflow annotations)\n" +
        "  --schema <file>                   Also check each policy against this signed action schema (JSON)\n" +
        "  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>\n" +
        "  --quiet, -q                       Only print findings and the summary line\n" +
        "  --help, -h                        Show this help\n\n" +
        "Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array\n" +
        "treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.";

    static string Message(Exception e) => e is InsufficientExecutionStackException ? "Maximum call stack size exceeded" : e.Message;

    static string ReadText(string file) => new UTF8Encoding(false).GetString(File.ReadAllBytes(file));

    static (bool Ok, object? Doc, string Reason) ReadJson(string file)
    {
        try { return (true, Pca.ParseJson(ReadText(file)), ""); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or StrictJsonException)
        { return (false, null, $"{file}: {Message(e)}"); }
    }

    static L FindingOf(string message) => new() { Obj(("rule", "malformed-policy"), ("severity", "error"), ("message", message)) };

    static L LintFile(string file, bool hasSchema, object? schema)
    {
        string text;
        try { text = ReadText(file); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return FindingOf($"cannot read file: {Message(e)}"); }
        object? doc;
        try { doc = Pca.ParseJson(text); }
        catch (StrictJsonException e) { return FindingOf($"invalid JSON: {Message(e)}"); }
        return PcaPolicyCi.Lint(doc, hasSchema ? Obj(("schema", schema)) : new D());
    }

    static string GhLevel(string sev) => sev == "error" ? "error" : sev == "warn" ? "warning" : "notice";
    static string TextTag(string sev) => sev == "error" ? "ERROR" : sev == "warn" ? "WARN " : "INFO ";

    static void PrintText(L results, bool quiet, Action<string> write)
    {
        foreach (var r in results)
        {
            if (!quiet) write($"\n{Str(G(r, "label"))}:");
            var findings = (L)G(r, "findings")!;
            if (findings.Count == 0)
            {
                if (!quiet) write("  (clean)");
                continue;
            }
            foreach (var f in findings)
            {
                var where = G(f, "where");
                var loc = where != null ? $" [{Str(where)}]" : "";
                write($"  {TextTag((string)G(f, "severity")!)} {Str(G(f, "rule"))}{loc}: {Str(G(f, "message"))}");
            }
        }
    }

    static string EscapeGh(string s) => s.Replace("%", "%25").Replace("\r", "%0D").Replace("\n", "%0A");
    /// <summary>Workflow-command property values must also escape ':' and ',', or a file name can add properties or end the command.</summary>
    static string EscapeGhProp(string s) => EscapeGh(s).Replace(":", "%3A").Replace(",", "%2C");

    static void PrintGithub(L results, Action<string> write)
    {
        foreach (var r in results)
            foreach (var f in (L)G(r, "findings")!)
            {
                var props = $"file={EscapeGhProp(Str(G(r, "label")))},title={EscapeGhProp(Str(G(f, "rule")))}";
                var where = G(f, "where");
                var loc = where != null ? $"{Str(where)}: " : "";
                write($"::{GhLevel((string)G(f, "severity")!)} {props}::{EscapeGh($"{loc}{Str(G(f, "message"))}")}");
            }
    }

    /// <summary>Number(v) of a trimmed non-empty flag value when it is finite, else null.</summary>
    static double? FlagNum(Jx.OMap flags, string k)
    {
        var i = flags.Find(k);
        if (i < 0 || flags.Items[i].Value is not string v || JsX.JsTrim(v).Length == 0) return null;
        var d = AtlasPca.Js.JsJson.ToJsNumber(v);
        return double.IsFinite(d) ? d : null;
    }

    static readonly HashSet<string> Valued = new() { "--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors" };
    static readonly HashSet<string> Bools = new() { "--allow-widen", "--integer", "--require-digest" };

    /// <summary><c>diff</c>, <c>test</c> and <c>coverage</c>: two files and flags. Unknown or malformed flags are a usage error (exit 2).</summary>
    static int RunAuthoring(string cmd, IReadOnlyList<string> rest, Action<string> write)
    {
        var files = new List<string>();
        var flags = new Jx.OMap();
        for (int i = 0; i < rest.Count; i++)
        {
            var a = rest[i];
            if (Valued.Contains(a))
            {
                if (++i >= rest.Count) { write($"{a} expects a value"); return 2; }
                flags.Set(a, rest[i]);
            }
            else if (Bools.Contains(a)) flags.Set(a, true);
            else if (a.StartsWith('-')) { write($"unknown option '{a}'"); return 2; }
            else files.Add(a);
        }
        foreach (var (k, v) in flags.Items.ToList())
            if (Valued.Contains(k) && k != "--verb" && k != "--amount-field" && FlagNum(flags, k) == null)
            {
                write($"{k} expects a number, got '{Str(v)}'");
                return 2;
            }
        if (files.Count != 2)
        {
            write($"error: {cmd} takes exactly two files");
            write(Help);
            return 2;
        }
        var docs = files.Select(ReadJson).ToList();
        var badDoc = docs.Where(d => !d.Ok).Select(d => d.Reason).FirstOrDefault();
        if (badDoc != null) { write(badDoc); return 2; }
        var a0 = docs[0].Doc; var b0 = docs[1].Doc;
        bool Flag(string k) => flags.Find(k) >= 0;
        string? Text(string k) { var i = flags.Find(k); return i >= 0 ? flags.Items[i].Value as string : null; }
        D r;
        if (cmd == "diff")
        {
            var o = Obj(("allowWiden", Flag("--allow-widen")));
            if (Text("--verb") is { } verb) o["verb"] = verb;
            if (Text("--amount-field") is { } af) o["amountField"] = af;
            o["integer"] = Flag("--integer");
            if (FlagNum(flags, "--window-secs") is double ws) o["windowSecs"] = NumD(ws);
            if (FlagNum(flags, "--max-exposure-increase") is double me) o["maxExposureIncrease"] = NumD(me);
            r = CiAuthoring.DiffCommand(a0, b0, o);
        }
        else if (cmd == "test") r = CiAuthoring.TestCommand(a0, b0, Obj(("requireDigest", Flag("--require-digest"))));
        else
        {
            var o = new D();
            if (FlagNum(flags, "--min-clauses") is double mc) o["minClauses"] = NumD(mc);
            if (FlagNum(flags, "--min-boundaries") is double mb) o["minBoundaries"] = NumD(mb);
            if (FlagNum(flags, "--min-mutation") is double mm) o["minMutation"] = NumD(mm);
            if (FlagNum(flags, "--max-survivors") is double ms) o["maxSurvivors"] = NumD(ms);
            r = CiAuthoring.CoverageCommand(a0, b0, o);
        }
        foreach (var l in (L)r["lines"]!) write((string)l!);
        return (int)Math.Round(Jx.ToNumber(r["exitCode"]));
    }

    /// <summary>Runs the command line; <paramref name="write"/> receives each output line (default: standard output). Returns the exit code.</summary>
    public static int Run(IReadOnlyList<string> argv, Action<string>? write = null)
    {
        write ??= Console.WriteLine;
        if (argv.Count > 0 && (argv[0] == "diff" || argv[0] == "test" || argv[0] == "coverage")) return RunAuthoring(argv[0], argv.Skip(1).ToList(), write);
        var parsed = ParseArgs(argv);
        if (parsed.TryGetValue("error", out var err))
        {
            write((string)err!);
            write(Help);
            return 2;
        }
        var args = (D)parsed["args"]!;
        var files = (L)args["files"]!;
        if (args["help"] is true)
        {
            write(Help);
            return 0;
        }
        var pinFailed = false;
        if (args.GetValueOrDefault("lintRulesPin") is string pinFile)
        {
            D r;
            try { r = PcaPolicyCi.CheckLintRulesPin(ReadText(pinFile)); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { r = Obj(("ok", false), ("message", $"cannot read the lint rules pin: {Message(e)}")); }
            write($"{(r["ok"] is true ? "PASS" : "FAIL")} — {Str(r["message"])}");
            pinFailed = r["ok"] is not true;
            if (files.Count == 0) return pinFailed ? 1 : 0;
        }
        if (files.Count == 0)
        {
            write("error: no policy files given");
            write(Help);
            return 2;
        }
        var hasSchema = false;
        object? schema = null;
        if (args.GetValueOrDefault("schema") is string schemaFile)
        {
            var s = ReadJson(schemaFile);
            if (!s.Ok) { write(s.Reason); return 2; }
            hasSchema = true;
            schema = s.Doc;
        }
        var results = new L(files.Select(f => (object?)Obj(("label", f), ("findings", LintFile((string)f!, hasSchema, schema)))));
        var summary = PcaPolicyCi.Summarize(results, Obj(("maxSeverity", args["maxSeverity"])));
        if (args["format"] is "github") PrintGithub(results, write);
        else PrintText(results, args["quiet"] is true, write);
        if (summary.TryGetValue("reason", out var reason) && Truthy(reason)) write($"error: {Str(reason)}");
        var c = (D)summary["counts"]!;
        write($"\n{(summary["ok"] is true ? "PASS" : "FAIL")} — {Str(c["error"])} error(s), {Str(c["warn"])} warning(s), {Str(c["info"])} info across {results.Count} policy/policies (fail threshold: {Str(summary["maxSeverity"])})");
        var code = (int)Math.Round(Jx.ToNumber(summary["exitCode"]));
        return pinFailed ? Math.Max(1, code) : code;
    }
}
