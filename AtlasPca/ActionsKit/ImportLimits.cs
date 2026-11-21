// The bounds every importer enforces before it believes a byte of foreign input: size, depth, node count and reference expansion.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public sealed class ImportLimits
{
    public readonly long MaxBytes, MaxOps, MaxJsonDepth, MaxNodes, MaxRefNodes, MaxRefDepth;

    public ImportLimits(long maxBytes, long maxOps, long maxJsonDepth, long maxNodes, long maxRefNodes, long maxRefDepth)
    {
        MaxBytes = maxBytes; MaxOps = maxOps; MaxJsonDepth = maxJsonDepth; MaxNodes = maxNodes; MaxRefNodes = maxRefNodes; MaxRefDepth = maxRefDepth;
    }

    public static readonly ImportLimits Default = new(64L * 1024 * 1024, 20_000, 64, 6_000_000, 20_000, 8);
    /// <summary>Ceilings no caller may raise past: a caller-supplied limit is clamped to these.</summary>
    public static readonly ImportLimits Hard = new(256L * 1024 * 1024, 50_000, 128, 20_000_000, 200_000, 16);

    static readonly string[] Keys = { "max_bytes", "max_ops", "max_json_depth", "max_nodes", "max_ref_nodes", "max_ref_depth" };

    long Of(int i) => i switch { 0 => MaxBytes, 1 => MaxOps, 2 => MaxJsonDepth, 3 => MaxNodes, 4 => MaxRefNodes, _ => MaxRefDepth };

    /// <summary>Defaults, overridden member by member (clamped to the hard ceilings); a member that is not a positive safe integer is refused.</summary>
    public static ImportLimits Resolve(object? over)
    {
        var o = new long[6];
        for (int i = 0; i < 6; i++)
        {
            o[i] = Default.Of(i);
            if (over is not D od || !od.ContainsKey(Keys[i])) continue;
            var v = od[Keys[i]];
            if (!ImportJx.IsSafe(v) || ImportJx.Dbl(v)! < 1) throw new ActionKitError("bad_limit", "limit " + Keys[i] + " must be a positive safe integer");
            o[i] = Math.Min((long)ImportJx.Dbl(v)!.Value, Hard.Of(i));
        }
        return new ImportLimits(o[0], o[1], o[2], o[3], o[4], o[5]);
    }

    /// <summary>The six limits as an object.</summary>
    public D ToJson() => new()
    {
        ["max_bytes"] = ImportJx.N(MaxBytes), ["max_ops"] = ImportJx.N(MaxOps), ["max_json_depth"] = ImportJx.N(MaxJsonDepth),
        ["max_nodes"] = ImportJx.N(MaxNodes), ["max_ref_nodes"] = ImportJx.N(MaxRefNodes), ["max_ref_depth"] = ImportJx.N(MaxRefDepth),
    };

    /// <summary>Size check of a text source (UTF-8 bytes).</summary>
    public void TextSizeCheck(string text)
    {
        if ((long)text.Length * 3 > MaxBytes && ImportJx.U8(text) > MaxBytes) throw new ActionKitError("import_limit", "the source is larger than " + MaxBytes + " bytes");
    }

    /// <summary>Walk a parsed source iteratively and refuse it when it is not plain JSON data, or is deeper or larger than the limits. Returns the node count.</summary>
    public long CheckParsed(object? root)
    {
        long nodes = 0, bytes = 0;
        var stack = new Stack<(object? V, int D)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (v, d) = stack.Pop();
            if (++nodes > MaxNodes) throw new ActionKitError("import_limit", "the source has more than " + MaxNodes + " nodes");
            if (d > MaxJsonDepth) throw new ActionKitError("import_limit", "the source nests deeper than " + MaxJsonDepth);
            if (v == null || v is bool) bytes += 4;
            else if (v is string s) bytes += s.Length;
            else if (v is L l)
            {
                bytes += 2 + l.Count;
                foreach (var x in l) stack.Push((x, d + 1));
            }
            else if (v is D m)
            {
                foreach (var e in m)
                {
                    bytes += e.Key.Length + 4;
                    stack.Push((e.Value, d + 1));
                }
            }
            else
            {
                var n = ImportJx.Dbl(v);
                if (n == null) throw new ActionKitError("bad_source", "the source holds a " + v.GetType().Name);
                if (double.IsNaN(n.Value) || double.IsInfinity(n.Value)) throw new ActionKitError("bad_source", "the source holds a non-finite number");
                bytes += 8;
            }
            if (bytes > MaxBytes) throw new ActionKitError("import_limit", "the source is larger than " + MaxBytes + " bytes");
        }
        return nodes;
    }
}
