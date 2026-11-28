// Duplicate-member check for JSON received from outside (signed or digested): the reference's duplicateKey / parseNoDuplicates. A plain parse keeps the LAST
// duplicate, so the signer and a verifier could read different claims from the same bytes. Only duplicates are refused (any depth, keys compared after
// unescaping); numbers and everything else stay as the sender wrote them. Use Pca.ParseStrict for formats we define.
using System.Text;

namespace AtlasPca;

/// <summary>The duplicate-member check of the reference (<c>duplicateKey</c> / <c>parseNoDuplicates</c>).</summary>
public static class NoDuplicateKeys
{
    /// <summary>The first member name that occurs twice in one object (after unescaping), else null. The text is scanned, not parsed: parse it first.</summary>
    public static string? DuplicateKey(string text)
    {
        var stack = new List<HashSet<string>?>();
        var expectKey = false;
        for (int i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"')
            {
                int j = i + 1;
                while (j < text.Length && text[j] != '"') j += text[j] == '\\' ? 2 : 1;
                var top = stack.Count > 0 ? stack[^1] : null;
                if (expectKey && top != null)
                {
                    var key = (string)Pca.ParseJson(text.Substring(i, Math.Min(j + 1, text.Length) - i))!;
                    if (!top.Add(key)) return key;
                    expectKey = false;
                }
                i = j;
            }
            else if (c == '{') { stack.Add(new HashSet<string>(StringComparer.Ordinal)); expectKey = true; }
            else if (c == '[') { stack.Add(null); expectKey = false; }
            else if (c == '}' || c == ']') { if (stack.Count > 0) stack.RemoveAt(stack.Count - 1); expectKey = false; }
            else if (c == ',') expectKey = stack.Count > 0 && stack[^1] != null;
        }
        return null;
    }

    /// <summary>A plain JSON parse that refuses a duplicate member (message <c>duplicate key "k"</c>).</summary>
    public static object? Parse(string text)
    {
        var v = Pca.ParseJson(text);
        var k = DuplicateKey(text);
        if (k != null) throw new FormatException("duplicate key " + AtlasPca.Js.JsJson.Quote(k));
        return v;
    }
}
