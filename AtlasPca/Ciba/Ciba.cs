using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Gnap;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Ciba;

/// <summary>
/// A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for PCA's step-up: a step-up request becomes a backchannel
/// authentication request (binding message, scope, expiry, interval) with risk-adaptive gating. Mirrors the TypeScript package's main module. A
/// step-up is a JSON object with the reference's field names (id, verb, resource, params, tier, goalCommit, goal, render, renderDigest); request
/// options use the reference's option names (expiresInSec, authReqId, stepUpScope, loginHint, bindingMessage = {maxChars, tokenOnly}, interval,
/// actsFor). Every refusal throws <see cref="ArgumentException"/> (the reference's RangeError / TypeError). Nothing here authorises anything: the
/// resource server's verifier and the FROST cosigners remain the authority.
/// The payee homograph checks use the runtime's Unicode tables and a fixed script table for the common writing systems; AsciiForm encodes a word
/// with RFC 3492 punycode after lower-casing and NFKC.
/// </summary>
public static class Ciba
{
    internal const int DefaultExpirySec = 300;
    internal const int DefaultIntervalSec = 5;
    internal const int MinAuthReqIdLen = 22;
    internal const int MaxGoalChars = 100;
    internal const int MaxPayeeChars = 64;
    internal static readonly string[] PayeeKeys = { "payee", "to", "recipient", "beneficiary", "destination" };
    static readonly HashSet<string> DisplayedParamKeys = new(new[] { "amount", "currency" }.Concat(PayeeKeys));

    const string WsClass = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static readonly Regex ForgedClause = new("because[" + WsClass + "]+you[" + WsClass + "]+asked", Ro | RegexOptions.IgnoreCase);
    static readonly Regex AuthReqIdRe = new(@"\A[A-Za-z0-9._-]+\z", Ro);
    static readonly Regex IdentRe = new(@"\A[A-Za-z0-9][A-Za-z0-9._:/#@+\-]{0,63}\z", Ro);
    static readonly Regex PlainAmount = new(@"\A(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\z", Ro);
    static readonly Regex CurrencyRe = new(@"\A[A-Za-z]{3}\z", Ro);
    static readonly Regex WsTwo = new("[" + WsClass + "]{2,}", Ro);

    static ArgumentException Range(string m) => new(m);

    // ---- text helpers ----

    static int CpLen(string s) => CibaJs.CodePoints(s).Count;

    static UnicodeCategory Cat(int cp) => cp >= 0xd800 && cp <= 0xdfff ? UnicodeCategory.Surrogate : CharUnicodeInfo.GetUnicodeCategory(cp);

    /// <summary>Make untrusted text safe for a one-line, plain-text approval prompt: control characters, line breaks and bidi / zero-width
    /// formatting characters become spaces, runs of whitespace collapse.</summary>
    internal static string PlainText(string value)
    {
        var sb = new StringBuilder();
        bool inWs = false;
        foreach (var cp in CibaJs.CodePoints(value))
        {
            var t = Cat(cp);
            bool space = t == UnicodeCategory.Control || t == UnicodeCategory.Format || cp == 0x2028 || cp == 0x2029 || CibaJs.IsWs(cp);
            if (space) { if (!inWs) sb.Append(' '); inWs = true; }
            else { sb.Append(CibaJs.FromCodePoint(cp)); inWs = false; }
        }
        return CibaJs.Trim(sb.ToString());
    }

    internal static string Clip(string value, double max)
    {
        var cps = CibaJs.CodePoints(value);
        if (cps.Count <= max) return value;
        int keep = (int)max - 1;
        int end = Math.Max(0, Math.Min(keep, cps.Count));
        var sb = new StringBuilder();
        for (int i = 0; i < end; i++) sb.Append(CibaJs.FromCodePoint(cps[i]));
        return sb.Append('…').ToString();
    }

    static bool AsciiPrintable(string s, bool allowEmpty)
    {
        if (s.Length == 0) return allowEmpty;
        foreach (var c in s) if (c < 0x20 || c > 0x7e) return false;
        return true;
    }

    static string Identifier(object? value, string what)
    {
        if (value is not string s || !IdentRe.IsMatch(s))
            throw Range("ciba: the step-up " + what + " must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message");
        if (ForgedClause.IsMatch(s)) throw Range("ciba: the step-up " + what + " contains an approval-explanation clause");
        return s;
    }

    static bool Undisplayable(int cp)
    {
        var t = Cat(cp);
        return t == UnicodeCategory.Control || t == UnicodeCategory.Format || t == UnicodeCategory.Surrogate || t == UnicodeCategory.PrivateUse || t == UnicodeCategory.OtherNotAssigned
            || cp == 0x2028 || cp == 0x2029 || (cp >= 0xfff9 && cp <= 0xfffd);
    }

    static bool IsMark(int cp)
    {
        var t = Cat(cp);
        return t == UnicodeCategory.NonSpacingMark || t == UnicodeCategory.SpacingCombiningMark || t == UnicodeCategory.EnclosingMark;
    }

    static bool IsLetter(int cp) => Cat(cp) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter;

    static bool IsLetterOrDigit(int cp) => IsLetter(cp) || Cat(cp) == UnicodeCategory.DecimalDigitNumber;

    static string PayeeText(object? value)
    {
        if (value is not string v) throw Range("ciba: the payee must be a string (a nested value cannot be shown to the approver)");
        var t = v.Normalize(NormalizationForm.FormC);
        if (t.Length == 0 || CibaJs.Trim(t) != t || WsTwo.IsMatch(t)) throw Range("ciba: the payee must be non-empty without leading, trailing or repeated whitespace");
        var cps = CibaJs.CodePoints(t);
        if (cps.Any(Undisplayable) || t.Contains('\r') || t.Contains('\n') || t.Contains('\t'))
            throw Range("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed");
        if (t.Contains('"') || t.Contains('\\')) throw Range("ciba: the payee must not contain quote or backslash characters");
        if (cps.Count > MaxPayeeChars) throw Range("ciba: the payee is longer than " + MaxPayeeChars + " characters; refusing to truncate what the person approves");
        if (ForgedClause.IsMatch(t)) throw Range("ciba: the payee contains an approval-explanation clause");
        // Look-alikes: NFC already composed what can be composed, so a combining mark left is stacked or decorative; compatibility forms differ from
        // their plain look-alike under NFKC; a payee that mixes scripts is the classic homograph.
        if (cps.Any(IsMark)) throw Range("ciba: the payee contains combining marks and cannot be shown unambiguously");
        if (t.Normalize(NormalizationForm.FormKC) != t) throw Range("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones");
        if (ScriptsOf(t).Count > 1) throw Range("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike");
        return t;
    }

    static readonly (int Lo, int Hi, string Script)[] ScriptTable =
    {
        (0x41, 0x5a, "latin"), (0x61, 0x7a, "latin"), (0xaa, 0xaa, "latin"), (0xba, 0xba, "latin"), (0xc0, 0xd6, "latin"), (0xd8, 0xf6, "latin"), (0xf8, 0x2b8, "latin"),
        (0x2e0, 0x2e4, "latin"), (0x1d00, 0x1d25, "latin"), (0x1d2c, 0x1d5c, "latin"), (0x1d62, 0x1d65, "latin"), (0x1d6b, 0x1d77, "latin"), (0x1d79, 0x1dbe, "latin"),
        (0x1e00, 0x1eff, "latin"), (0x2071, 0x2071, "latin"), (0x207f, 0x207f, "latin"), (0x2090, 0x209c, "latin"), (0x212a, 0x212b, "latin"), (0x2132, 0x2132, "latin"),
        (0x214e, 0x214e, "latin"), (0x2160, 0x2188, "latin"), (0x2c60, 0x2c7f, "latin"), (0xa722, 0xa787, "latin"), (0xa78b, 0xa7ff, "latin"), (0xab30, 0xab5a, "latin"),
        (0xab5c, 0xab64, "latin"), (0xfb00, 0xfb06, "latin"), (0xff21, 0xff3a, "latin"), (0xff41, 0xff5a, "latin"),
        (0x370, 0x373, "greek"), (0x375, 0x377, "greek"), (0x37a, 0x37d, "greek"), (0x37f, 0x37f, "greek"), (0x384, 0x384, "greek"), (0x386, 0x386, "greek"), (0x388, 0x3e1, "greek"),
        (0x3f0, 0x3ff, "greek"), (0x1f00, 0x1fff, "greek"), (0x2126, 0x2126, "greek"),
        (0x400, 0x484, "cyrillic"), (0x487, 0x52f, "cyrillic"), (0x1c80, 0x1c88, "cyrillic"), (0x1d2b, 0x1d2b, "cyrillic"), (0x1d78, 0x1d78, "cyrillic"), (0x2de0, 0x2dff, "cyrillic"),
        (0xa640, 0xa69f, "cyrillic"),
        (0x531, 0x58f, "armenian"), (0xfb13, 0xfb17, "armenian"),
        (0x591, 0x5f4, "hebrew"), (0xfb1d, 0xfb4f, "hebrew"),
        (0x600, 0x6ff, "arabic"), (0x750, 0x77f, "arabic"), (0x8a0, 0x8ff, "arabic"), (0xfb50, 0xfdff, "arabic"), (0xfe70, 0xfefe, "arabic"),
        (0x2e80, 0x2fdf, "cjk"), (0x3005, 0x3005, "cjk"), (0x3007, 0x3007, "cjk"), (0x3021, 0x3029, "cjk"), (0x3038, 0x303b, "cjk"), (0x3400, 0x4dbf, "cjk"), (0x4e00, 0x9fff, "cjk"),
        (0xf900, 0xfaff, "cjk"), (0x20000, 0x323af, "cjk"),
        (0x3041, 0x3096, "cjk"), (0x309d, 0x309f, "cjk"),
        (0x30a1, 0x30fa, "cjk"), (0x30fd, 0x30ff, "cjk"), (0x31f0, 0x31ff, "cjk"), (0x32d0, 0x32fe, "cjk"), (0x3300, 0x3357, "cjk"), (0xff66, 0xff6f, "cjk"), (0xff71, 0xff9d, "cjk"),
        (0x1100, 0x11ff, "cjk"), (0x3131, 0x318e, "cjk"), (0xa960, 0xa97c, "cjk"), (0xac00, 0xd7a3, "cjk"), (0xd7b0, 0xd7fb, "cjk"),
        (0x3105, 0x312f, "cjk"), (0x31a0, 0x31bf, "cjk"),
        (0x900, 0x950, "indic-thai"), (0x953, 0x963, "indic-thai"), (0x966, 0x97f, "indic-thai"), (0xa8e0, 0xa8ff, "indic-thai"), (0x980, 0x9ff, "indic-thai"), (0xb80, 0xbff, "indic-thai"),
        (0xe01, 0xe3a, "indic-thai"), (0xe40, 0xe5b, "indic-thai"), (0x10a0, 0x10fa, "indic-thai"), (0x10fc, 0x10ff, "indic-thai"), (0x1c90, 0x1cbf, "indic-thai"), (0x2d00, 0x2d2f, "indic-thai"),
    };

    /// <summary>Writing-system groups present in <paramref name="t"/> (letters only; digits, punctuation and spaces are script-neutral). A letter of a script
    /// outside the table is its own group.</summary>
    internal static HashSet<string> ScriptsOf(string t)
    {
        var found = new HashSet<string>();
        foreach (var cp in CibaJs.CodePoints(t))
        {
            if (!IsLetter(cp)) continue;
            string? g = null;
            foreach (var (lo, hi, script) in ScriptTable) if (cp >= lo && cp <= hi) { g = script; break; }
            found.Add(g ?? "other:" + CibaJs.FromCodePoint(cp));
        }
        return found;
    }

    // ---- ASCII form of a payee (punycode) ----

    static char PDigit(int d) => (char)(d < 26 ? 'a' + d : '0' + (d - 26));

    static int Adapt(int delta, int numPoints, bool first)
    {
        delta = first ? delta / 700 : delta / 2;
        delta += delta / numPoints;
        int k = 0;
        while (delta > 455) { delta /= 35; k += 36; }
        return k + 36 * delta / (delta + 38);
    }

    /// <summary>RFC 3492 punycode of a label (no xn-- prefix).</summary>
    static string Punycode(List<int> input)
    {
        var o = new StringBuilder();
        int n = 128, delta = 0, bias = 72;
        foreach (var c in input) if (c < 128) o.Append((char)c);
        int b = o.Length, h = b;
        if (b > 0) o.Append('-');
        while (h < input.Count)
        {
            int m = int.MaxValue;
            foreach (var c in input) if (c >= n && c < m) m = c;
            delta += (m - n) * (h + 1);
            n = m;
            foreach (var c in input)
            {
                if (c < n) delta++;
                if (c == n)
                {
                    int q = delta;
                    for (int k = 36; ; k += 36)
                    {
                        int t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
                        if (q < t) break;
                        o.Append(PDigit(t + (q - t) % (36 - t)));
                        q = (q - t) / (36 - t);
                    }
                    o.Append(PDigit(q));
                    bias = Adapt(delta, h + 1, h == b);
                    delta = 0;
                    h++;
                }
            }
            delta++;
            n++;
        }
        return o.ToString();
    }

    static int Hex(char c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    static string PercentDecode(string h)
    {
        var bytes = new List<byte>();
        for (int i = 0; i < h.Length;)
        {
            if (h[i] == '%' && i + 2 < h.Length && Hex(h[i + 1]) >= 0 && Hex(h[i + 2]) >= 0)
            {
                bytes.Add((byte)(Hex(h[i + 1]) * 16 + Hex(h[i + 2])));
                i += 3;
                continue;
            }
            int len = char.IsHighSurrogate(h[i]) && i + 1 < h.Length && char.IsLowSurrogate(h[i + 1]) ? 2 : 1;
            bytes.AddRange(Encoding.UTF8.GetBytes(h.Substring(i, len)));
            i += len;
        }
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    static bool IgnoredByIdna(int cp) => cp == 0xad || cp == 0x200b || cp == 0x2060 || cp == 0xfeff || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0x180b && cp <= 0x180d);

    static readonly Regex DigitsOnly = new(@"\A[0-9]+\z", Ro);
    static readonly Regex HexOnly = new(@"\A0[xX][0-9a-fA-F]*\z", Ro);

    /// <summary>An approximation of url.domainToASCII (the host of ws://&lt;word&gt;): the word ends at the first / ? # \, a valid %XX is decoded, then UTS 46 style
    /// mapping (lower case, NFKC, ideographic dots, ignored characters), per-label punycode, and a numeric last label (an IPv4 form) is refused; empty when the
    /// host cannot be encoded.</summary>
    internal static string DomainToAscii(string w)
    {
        if (AdaIdna.TryToAscii(w, out var viaAda)) return viaAda;
        if (!AdaIdna.AllowFallback && AdaIdna.NeedsIdna(w)) return ""; // no UTS 46 library and no opt-in: refuse rather than approximate
        return DomainToAsciiBuiltin(w);
    }

    static string DomainToAsciiBuiltin(string w)
    {
        int cut = w.Length;
        for (int i = 0; i < w.Length; i++) { var c = w[i]; if (c == '/' || c == '?' || c == '#' || c == '\\') { cut = i; break; } }
        var host = w[..cut];
        if (host.Length == 0) return "";
        var decoded = PercentDecode(host);
        var lower = new StringBuilder();
        foreach (var cp in CibaJs.CodePoints(decoded))
        {
            if (IgnoredByIdna(cp)) continue;
            lower.Append(ObjectiveRisk.ToLowerJs(CibaJs.FromCodePoint(cp))); // UTS 46 maps U+0130 to i and a combining dot
        }
        var m = lower.ToString().Normalize(NormalizationForm.FormKC).Replace('。', '.').Replace('．', '.').Replace('｡', '.');
        foreach (var cp in CibaJs.CodePoints(m))
        {
            if (cp < 0x80)
            {
                if (cp <= 0x20 || cp == 0x7f || "#%/:<>?@[\\]^|".IndexOf((char)cp) >= 0) return "";
            }
            else if (!IsLetterOrDigit(cp) && !IsMark(cp)) return "";
        }
        var labels = new List<string>();
        foreach (var label in m.Split('.'))
        {
            bool ascii = label.All(ch => ch < 0x80);
            labels.Add(ascii ? label : "xn--" + Punycode(CibaJs.CodePoints(label)));
        }
        int last = labels.Count - 1;
        if (last > 0 && labels[last].Length == 0) last--;
        var l = labels[last];
        if (DigitsOnly.IsMatch(l) || HexOnly.IsMatch(l)) return "";
        return string.Join(".", labels);
    }

    /// <summary>Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or braced code point escapes when IDNA refuses).</summary>
    public static string AsciiForm(string payee)
    {
        if (AsciiPrintable(payee, true)) return payee;
        var o = new List<string>();
        foreach (var w in payee.Split(' '))
        {
            if (AsciiPrintable(w, true)) { o.Add(w); continue; }
            var a = DomainToAscii(w);
            if (a.Length > 0) { o.Add(a); continue; }
            var sb = new StringBuilder();
            foreach (var cp in CibaJs.CodePoints(w))
            {
                if (cp > 0x7e) sb.Append("\\u{").Append(cp.ToString("x", CultureInfo.InvariantCulture)).Append('}'); else sb.Append(CibaJs.FromCodePoint(cp));
            }
            o.Add(sb.ToString());
        }
        return string.Join(" ", o);
    }

    // ---- the canonical action ----

    /// <summary>Build the canonical action from a step-up: <c>{verb, [amount, currency,] [payee,] resource}</c>. Fails loud: unknown params keys, a nested or
    /// malformed amount, a missing currency or payee next to an amount, two different payee fields, and non-identifier verb / resource all throw.</summary>
    public static D CibaActionFromStepUp(D stepUp)
    {
        var po = stepUp.GetValueOrDefault("params") ?? new D();
        if (po is not D prm) throw Range("ciba: step-up params must be an object");
        var unknown = prm.Keys.Where(k => !DisplayedParamKeys.Contains(k)).ToList();
        if (unknown.Count > 0)
            throw Range("ciba: step-up params field(s) " + string.Join(", ", unknown) + " are not displayed in the approval message (displayable: amount, currency, "
                + string.Join("/", PayeeKeys) + "); refusing so the person never approves a hidden field");
        var verb = Identifier(stepUp.GetValueOrDefault("verb"), "verb");
        var resource = Identifier(stepUp.GetValueOrDefault("resource"), "resource");
        var action = new D { ["verb"] = verb, ["resource"] = resource };
        var payeeKeys = PayeeKeys.Where(k => prm.GetValueOrDefault(k) != null).ToList();
        if (payeeKeys.Count > 1) throw Range("ciba: more than one payee field (" + string.Join(", ", payeeKeys) + ") in params; the approver would see only one");
        if (prm.GetValueOrDefault("amount") is { } amt)
        {
            double? d = amt is bool ? null : GnapJs.NumOf(amt);
            var text = d is double dd && double.IsFinite(dd) ? CibaJs.JsNumber(dd) : amt is string sa ? sa : "";
            if (!PlainAmount.IsMatch(text)) throw Range("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)");
            if (prm.GetValueOrDefault("currency") is not string cur || !CurrencyRe.IsMatch(cur)) throw Range("ciba: the binding message needs a 3-letter currency code next to the amount");
            if (payeeKeys.Count == 0) throw Range("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it");
            action["amount"] = text;
            action["currency"] = cur.ToUpperInvariant();
        }
        else if (prm.GetValueOrDefault("currency") != null)
        {
            throw Range("ciba: a currency without an amount cannot be displayed");
        }
        if (payeeKeys.Count == 1)
        {
            var o = new D { ["verb"] = action["verb"] };
            if (action.ContainsKey("amount")) { o["amount"] = action["amount"]; o["currency"] = action["currency"]; }
            o["payee"] = PayeeText(prm.GetValueOrDefault(payeeKeys[0]));
            o["resource"] = action["resource"];
            return o;
        }
        return action;
    }

    // ---- the binding message ----

    static string BindingMessage(D stepUp, string actsFor, double? maxChars)
    {
        var a = CibaActionFromStepUp(stepUp);
        var head = new StringBuilder("Approve ").Append(a["verb"]);
        if (a.ContainsKey("amount")) head.Append(' ').Append(a["amount"]).Append(' ').Append(a["currency"]);
        if (a.ContainsKey("payee"))
        {
            var p = (string)a["payee"]!;
            head.Append(" to \"").Append(p).Append('"');
            if (!AsciiPrintable(p, true)) head.Append(" [non-ASCII name; ASCII form: ").Append(AsciiForm(p)).Append(']');
        }
        head.Append(" on ").Append(a["resource"]);
        double limit = maxChars ?? double.PositiveInfinity;
        var h = head.ToString();
        if (CpLen(h) > limit)
            throw Range("ciba: the binding message needs " + CpLen(h) + " characters but bindingMessage.maxChars is " + CibaJs.JsNumber(maxChars ?? double.NaN) + "; refusing to truncate what the person approves");
        var plainGoal = "";
        if (stepUp.ContainsKey("goal"))
        {
            if (stepUp["goal"] is not string g) throw Range("ciba: the step-up goal must be a string");
            plainGoal = PlainText(g).Replace('\'', '′').Replace('‘', '′').Replace('’', '′');
        }
        string? goalText;
        if (plainGoal.Length > 0) goalText = Clip(plainGoal, MaxGoalChars);
        else
        {
            var gc = stepUp.GetValueOrDefault("goalCommit") ?? throw Range("ciba: the step-up goalCommit is required");
            var s = gc as string ?? "";
            goalText = s.Length > 0 ? "goal " + s[..Math.Min(10, s.Length)] + "…" : null;
        }
        if (goalText == null) return h;
        var prefix = " — because you asked " + actsFor + " to '";
        double room = limit - CpLen(h + prefix) - 1;
        if (room >= CpLen(goalText)) return h + prefix + goalText + "'";
        if (room >= 8) return h + prefix + Clip(goalText, room) + "'";
        return h;
    }

    static string Tokenise(string value)
    {
        var t = Regex.Replace(value, "[^A-Za-z0-9._-]+", "-", Ro);
        t = Regex.Replace(t, "-{2,}", "-", Ro);
        return Regex.Replace(t, @"\A[-.]+|[-.]+\z", "", Ro);
    }

    static string CompactBindingMessage(D stepUp, double maxChars)
    {
        var a = CibaActionFromStepUp(stepUp);
        if (a.ContainsKey("payee") && !AsciiPrintable((string)a["payee"]!, false))
            throw Range("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)");
        var parts = new List<string> { "Approve", (string)a["verb"]! };
        if (a.ContainsKey("amount")) { parts.Add((string)a["amount"]!); parts.Add((string)a["currency"]!); }
        if (a.ContainsKey("payee")) { parts.Add("to"); parts.Add((string)a["payee"]!); }
        parts.Add((string)a["resource"]!);
        var toks = parts.Select(Tokenise).ToList();
        if (toks.Any(p => p.Length == 0)) throw Range("ciba: tokenOnly binding message cannot represent the verb, payee or resource");
        var o = string.Join("-", toks);
        if (o.Length > maxChars)
            throw Range("ciba: the binding message needs " + o.Length + " characters but bindingMessage.maxChars is " + CibaJs.JsNumber(maxChars) + "; refusing to truncate what the person approves");
        return o;
    }

    // ---- the request ----

    /// <summary>Map a PCA step-up to a CIBA auth request: <c>{auth_req_id, binding_message, scope, requested_expiry, interval, [login_hint,] stepUpId, tier,
    /// [authorization_details, render_digest]}</c>. Pure: derives a stable <c>auth_req_id</c> from the step-up id unless <c>opts.authReqId</c> is given, renders the
    /// binding message, and carries the scope, expiry and poll interval.</summary>
    public static D ToCibaAuthRequest(D stepUp, D? opts = null)
    {
        var o = opts ?? new D();
        var actsFor = "your agent";
        if (o.ContainsKey("actsFor"))
        {
            if (o["actsFor"] is not string af) throw Range("ciba: actsFor must be a string");
            var pt = PlainText(af);
            if (pt.Length > 0) actsFor = Clip(pt, 40);
        }
        var requestedExpiry = o.ContainsKey("expiresInSec") ? o["expiresInSec"] : new Num(DefaultExpirySec.ToString(CultureInfo.InvariantCulture));
        if (!CibaJs.IsSafeInteger(requestedExpiry) || GnapJs.NumOf(requestedExpiry)! <= 0)
            throw Range("ciba: requested_expiry must be a positive integer number of seconds, got " + GnapJs.Str(requestedExpiry));
        var stepUpScope = "urn:atlas:pca:stepup:" + GnapJs.Str(GnapJs.Get(stepUp, "verb"));
        foreach (var c in stepUpScope)
            if (!(c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e))) throw Range("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)");
        var scope = o.GetValueOrDefault("stepUpScope") is false ? "openid" : "openid " + stepUpScope;
        var interval = o.ContainsKey("interval") ? o["interval"] : new Num(DefaultIntervalSec.ToString(CultureInfo.InvariantCulture));
        if (!CibaJs.IsSafeInteger(interval) || GnapJs.NumOf(interval)! <= 0)
            throw Range("ciba: interval must be a positive integer number of seconds, got " + GnapJs.Str(interval));
        var idO = o.GetValueOrDefault("authReqId");
        if (idO == null && !stepUp.ContainsKey("id")) throw Range("ciba: the step-up has no id to derive the auth_req_id from");
        object authReqId = idO ?? Pca.HashCanonical(new D { ["d"] = "atlas-pca/ciba/auth_req_id/v1", ["stepUp"] = stepUp.GetValueOrDefault("id") });
        // the reference tests the text of any value with the pattern, and a value without a length (a number) passes both length comparisons
        int? idLen = authReqId is string idS ? idS.Length : authReqId is L idL ? idL.Count : null;
        if (!AuthReqIdRe.IsMatch(GnapJs.Str(authReqId)) || idLen < MinAuthReqIdLen || idLen > 1024)
            throw Range("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)");
        var bm = o.GetValueOrDefault("bindingMessage") as D;
        bool hasMax = bm != null && bm.ContainsKey("maxChars");
        var bmMax = hasMax ? bm!["maxChars"] : null;
        if (hasMax && (!CibaJs.IsSafeInteger(bmMax) || GnapJs.NumOf(bmMax)! < 1)) throw Range("ciba: bindingMessage.maxChars must be a positive integer");
        double maxChars = hasMax && bmMax != null ? GnapJs.NumOf(bmMax)!.Value : 50;
        string? words = null;
        var render = stepUp.GetValueOrDefault("render"); var renderDigest = stepUp.GetValueOrDefault("renderDigest");
        if (stepUp.ContainsKey("render") || stepUp.ContainsKey("renderDigest"))
        {
            if (!stepUp.ContainsKey("render") || !stepUp.ContainsKey("renderDigest") || Approval.RenderDigest(render) != renderDigest as string)
                throw Range("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else");
            words = Approval.BindingWords(renderDigest);
        }
        int reserve = words == null ? 0 : words.Length + 14;
        bool tokenOnly = bm != null && bm.GetValueOrDefault("tokenOnly") is true;
        var bindingMessage = tokenOnly ? CompactBindingMessage(stepUp, maxChars - reserve)
            : BindingMessage(stepUp, actsFor, hasMax ? GnapJs.NumOf(bmMax)!.Value - reserve : null);
        if (words != null) bindingMessage = tokenOnly ? bindingMessage + "-match-" + words : bindingMessage + " [match code " + words + "]";
        var outp = new D { ["auth_req_id"] = authReqId, ["binding_message"] = bindingMessage, ["scope"] = scope, ["requested_expiry"] = requestedExpiry, ["interval"] = interval };
        if (o.ContainsKey("loginHint")) outp["login_hint"] = o["loginHint"];
        outp["stepUpId"] = stepUp.GetValueOrDefault("id");
        if (stepUp.ContainsKey("tier")) outp["tier"] = stepUp["tier"]; // an absent member stays absent
        if (stepUp.ContainsKey("render") && stepUp.ContainsKey("renderDigest"))
        {
            outp["authorization_details"] = new L { new D { ["type"] = "pca_approval", ["render"] = render, ["render_digest"] = renderDigest } };
            outp["render_digest"] = renderDigest;
        }
        return outp;
    }

    // ---- gating and the hand-off to the cosign ----

    /// <summary>The gate: does this review need a CIBA human-approval round-trip? Only a tier-3 step-up does (tier-2 is the guardian's auto-cosign).</summary>
    public static bool RequiresCiba(object? review)
    {
        if (review == null) throw new ArgumentException("ciba: review is null");
        if (GnapJs.Member(review, "kind") is not "step_up") return false;
        var req = GnapJs.Member(review, "request") ?? throw new ArgumentException("ciba: the step_up review has no request");
        return GnapJs.NumOf(GnapJs.Member(req, "tier")) is 3.0;
    }

    static double Nz(object? x) => GnapJs.NumOf(x) is double d && double.IsFinite(d) && d > 0 ? d : 0;

    /// <summary>Fold a settled CIBA decision into PCA's trust budget <c>{B, tau, asOf?}</c>: on <c>approve</c>, recharge (partial rho per cosign, or full with
    /// <c>opts.full</c>); on anything else the budget is unchanged. Returns <c>{budget, cosigned}</c>. This is the BUDGET-level effect only: the cryptographic
    /// cosign that authorises a tier-3 action is a FROST threshold signature verified by the resource server.</summary>
    public static D CibaDecisionToCosign(object? decision, D budget, D policy, object? now, D? opts = null)
    {
        if (decision is not "approve") return new D { ["budget"] = budget, ["cosigned"] = false };
        bool full = opts != null && GnapJs.Truthy(opts.GetValueOrDefault("full"));
        double bMax = Nz(policy.GetValueOrDefault("bMax"));
        double b = full ? bMax : Math.Min(bMax, (GnapJs.NumOf(budget.GetValueOrDefault("B")) ?? throw new ArgumentException("ciba: budget.B is not a number")) + Nz(policy.GetValueOrDefault("rho")));
        return new D { ["budget"] = new D { ["B"] = b, ["tau"] = now, ["asOf"] = now }, ["cosigned"] = true };
    }
}
