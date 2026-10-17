// The linear-time, budgeted regular-expression matcher of the predicate DSL (`re:` resources and the `matches` operator), a
// port of packages/pca/src/safe-regex.ts and regex-budget.ts (mirrors SafeRegex.java / SafeRegex.kt). A pattern is parsed
// ONCE into a Thompson NFA and run by a Pike-style simulation: O(|subject| x |NFA|), no backtracking. Anything outside the
// subset is refused (fail closed). Matching is over UTF-16 code units, exactly like a flagless JS RegExp.
using System.Text.RegularExpressions;

namespace AtlasPca;

public static class SafeRegex
{
    public const int MaxNfaInstructions = 4096;
    public const int MaxRepeat = 64;
    public const long MaxMatchSteps = 2_000_000L;
    public const int MaxRegexEvaluationsPerDocument = 64;
    public const int MaxRegexSourceCharsPerDocument = 8192;
    public const long MaxRegexStepsPerDocument = 5_000_000L;

    const int OpSet = 0, OpSplit = 1, OpJmp = 2, OpBol = 3, OpEol = 4, OpMatch = 5;

    /// <summary>A set of UTF-16 code units: sorted, merged ranges, optionally negated.</summary>
    internal sealed class CharSet
    {
        internal readonly int[][] Ranges;
        internal readonly bool Negated;
        internal CharSet(int[][] ranges, bool negated) { Ranges = ranges; Negated = negated; }
        internal bool Has(int c)
        {
            int lo = 0, hi = Ranges.Length - 1;
            bool inside = false;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                var r = Ranges[mid];
                if (c < r[0]) hi = mid - 1;
                else if (c > r[1]) lo = mid + 1;
                else { inside = true; break; }
            }
            return inside != Negated;
        }
    }

    static readonly int[][] Digit = { new[] { 0x30, 0x39 } };
    static readonly int[][] Word = { new[] { 0x30, 0x39 }, new[] { 0x41, 0x5a }, new[] { 0x5f, 0x5f }, new[] { 0x61, 0x7a } };
    static readonly int[][] Space = { new[] { 0x09, 0x0d }, new[] { 0x20, 0x20 }, new[] { 0xa0, 0xa0 }, new[] { 0x1680, 0x1680 }, new[] { 0x2000, 0x200a },
        new[] { 0x2028, 0x2029 }, new[] { 0x202f, 0x202f }, new[] { 0x205f, 0x205f }, new[] { 0x3000, 0x3000 }, new[] { 0xfeff, 0xfeff } };
    static readonly int[][] LineTerminators = { new[] { 0x0a, 0x0a }, new[] { 0x0d, 0x0d }, new[] { 0x2028, 0x2029 } };

    static int[][] Normalize(IEnumerable<int[]> input)
    {
        var s = input.Select(r => new[] { r[0], r[1] }).OrderBy(r => r[0]).ToList();
        var output = new List<int[]>();
        foreach (var r in s)
        {
            var last = output.Count > 0 ? output[^1] : null;
            if (last != null && r[0] <= last[1] + 1) last[1] = Math.Max(last[1], r[1]);
            else output.Add(new[] { r[0], r[1] });
        }
        return output.ToArray();
    }

    static int[][] Complement(int[][] r)
    {
        var output = new List<int[]>();
        int next = 0;
        foreach (var ab in Normalize(r))
        {
            if (ab[0] > next) output.Add(new[] { next, ab[0] - 1 });
            next = ab[1] + 1;
        }
        if (next <= 0xffff) output.Add(new[] { next, 0xffff });
        return output.ToArray();
    }

    sealed class Node
    {
        internal readonly char K; // 's' set, '^' bol, '$' eol, 'c' cat, 'a' alt, 'r' rep
        internal CharSet? Set;
        internal List<Node>? Items;
        internal Node? Child;
        internal int Min;
        internal double Max; // +Infinity for unbounded
        internal Node(char k) { K = k; }
    }

    sealed class Refuse : Exception { internal Refuse(string m) : base(m) { } }

    static readonly Regex Quant = new(@"^\{([0-9]{1,4})(?:(,)([0-9]{0,4}))?\}", RegexOptions.CultureInvariant);

    sealed record Esc(CharSet Set, bool Cls, int Ch);

    sealed class Parser
    {
        readonly string s;
        int i;
        internal Parser(string s) { this.s = s; }
        int At(int k) => k < s.Length ? s[k] : -1;

        internal Node Parse()
        {
            var n = Alt();
            if (i < s.Length) throw new Refuse("unbalanced )");
            return n;
        }

        Node Alt()
        {
            var items = new List<Node> { Cat() };
            while (At(i) == '|') { i++; items.Add(Cat()); }
            return items.Count == 1 ? items[0] : new Node('a') { Items = items };
        }

        Node Cat()
        {
            var items = new List<Node>();
            while (i < s.Length && s[i] != '|' && s[i] != ')') items.Add(Quantified());
            return new Node('c') { Items = items };
        }

        Node Quantified()
        {
            var atom = Atom();
            int c = At(i);
            int min;
            double max;
            if (c == '*') { min = 0; max = double.PositiveInfinity; i++; }
            else if (c == '+') { min = 1; max = double.PositiveInfinity; i++; }
            else if (c == '?') { min = 0; max = 1; i++; }
            else if (c == '{')
            {
                var m = Quant.Match(s.Substring(i, Math.Min(s.Length, i + 16) - i));
                if (!m.Success) throw new Refuse("{ is not a well-formed quantifier");
                min = int.Parse(m.Groups[1].Value);
                max = !m.Groups[2].Success ? min : m.Groups[3].Value.Length == 0 ? double.PositiveInfinity : int.Parse(m.Groups[3].Value);
                if (max < min) throw new Refuse("quantifier range out of order");
                i += m.Value.Length;
            }
            else return atom;
            if (atom.K == '^' || atom.K == '$') throw new Refuse("nothing to repeat (assertion)");
            if ((!double.IsPositiveInfinity(max) && max > MaxRepeat) || min > MaxRepeat) throw new Refuse("repeat bound too large");
            if (At(i) == '?') i++;
            return new Node('r') { Child = atom, Min = min, Max = max };
        }

        static Node SetNode(CharSet cs) => new('s') { Set = cs };

        Node Atom()
        {
            char c = s[i];
            switch (c)
            {
                case '(':
                    {
                        i++;
                        if (At(i) == '?')
                        {
                            if (At(i + 1) != ':') throw new Refuse("lookaround / named groups are not supported");
                            i += 2;
                        }
                        var n = Alt();
                        if (At(i) != ')') throw new Refuse("unterminated group");
                        i++;
                        return n;
                    }
                case '[': return Cls();
                case '.': i++; return SetNode(new CharSet(LineTerminators, true));
                case '^': i++; return new Node('^');
                case '$': i++; return new Node('$');
                case '\\': return SetNode(EscapeInner(false).Set);
                case '*': case '+': case '?': throw new Refuse("nothing to repeat");
                case '{': throw new Refuse("{ is not a well-formed quantifier");
                default:
                    i++;
                    return SetNode(new CharSet(new[] { new int[] { c, c } }, false));
            }
        }

        static Esc Single(int code) => new(new CharSet(new[] { new[] { code, code } }, false), false, code);

        static bool IsHex(string s, int from, int n)
        {
            for (int k = from; k < from + n; k++)
            {
                char ch = s[k];
                if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
            }
            return true;
        }

        Esc EscapeInner(bool inClass)
        {
            i++;
            int c = At(i);
            if (c < 0) throw new Refuse("trailing backslash");
            i++;
            switch (c)
            {
                case 'd': return new(new CharSet(Digit, false), true, -1);
                case 'D': return new(new CharSet(Digit, true), true, -1);
                case 'w': return new(new CharSet(Word, false), true, -1);
                case 'W': return new(new CharSet(Word, true), true, -1);
                case 's': return new(new CharSet(Space, false), true, -1);
                case 'S': return new(new CharSet(Space, true), true, -1);
                case 't': return Single(9);
                case 'n': return Single(10);
                case 'v': return Single(11);
                case 'f': return Single(12);
                case 'r': return Single(13);
                case '0':
                    {
                        int n = At(i);
                        if (n >= '0' && n <= '9') throw new Refuse("octal escape");
                        return Single(0);
                    }
                case 'x':
                    {
                        if (i + 2 > s.Length || !IsHex(s, i, 2)) throw new Refuse("bad \\x escape");
                        int v = Convert.ToInt32(s.Substring(i, 2), 16);
                        i += 2;
                        return Single(v);
                    }
                case 'u':
                    {
                        if (i + 4 > s.Length || !IsHex(s, i, 4)) throw new Refuse("bad \\u escape");
                        int v = Convert.ToInt32(s.Substring(i, 4), 16);
                        i += 4;
                        return Single(v);
                    }
                case 'c':
                    {
                        int l = At(i);
                        if (!((l >= 'A' && l <= 'Z') || (l >= 'a' && l <= 'z'))) throw new Refuse("bad \\c escape");
                        i++;
                        return Single(l % 32);
                    }
                case 'b':
                    if (inClass) return Single(8);
                    throw new Refuse("word-boundary assertions are not supported");
                default:
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')
                        throw new Refuse("escape is not supported");
                    return Single(c);
            }
        }

        Node Cls()
        {
            i++;
            bool negated = false;
            if (At(i) == '^') { negated = true; i++; }
            var ranges = new List<int[]>();
            while (true)
            {
                int c = At(i);
                if (c < 0) throw new Refuse("unterminated class");
                if (c == ']') { i++; break; }
                var a = ReadAtom();
                if (At(i) == '-' && At(i + 1) >= 0 && At(i + 1) != ']')
                {
                    i++;
                    var b = ReadAtom();
                    if (a.Cls || b.Cls)
                    {
                        foreach (var r in a.Set.Ranges) ranges.Add(new[] { r[0], r[1] });
                        ranges.Add(new[] { 0x2d, 0x2d });
                        foreach (var r in b.Set.Ranges) ranges.Add(new[] { r[0], r[1] });
                    }
                    else
                    {
                        if (a.Ch > b.Ch) throw new Refuse("class range out of order");
                        ranges.Add(new[] { a.Ch, b.Ch });
                    }
                }
                else foreach (var r in a.Set.Ranges) ranges.Add(new[] { r[0], r[1] });
            }
            return new Node('s') { Set = new CharSet(Normalize(ranges), negated) };
        }

        /// <summary>A class atom; its set holds plain (already complemented) ranges.</summary>
        Esc ReadAtom()
        {
            int c = s[i];
            if (c == '\\')
            {
                var e = EscapeInner(true);
                var rs = e.Set.Negated ? Complement(e.Set.Ranges) : e.Set.Ranges;
                return new Esc(new CharSet(rs, false), e.Cls, e.Ch);
            }
            i++;
            return new Esc(new CharSet(new[] { new[] { c, c } }, false), false, c);
        }
    }

    internal sealed class Inst
    {
        internal readonly int Op;
        internal int X, Y;
        internal readonly CharSet? Set;
        internal Inst(int op, int x, int y, CharSet? set) { Op = op; X = x; Y = y; Set = set; }
    }

    /// <summary>A compiled NFA program.</summary>
    public sealed class Compiled
    {
        internal readonly Inst[] Program;
        internal Compiled(Inst[] program) { Program = program; }
        public int Size => Program.Length;
    }

    static void Emit(Node node, List<Inst> prog)
    {
        if (prog.Count > MaxNfaInstructions) throw new Refuse("pattern too large");
        switch (node.K)
        {
            case 's': prog.Add(new Inst(OpSet, 0, 0, node.Set)); return;
            case '^': prog.Add(new Inst(OpBol, 0, 0, null)); return;
            case '$': prog.Add(new Inst(OpEol, 0, 0, null)); return;
            case 'c': foreach (var it in node.Items!) Emit(it, prog); return;
            case 'a':
                {
                    var jmps = new List<int>();
                    for (int i = 0; i < node.Items!.Count; i++)
                    {
                        if (i < node.Items.Count - 1)
                        {
                            int split = prog.Count;
                            prog.Add(new Inst(OpSplit, split + 1, -1, null));
                            Emit(node.Items[i], prog);
                            jmps.Add(prog.Count);
                            prog.Add(new Inst(OpJmp, -1, 0, null));
                            prog[split].Y = prog.Count;
                        }
                        else Emit(node.Items[i], prog);
                    }
                    foreach (var j in jmps) prog[j].X = prog.Count;
                    return;
                }
            default:
                {
                    for (int i = 0; i < node.Min; i++) Emit(node.Child!, prog);
                    if (double.IsPositiveInfinity(node.Max))
                    {
                        int split = prog.Count;
                        prog.Add(new Inst(OpSplit, split + 1, -1, null));
                        Emit(node.Child!, prog);
                        prog.Add(new Inst(OpJmp, split, 0, null));
                        prog[split].Y = prog.Count;
                    }
                    else
                    {
                        var splits = new List<int>();
                        for (int i = node.Min; i < node.Max; i++)
                        {
                            splits.Add(prog.Count);
                            prog.Add(new Inst(OpSplit, prog.Count + 1, -1, null));
                            Emit(node.Child!, prog);
                        }
                        foreach (var sp in splits) prog[sp].Y = prog.Count;
                    }
                    if (prog.Count > MaxNfaInstructions) throw new Refuse("pattern too large");
                    return;
                }
        }
    }

    /// <summary>Compile <paramref name="src"/>, or null when it is outside the subset or too large. Never throws.</summary>
    public static Compiled? Compile(string? src)
    {
        try
        {
            if (src == null) return null;
            var ast = new Parser(src).Parse();
            var prog = new List<Inst>();
            Emit(ast, prog);
            prog.Add(new Inst(OpMatch, 0, 0, null));
            if (prog.Count > MaxNfaInstructions) return null;
            return new Compiled(prog.ToArray());
        }
        catch (Exception) { return null; }
    }

    /// <summary>Full-match <paramref name="subject"/>: true / false, or null when the work budget would be exceeded.</summary>
    public static bool? Run(Compiled re, string subject)
    {
        var prog = re.Program;
        int n = subject.Length;
        if ((long)prog.Length * (n + 1) > MaxMatchSteps) return null;
        var clist = new int[prog.Length];
        var nlist = new int[prog.Length];
        var mark = Enumerable.Repeat(-1, prog.Length).ToArray();
        var stack = new int[prog.Length * 2 + 2];
        int gen = 0;
        bool matched = false;

        int Add(int[] list, int count, int pc0, int pos)
        {
            int sp = 0;
            stack[sp++] = pc0;
            while (sp > 0)
            {
                int pc = stack[--sp];
                if (mark[pc] == gen) continue;
                mark[pc] = gen;
                var ins = prog[pc];
                switch (ins.Op)
                {
                    case OpJmp: stack[sp++] = ins.X; break;
                    case OpSplit: stack[sp++] = ins.Y; stack[sp++] = ins.X; break;
                    case OpBol: if (pos == 0) stack[sp++] = pc + 1; break;
                    case OpEol: if (pos == n) stack[sp++] = pc + 1; break;
                    case OpMatch: if (pos == n) matched = true; break;
                    default: list[count++] = pc; break;
                }
            }
            return count;
        }

        gen++;
        int cn = Add(clist, 0, 0, 0);
        for (int pos = 0; pos < n; pos++)
        {
            int c = subject[pos];
            gen++;
            int nn = 0;
            for (int k = 0; k < cn; k++)
            {
                int pc = clist[k];
                if (prog[pc].Set!.Has(c)) nn = Add(nlist, nn, pc + 1, pos + 1);
            }
            (clist, nlist) = (nlist, clist);
            cn = nn;
            if (cn == 0 && !matched) return false;
        }
        return matched;
    }

    /// <summary><c>new RegExp('^(?:' + src + ')$').test(subject)</c> over the subset; null when refused or over budget.</summary>
    public static bool? FullMatch(string src, string subject)
    {
        var re = Compile(src);
        return re == null ? null : Run(re, subject);
    }

    // ---- the safe-source guard (predicates.ts isSafeRegexSource) ----
    const int MaxRegexCostBits = 22;
    const int UnboundedQuantifierBits = 8;
    const int MaxBoundedRepeat = 64;
    static readonly Regex GuardQuant = new(@"^\{([0-9]+)(?:(,)([0-9]*))?\}", RegexOptions.CultureInvariant);

    sealed class Frame { internal bool HasQuant, HasAlt; }

    /// <summary>The linear-time-safe subset guard: no quantified group containing a quantifier or an alternation, no
    /// backreferences / lookaround / named groups, bounded repeats at most 64, a 22-bit backtracking-cost budget, and the
    /// source must compile in <see cref="Compile"/>.</summary>
    public static bool IsSafeSource(string? src)
    {
        if (src == null) return false;
        var stack = new List<Frame> { new() };
        object? prev = null; // null = none, true = atom, Frame = a closed group
        int bits = 0;
        int i = 0;
        while (i < src.Length)
        {
            char ch = src[i];
            if (ch == '\\')
            {
                if (i + 1 >= src.Length) return false;
                char n = src[i + 1];
                if ((n >= '1' && n <= '9') || n == 'k') return false;
                i += 2;
                prev = true;
                continue;
            }
            if (ch == '[')
            {
                int j = i + 1;
                if (j < src.Length && src[j] == '^') j++;
                for (; j < src.Length && src[j] != ']'; j++) if (src[j] == '\\') j++;
                if (j >= src.Length) return false;
                i = j + 1;
                prev = true;
                continue;
            }
            if (ch == '(')
            {
                if (i + 1 < src.Length && src[i + 1] == '?')
                {
                    if (!(i + 2 < src.Length && src[i + 2] == ':')) return false;
                    i += 3;
                }
                else i += 1;
                stack.Add(new Frame());
                prev = null;
                continue;
            }
            if (ch == ')')
            {
                if (stack.Count < 2) return false;
                var f = stack[^1];
                stack.RemoveAt(stack.Count - 1);
                var parent = stack[^1];
                parent.HasQuant |= f.HasQuant;
                parent.HasAlt |= f.HasAlt;
                prev = f;
                i++;
                continue;
            }
            if (ch == '|')
            {
                if (++bits > MaxRegexCostBits) return false;
                stack[^1].HasAlt = true;
                prev = null;
                i++;
                continue;
            }
            bool isQ = false, unbounded = false;
            int len = 0;
            double max = 0, options = 0;
            if (ch == '*' || ch == '+') { isQ = true; len = 1; unbounded = true; max = double.PositiveInfinity; options = double.PositiveInfinity; }
            else if (ch == '?') { isQ = true; len = 1; max = 1; options = 2; }
            else if (ch == '{')
            {
                var m = GuardQuant.Match(src.Substring(i));
                if (!m.Success) return false;
                double lo = double.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
                bool hasComma = m.Groups[2].Success;
                double hi = !hasComma ? lo : m.Groups[3].Value.Length == 0 ? double.PositiveInfinity : double.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture);
                if (hi < lo) return false;
                isQ = true;
                len = m.Value.Length;
                unbounded = double.IsPositiveInfinity(hi);
                max = hi;
                options = double.IsPositiveInfinity(hi) ? double.PositiveInfinity : hi - lo + 1;
            }
            if (isQ)
            {
                if (prev == null) return false;
                if (prev is Frame pf && (pf.HasQuant || pf.HasAlt)) return false;
                if (!unbounded && !double.IsPositiveInfinity(max) && max > MaxBoundedRepeat) return false;
                bits += unbounded ? UnboundedQuantifierBits : options > 1 ? CeilLog2((long)options) : 0;
                if (bits > MaxRegexCostBits) return false;
                stack[^1].HasQuant = true;
                i += len;
                if (i < src.Length && src[i] == '?') i++;
                prev = null;
                continue;
            }
            i++;
            prev = true;
        }
        return stack.Count == 1 && Compile(src) != null;
    }

    /// <summary><c>Math.ceil(Math.log2(n))</c> for an integer n &gt;= 2, computed exactly.</summary>
    internal static int CeilLog2(long n) => 64 - System.Numerics.BitOperations.LeadingZeroCount((ulong)(n - 1));

    // ---- per-document budget (regex-budget.ts) ----
    sealed class Budget
    {
        int evaluations, chars;
        long steps;

        internal bool Charge(string src, int subjectLen)
        {
            var c = Compile(src);
            if (c == null) return false;
            int ev = evaluations + 1;
            int ch = chars + src.Length;
            long st = steps + (long)c.Size * (subjectLen + 1);
            if (ev > MaxRegexEvaluationsPerDocument || ch > MaxRegexSourceCharsPerDocument || st > MaxRegexStepsPerDocument)
            {
                evaluations = MaxRegexEvaluationsPerDocument + 1; // poison: order-independent refusal
                return false;
            }
            evaluations = ev;
            chars = ch;
            steps = st;
            return true;
        }
    }

    [ThreadStatic] static Budget? current;

    /// <summary>Run <paramref name="fn"/> inside the open document budget, or a fresh one when none is open (withRegexBudget).</summary>
    internal static T WithBudget<T>(Func<T> fn)
    {
        if (current != null) return fn();
        current = new Budget();
        try { return fn(); }
        finally { current = null; }
    }

    /// <summary>Charge one evaluation of <paramref name="src"/> against a subject of <paramref name="subjectLen"/> code units.</summary>
    internal static bool Charge(string src, int subjectLen) => (current ?? new Budget()).Charge(src, subjectLen);
}
