using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;

/// <summary>The extracted goal kernel is not compiled into this assembly (or lacks the expected entry points).</summary>
public sealed class GoalKernelUnavailable : Exception
{
    public GoalKernelUnavailable(Exception? cause)
        : base("pca-goal: the extracted goal kernel is missing (formal/dafny/build-native.sh cs writes AtlasPca/GoalKernel/Generated): " + cause?.Message, cause) { }
}

/// <summary>
/// The proved goal kernel: Typecheck, CompileGoal, DecideGoal, DecidePolicy and RenderTape run the Dafny-proved goal compiler
/// (formal/dafny/Goal.dfy), translated to C# with the pinned Dafny by formal/dafny/build-native.sh cs into GoalKernel/Generated
/// (compiled into this assembly). There is no decision logic here: token tapes are converted to the translation's tokens and back,
/// and no Dafny value crosses this boundary. The translation is bound by type name at first use, so the assembly builds before CI
/// has committed it; until then every call throws <see cref="GoalKernelUnavailable"/> (there is no fallback).
/// <see cref="ProvedKernel"/> plugs it into <see cref="GoalReview"/>.
/// </summary>
public static class GoalKernel
{
    const long MAX_SAFE = 9007199254740991L;

    sealed class Gen
    {
        public readonly MethodInfo MkKw, MkI, MkS, TokKind, TokKw, TokInt, TokStr, Typecheck, Compile, DecideG, DecideP, Render, Unicode, FromArray;
        public readonly Type TokType;

        public Gen()
        {
            var asm = typeof(GoalKernel).Assembly;
            var api = asm.GetType("GoalApi.__default", true)!;
            MkKw = St(api, "MkKw", 1); MkI = St(api, "MkI", 1); MkS = St(api, "MkS", 1);
            TokKind = St(api, "TokKind", 1); TokKw = St(api, "TokKw", 1); TokInt = St(api, "TokInt", 1); TokStr = St(api, "TokStr", 1);
            Typecheck = St(api, "TypecheckT", 2); Compile = St(api, "CompileT", 2); Render = St(api, "RenderT", 1);
            DecideG = St(api, "DecideGoalT", 4); DecideP = St(api, "DecidePolicyT", 4);
            // ISequence<_ITok> and ISequence<Rune>: the element types come from the entry points' own signatures
            TokType = Typecheck.GetParameters()[0].ParameterType.GetGenericArguments()[0];
            var runeType = MkS.GetParameters()[0].ParameterType.GetGenericArguments()[0];
            var seq = asm.GetType("Dafny.Sequence`1", true)!;
            Unicode = St(seq.MakeGenericType(runeType), "UnicodeFromString", 1);
            FromArray = St(seq.MakeGenericType(TokType), "FromArray", 1);
        }

        static MethodInfo St(Type t, string name, int arity) =>
            t.GetMethods(BindingFlags.Public | BindingFlags.Static).FirstOrDefault(m => m.Name == name && m.GetParameters().Length == arity)
            ?? throw new MissingMethodException(t.FullName, name + "/" + arity);
    }

    static readonly Lazy<Gen> G0 = new(() =>
    {
        try { return new Gen(); }
        catch (Exception e) when (e is TypeLoadException or MissingMethodException or ArgumentException or IndexOutOfRangeException) { throw new GoalKernelUnavailable(e); }
    }, LazyThreadSafetyMode.ExecutionAndPublication);

    static Gen Load()
    {
        try { return G0.Value; }
        catch (GoalKernelUnavailable) { throw; }
        catch (Exception e) { throw new GoalKernelUnavailable(e); }
    }

    /// <summary>Whether the extracted kernel is compiled in.</summary>
    public static bool Available()
    {
        try { Load(); return true; } catch (GoalKernelUnavailable) { return false; }
    }

    static object? Inv(MethodInfo m, params object?[] args)
    {
        try { return m.Invoke(null, args); }
        catch (TargetInvocationException e) when (e.InnerException != null) { throw new InvalidOperationException("pca-goal: goal kernel failed: " + e.InnerException.Message, e.InnerException); }
    }

    static long Safe(object? v)
    {
        long? n = G.safeInt(v);
        if (n == null || Math.Abs(n.Value) > MAX_SAFE) throw new IrError("goal tape: " + v + " is not a safe integer");
        return n.Value;
    }

    static object ToDafny(L? tape)
    {
        var g = Load();
        tape ??= new L();
        var arr = Array.CreateInstance(g.TokType, tape.Count);
        for (int i = 0; i < tape.Count; i++)
        {
            if (tape[i] is not L t || t.Count != 2) throw new IrError("goal tape: token expected");
            object? tok = (t[0] as string) switch
            {
                "k" => Inv(g.MkKw, new BigInteger(Safe(t[1]))),
                "i" => Inv(g.MkI, new BigInteger(Safe(t[1]))),
                "s" => t[1] is string s ? Inv(g.MkS, Inv(g.Unicode, s)) : throw new IrError("goal tape: string token expected"),
                _ => throw new IrError("goal tape: unknown token tag " + t[0]),
            };
            arr.SetValue(tok, i);
        }
        return Inv(g.FromArray, arr)!;
    }

    static long Big(object? o) =>
        o is BigInteger b && b >= long.MinValue && b <= long.MaxValue ? (long)b : throw new IrError("malformed compiler output");

    static L Tok(string tag, object? v) => new() { tag, v };

    static System.Collections.IEnumerable Elements(object seq)
    {
        var p = seq.GetType().GetProperty("Elements") ?? seq.GetType().GetInterfaces().Select(i => i.GetProperty("Elements")).FirstOrDefault(x => x != null);
        if (p?.GetValue(seq) is System.Collections.IEnumerable e) return e;
        if (seq is System.Collections.IEnumerable direct) return direct;
        throw new GoalKernelUnavailable(new MissingMemberException(seq.GetType().FullName, "Elements"));
    }

    // a Dafny.Rune: its code point (Value), else its text
    static string CodePointText(object c) =>
        c.GetType().GetProperty("Value")?.GetValue(c) is { } v ? char.ConvertFromUtf32(Convert.ToInt32(v, CultureInfo.InvariantCulture)) : c.ToString() ?? "";

    static L FromDafny(object? seq)
    {
        var g = Load();
        var outp = new L();
        foreach (var t in Elements(seq!))
        {
            long kind = Big(Inv(g.TokKind, t));
            if (kind == 0) outp.Add(Tok("k", G.num(Big(Inv(g.TokKw, t)))));
            else if (kind == 1) outp.Add(Tok("i", G.num(Big(Inv(g.TokInt, t)))));
            else
            {
                var sb = new StringBuilder();
                foreach (var c in Elements(Inv(g.TokStr, t)!)) sb.Append(CodePointText(c!));
                outp.Add(Tok("s", sb.ToString()));
            }
        }
        return outp;
    }

    /// <summary>One proved entry point over token tapes: op in typecheck, compile, decideg, decidep, render. First output token:
    /// i0 ok, i1 rejected with reasons, i9 malformed input.</summary>
    public static L Call(string op, L goal, L? ont = null, L? act = null, L? hist = null)
    {
        // The Dafny runtime's lazy Seq concatenation and the generated recursion use the thread stack; run on a thread with a large
        // one so a huge string cannot overflow it (the JS runtime's Seq.Concat had that failure; this is the same guard here).
        L? result = null;
        Exception? error = null;
        var t = new Thread(() => { try { result = CallHere(op, goal, ont, act, hist); } catch (Exception e) { error = e; } }, 1 << 29);
        t.Start();
        t.Join();
        if (error != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
        return result!;
    }

    static L CallHere(string op, L goal, L? ont, L? act, L? hist)
    {
        var g = Load();
        return op switch
        {
            "typecheck" => FromDafny(Inv(g.Typecheck, ToDafny(goal), ToDafny(ont))),
            "compile" => FromDafny(Inv(g.Compile, ToDafny(goal), ToDafny(ont))),
            "render" => FromDafny(Inv(g.Render, ToDafny(goal))),
            "decideg" => FromDafny(Inv(g.DecideG, ToDafny(goal), ToDafny(ont), ToDafny(act), ToDafny(hist))),
            "decidep" => FromDafny(Inv(g.DecideP, ToDafny(goal), ToDafny(ont), ToDafny(act), ToDafny(hist))),
            _ => throw new ArgumentException("goal kernel: unknown op " + op),
        };
    }

    // ---- the typed front door (compiler.ts) ----

    static long First(L t) =>
        t.Count > 0 && t[0] is L x && (x[0] as string) == "i" ? Safe(x[1]) : throw new IrError("malformed compiler output");

    static long At(L t, int i) => Safe(((L)t[i]!)[1]);

    static string Str(object? tok) => tok is L x && (x[0] as string) == "s" ? (string)x[1]! : "";

    static List<string> Reasons(L t)
    {
        int n = t.Count > 1 ? (int)At(t, 1) : 0;
        return t.GetRange(2, n).Select(Str).ToList();
    }

    static string Decision(long n) => n == 2 ? "allow" : n == 1 ? "escalate" : "deny";

    /// <summary>Type reasons of a goal against an ontology; empty = well typed.</summary>
    public static List<string> Typecheck(D goal, D ont)
    {
        var outp = Call("typecheck", GoalCodec.EncodeGoal(goal), GoalCodec.EncodeOntology(ont));
        long s = First(outp);
        if (s == 0) return new();
        if (s == 1) return Reasons(outp);
        throw new IrError("compiler rejected the input tape");
    }

    /// <summary>C: Goal -> {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced.</summary>
    public static D CompileGoal(D goal, D ont)
    {
        var outp = Call("compile", GoalCodec.EncodeGoal(goal), GoalCodec.EncodeOntology(ont));
        long s = First(outp);
        if (s == 0) return new D { ["ok"] = true, ["policy"] = GoalCodec.DecodePolicy(outp.GetRange(1, outp.Count - 1)) };
        if (s == 1) return new D { ["ok"] = false, ["reasons"] = Reasons(outp).Cast<object?>().ToList() };
        throw new IrError("compiler rejected the input tape");
    }

    /// <summary>The reference semantics D_G(a, H): "allow" | "escalate" | "deny".</summary>
    public static string DecideGoal(D goal, D ont, D act, D hist)
    {
        var outp = Call("decideg", GoalCodec.EncodeGoal(goal), GoalCodec.EncodeOntology(ont), GoalCodec.EncodeAct(act), GoalCodec.EncodeHist(hist));
        if (First(outp) != 0) throw new IrError("compiler rejected the input tape");
        return Decision(At(outp, 1));
    }

    /// <summary>The compiled policy's decision: {ok: false, reasons} | {ok: true, decision, witness (null unless allow), witnessChecked}.</summary>
    public static D DecidePolicy(D goal, D ont, D act, D hist)
    {
        var outp = Call("decidep", GoalCodec.EncodeGoal(goal), GoalCodec.EncodeOntology(ont), GoalCodec.EncodeAct(act), GoalCodec.EncodeHist(hist));
        long s = First(outp);
        if (s == 1) return new D { ["ok"] = false, ["reasons"] = Reasons(outp).Cast<object?>().ToList() };
        if (s != 0) throw new IrError("compiler rejected the input tape");
        string d = Decision(At(outp, 1));
        int n = (int)At(outp, 3);
        var bids = outp.GetRange(4, n).Select(x => (object?)Str(x)).ToList();
        D? w = d == "allow" ? new D { ["gid"] = Str(outp[2]), ["bids"] = bids } : null;
        return new D { ["ok"] = true, ["decision"] = d, ["witness"] = w, ["witnessChecked"] = At(outp, 4 + n) == 1 };
    }

    /// <summary>The card as a token tape (GoalRender.Render): GoalCodec.DecodeGoal(RenderTape(g)) equals g.</summary>
    public static L RenderTape(D goal)
    {
        var outp = Call("render", GoalCodec.EncodeGoal(goal));
        if (First(outp) != 0) throw new IrError("goal tape rejected");
        return outp.GetRange(1, outp.Count - 1);
    }

    sealed class Proved : GoalReview.ReviewKernel
    {
        public D Compile(D goal, D ont) => CompileGoal(goal, ont);
        public string PolicyDigest(D policy) => GoalCompiler.PolicyDigest(policy);
        public bool CanDecide() => true;
        public string Decide(D goal, D ont, D act, D hist) => DecideGoal(goal, ont, act, hist);
    }

    /// <summary>The review kernel of the reference (provedKernel): compile, policy digest and the reference decision.</summary>
    public static GoalReview.ReviewKernel ProvedKernel() => new Proved();

    // ---- harness text syntax (kN, iN, s<hex>.<hex>...) ----

    /// <summary>A tape in the differential-harness syntax.</summary>
    public static string TapeToText(L tape)
    {
        var parts = new List<string>();
        foreach (var o in tape)
        {
            var t = (L)o!;
            if ((t[0] as string) == "s")
            {
                var s = (string)t[1]!;
                var hs = new List<string>();
                for (int i = 0; i < s.Length; i += char.IsSurrogatePair(s, i) ? 2 : 1) hs.Add(char.ConvertToUtf32(s, i).ToString("x", CultureInfo.InvariantCulture));
                parts.Add("s" + string.Join(".", hs));
            }
            else parts.Add((string)t[0]! + Safe(t[1]).ToString(CultureInfo.InvariantCulture));
        }
        return string.Join(" ", parts);
    }

    /// <summary>Parse the differential-harness syntax.</summary>
    public static L TapeFromText(string s)
    {
        var outp = new L();
        foreach (var x in s.Split(' '))
        {
            if (x.Length == 0) continue;
            var b = x[1..];
            if (x[0] == 'k' || x[0] == 'i') outp.Add(Tok(x[0].ToString(), G.num(long.Parse(b, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture))));
            else if (x[0] == 's')
                outp.Add(Tok("s", b.Length == 0 ? "" : string.Concat(b.Split('.').Select(h => char.ConvertFromUtf32(int.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture))))));
            else throw new IrError("goal tape text: bad token " + x);
        }
        return outp;
    }
}
