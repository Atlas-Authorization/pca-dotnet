// Protobuf services to drafts, from .proto text or a binary FileDescriptorSet. service.method becomes the verb; google.api.http gives method and path;
// idempotency_level gives read / idempotent; field behavior refines params; streaming methods get pca.bulk. Offline, bounded; the descriptor wire format
// is read by hand (no protobuf dependency).
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using static AtlasPca.ActionsKit.ImportCommon;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.ActionsKit;

public static class GrpcImporter
{
    // ---- model ----

    public sealed class PField
    {
        public string Name = "", Type = "", Scope = "";
        public bool Repeated, Optional;
        public string[]? Map;
        public List<string> Behavior = new();
        internal D ToJson()
        {
            var m = ImportJx.Obj(("name", Name), ("type", Type), ("scope", Scope), ("repeated", Repeated), ("optional", Optional));
            if (Map != null) m["map"] = ImportJx.List(Map[0], Map[1]);
            m["behavior"] = Ak.ToL(Behavior);
            return m;
        }
    }

    public sealed class PMsg
    {
        public string Full = "";
        public List<PField> Fields = new();
        public bool MapEntry;
    }

    public sealed class PEnum
    {
        public string Full = "";
        public List<string> Values = new();
    }

    public sealed class PHttp
    {
        public string Method = "", Path = "";
        public string? Body;
    }

    public sealed class PMethod
    {
        public string Name = "", Input = "", Output = "", Scope = "";
        public string? Idem;
        public bool Cs, Ss;
        public PHttp? Http;
    }

    public sealed class PService
    {
        public string Full = "", Name = "";
        public List<PMethod> Methods = new();
    }

    public sealed class ProtoModel
    {
        public readonly Dictionary<string, PMsg> Messages = new();
        public readonly Dictionary<string, PEnum> Enums = new();
        public readonly List<PService> Services = new();

        /// <summary>{messages: [[full, {...}]...], enums: [[full, [values]]...], services: [{...}]}.</summary>
        public D ToJson()
        {
            var ms = new L();
            foreach (var m in Messages.Values)
                ms.Add(ImportJx.List(m.Full, ImportJx.Obj(("full", m.Full), ("fields", new L(m.Fields.Select(f => (object?)f.ToJson()))), ("mapEntry", m.MapEntry))));
            var es = new L();
            foreach (var e in Enums.Values) es.Add(ImportJx.List(e.Full, Ak.ToL(e.Values)));
            var ss = new L();
            foreach (var s in Services)
            {
                var mm = new L();
                foreach (var x in s.Methods)
                {
                    var o = ImportJx.Obj(("name", x.Name), ("input", x.Input), ("output", x.Output), ("cs", x.Cs), ("ss", x.Ss), ("scope", x.Scope));
                    if (x.Http != null) { var h = ImportJx.Obj(("method", x.Http.Method), ("path", x.Http.Path)); if (x.Http.Body != null) h["body"] = x.Http.Body; o["http"] = h; }
                    if (x.Idem != null) o["idem"] = x.Idem;
                    mm.Add(o);
                }
                ss.Add(ImportJx.Obj(("full", s.Full), ("name", s.Name), ("methods", mm)));
            }
            return ImportJx.Obj(("messages", ms), ("enums", es), ("services", ss));
        }
    }

    static readonly HashSet<string> ScalarNames = new() { "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes" };

    // ---- .proto text ----

    sealed class Tok
    {
        public readonly string T, V;
        public Tok(string t, string v) { T = t; V = v; }
    }

    static bool IdStart(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '.';
    static bool IdChar(char c) => IdStart(c) || (c >= '0' && c <= '9');
    static bool NumChar(char c) => c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');

    static List<Tok> Lex(string src, int maxTokens)
    {
        var o = new List<Tok>();
        int n = src.Length, i = 0;
        while (i < n)
        {
            char ch = src[i];
            Tok push;
            if (ImportJx.JsSpace(ch)) { i++; continue; }
            if (string.CompareOrdinal(src, i, "//", 0, 2) == 0) { while (i < n && src[i] != '\n') i++; continue; }
            if (string.CompareOrdinal(src, i, "/*", 0, 2) == 0)
            {
                int j0 = src.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (j0 < 0) throw new ActionKitError("bad_source", "unterminated comment in proto source");
                i = j0 + 2;
                continue;
            }
            if (ch == '"' || ch == '\'')
            {
                int j = i + 1;
                var s = new StringBuilder();
                while (j < n && src[j] != ch)
                {
                    if (src[j] == '\n') throw new ActionKitError("bad_source", "unterminated string in proto source");
                    if (src[j] == '\\') { if (j + 1 < n) s.Append(src[j + 1]); j += 2; } else s.Append(src[j++]);
                }
                if (j >= n) throw new ActionKitError("bad_source", "unterminated string in proto source");
                push = new Tok("str", s.ToString());
                i = j + 1;
            }
            else if (IdStart(ch))
            {
                int j = i + 1;
                while (j < n && IdChar(src[j])) j++;
                push = new Tok("id", src.Substring(i, j - i));
                i = j;
            }
            else if (ch == '-' || (ch >= '0' && ch <= '9'))
            {
                int j = i + 1;
                while (j < n && NumChar(src[j])) j++;
                push = new Tok("num", src.Substring(i, j - i));
                i = j;
            }
            else if ("{}[]()<>=;,:".IndexOf(ch) >= 0) { push = new Tok("p", ch.ToString()); i++; }
            else throw new ActionKitError("bad_source", "unexpected character in proto source at offset " + i);
            if (o.Count >= maxTokens) throw new ActionKitError("import_limit", "the proto source has too many tokens");
            o.Add(push);
        }
        return o;
    }

    static readonly Regex UpperWord = new("\\A[A-Z_]+\\z", RegexOptions.CultureInvariant);
    static readonly string[] HttpVerbs = { "get", "put", "post", "delete", "patch" };

    sealed class PP
    {
        int i = 0;
        string pkg = "";
        readonly List<Tok> toks;
        readonly ProtoModel m;
        readonly int maxDepth;
        public PP(List<Tok> toks, ProtoModel m, int maxDepth) { this.toks = toks; this.m = m; this.maxDepth = maxDepth; }

        Tok? Cur() => i < toks.Count ? toks[i] : null;
        bool Is(string v) { var t = Cur(); return t != null && t.T != "str" && t.V == v; }
        bool Eat(string v) { if (Is(v)) { i++; return true; } return false; }
        ActionKitError Fail(string msg) => new("bad_source", "proto parse error: " + msg + " near '" + Clip(Cur() == null ? "<end>" : Cur()!.V, 30) + "'");
        void Expect(string v) { if (!Eat(v)) throw Fail("expected '" + v + "'"); }
        string Id() { var t = Cur(); if (t == null || t.T != "id") throw Fail("expected an identifier"); i++; return t.V; }

        /// <summary>Skip to the matching close of an already-opened bracket.</summary>
        void SkipTo(string open, string close)
        {
            int depth = 1;
            while (depth > 0)
            {
                var t = i < toks.Count ? toks[i] : null;
                i++;
                if (t == null) throw Fail("unterminated block");
                if (t.T == "p") { if (t.V == open) depth++; else if (t.V == close) depth--; }
            }
        }

        void SkipStatement()
        {
            while (Cur() != null && !Is(";"))
            {
                if (Is("{")) { i++; SkipTo("{", "}"); return; }
                i++;
            }
            Eat(";");
        }

        public void File()
        {
            while (Cur() != null)
            {
                if (Eat(";")) continue;
                var kw = Id();
                if (kw == "package") { pkg = Id(); Expect(";"); }
                else if (kw == "message") Message(pkg, 0);
                else if (kw == "enum") EnumDef(pkg);
                else if (kw == "service") Service();
                else if (kw == "extend") { Id(); Expect("{"); SkipTo("{", "}"); }
                else SkipStatement();
            }
        }

        static string Qual(string scope, string name) => scope.Length == 0 ? name : scope + "." + name;

        void EnumDef(string scope)
        {
            var name = Id();
            var full = Qual(scope, name);
            Expect("{");
            var values = new List<string>();
            while (!Is("}"))
            {
                if (Cur() == null) throw Fail("unterminated enum");
                if (Is("option") || Is("reserved")) { SkipStatement(); continue; }
                values.Add(Id());
                SkipStatement();
            }
            Expect("}");
            m.Enums[full] = new PEnum { Full = full, Values = values };
        }

        /// <summary>Field options: collect field_behavior names; everything else is skipped.</summary>
        List<string> FieldOptions()
        {
            var behavior = new List<string>();
            if (!Eat("[")) return behavior;
            int depth = 1;
            bool inBehavior = false;
            while (depth > 0)
            {
                var t = i < toks.Count ? toks[i] : null;
                i++;
                if (t == null) throw Fail("unterminated field options");
                if (t.T == "p")
                {
                    if (t.V == "[" || t.V == "{") depth++;
                    else if (t.V == "]" || t.V == "}") depth--;
                    else if (t.V == ",") inBehavior = false;
                }
                else if (t.T == "id")
                {
                    if (t.V.EndsWith("field_behavior", StringComparison.Ordinal)) inBehavior = true;
                    else if (inBehavior && UpperWord.IsMatch(t.V)) behavior.Add(t.V);
                }
            }
            return behavior;
        }

        void Field(PMsg msg, string full, string? label, bool oneof)
        {
            bool repeated = label == "repeated";
            var type = Id();
            string[]? map = null;
            if (type == "map" && Eat("<")) { var k = Id(); Expect(","); var v = Id(); Expect(">"); map = new[] { k, v }; type = "map"; repeated = false; }
            var fname = Id();
            Expect("=");
            i++; // field number
            var behavior = FieldOptions();
            Expect(";");
            msg.Fields.Add(new PField { Name = fname, Type = type, Scope = full, Repeated = repeated, Optional = label == "optional" || oneof, Map = map, Behavior = behavior });
        }

        void Message(string scope, int depth)
        {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "proto message nesting is too deep");
            var name = Id();
            var full = Qual(scope, name);
            var msg = new PMsg { Full = full };
            m.Messages[full] = msg;
            Expect("{");
            while (!Is("}"))
            {
                if (Cur() == null) throw Fail("unterminated message");
                if (Eat(";")) continue;
                var kw = Cur()!.T == "id" ? Cur()!.V : "";
                if (kw == "message") { i++; Message(full, depth + 1); continue; }
                if (kw == "enum") { i++; EnumDef(full); continue; }
                if (kw == "oneof")
                {
                    i++; Id(); Expect("{");
                    while (!Is("}"))
                    {
                        if (Cur() == null) throw Fail("unterminated oneof");
                        if (Is("option")) { SkipStatement(); continue; }
                        Field(msg, full, null, true);
                    }
                    Expect("}");
                    continue;
                }
                if (kw == "option" || kw == "reserved" || kw == "extensions") { SkipStatement(); continue; }
                if (kw == "extend") { i++; Id(); Expect("{"); SkipTo("{", "}"); continue; }
                if (kw == "group") { SkipStatement(); continue; }
                if (kw == "repeated" || kw == "optional" || kw == "required") { i++; Field(msg, full, kw, false); continue; }
                Field(msg, full, null, false);
            }
            Expect("}");
        }

        bool StreamKw() { var t = Cur(); if (t != null && t.V == "stream" && t.T == "id") { i++; return true; } return false; }

        void Service()
        {
            var name = Id();
            var full = Qual(pkg, name);
            var svc = new PService { Full = full, Name = name };
            Expect("{");
            while (!Is("}"))
            {
                if (Cur() == null) throw Fail("unterminated service");
                if (Eat(";")) continue;
                var kw = Id();
                if (kw != "rpc") { SkipStatement(); continue; }
                var mname = Id();
                Expect("(");
                bool cs = StreamKw();
                var input = Id();
                Expect(")");
                if (Id() != "returns") throw Fail("expected 'returns'");
                Expect("(");
                bool ss = StreamKw();
                var output = Id();
                Expect(")");
                var me = new PMethod { Name = mname, Input = input, Output = output, Cs = cs, Ss = ss, Scope = pkg };
                if (Eat("{"))
                {
                    while (!Is("}"))
                    {
                        if (Cur() == null) throw Fail("unterminated rpc body");
                        if (!Is("option")) { SkipStatement(); continue; }
                        i++;
                        string oname;
                        if (Eat("(")) { oname = Id(); Expect(")"); } else oname = Id();
                        Expect("=");
                        if (Is("{"))
                        {
                            i++;
                            int depth = 1;
                            while (depth > 0)
                            {
                                var t = i < toks.Count ? toks[i] : null;
                                i++;
                                if (t == null) throw Fail("unterminated option");
                                if (t.T == "p") { if (t.V == "{") depth++; else if (t.V == "}") depth--; continue; }
                                if (depth == 1 && oname.EndsWith("http", StringComparison.Ordinal) && t.T == "id" && HttpVerbs.Contains(t.V) && Is(":"))
                                {
                                    i++;
                                    var path = Cur() != null && Cur()!.T == "str" ? Cur()!.V : "";
                                    i++;
                                    if (me.Http == null) me.Http = new PHttp { Method = t.V.ToUpperInvariant(), Path = path };
                                }
                                else if (depth == 1 && oname.EndsWith("http", StringComparison.Ordinal) && t.T == "id" && t.V == "body" && Is(":"))
                                {
                                    i++;
                                    if (Cur() != null && Cur()!.T == "str" && me.Http != null) me.Http.Body = Cur()!.V;
                                    i++;
                                }
                            }
                            Eat(";");
                        }
                        else
                        {
                            var v = Cur();
                            i++;
                            if (oname.EndsWith("idempotency_level", StringComparison.Ordinal) && v != null) me.Idem = v.V;
                            Eat(";");
                        }
                    }
                    Expect("}");
                    Eat(";");
                }
                else Expect(";");
                svc.Methods.Add(me);
            }
            Expect("}");
            m.Services.Add(svc);
        }
    }

    public static ProtoModel ParseProto(string src, int maxTokens = 2_000_000)
    {
        var m = new ProtoModel();
        new PP(Lex(src, maxTokens), m, 32).File();
        return m;
    }

    // ---- binary descriptor set ----

    sealed class Reader
    {
        readonly byte[] b;
        public int P;
        public readonly int End;
        public Reader(byte[] b, int p, int end) { this.b = b; P = p; End = end; }
        public bool More() => P < End;

        public double Varint()
        {
            double r = 0, mul = 1;
            for (int k = 0; k < 10; k++)
            {
                if (P >= End) throw new ActionKitError("bad_source", "truncated descriptor");
                int by = b[P++] & 0xff;
                r += (by & 0x7f) * mul;
                if ((by & 0x80) == 0) return r;
                mul *= 128;
            }
            throw new ActionKitError("bad_source", "overlong varint in descriptor");
        }

        public Reader Len()
        {
            double n = Varint();
            if (n > End - P) throw new ActionKitError("bad_source", "descriptor length exceeds the buffer");
            var r = new Reader(b, P, P + (int)n);
            P += (int)n;
            return r;
        }

        public void Skip(double wt)
        {
            if (wt == 0) Varint();
            else if (wt == 1) Adv(8);
            else if (wt == 2) Len();
            else if (wt == 5) Adv(4);
            else throw new ActionKitError("bad_source", "unsupported wire type " + JsJson.NumberToString(wt) + " in descriptor");
        }

        void Adv(int n) { if (n > End - P) throw new ActionKitError("bad_source", "truncated descriptor"); P += n; }
        public string Str() { var r = Len(); return DecodeUtf8(b, r.P, r.End); }
    }

    /// <summary>TextDecoder('utf-8') without fatal: maximal-subpart replacement, and a leading byte order mark is dropped.</summary>
    static string DecodeUtf8(byte[] b, int from, int to)
    {
        var s = new UTF8Encoding(false, false).GetString(b, from, to - from);
        return s.Length > 0 && s[0] == '﻿' ? s.Substring(1) : s;
    }

    static readonly string?[] FTypes = BuildFTypes();
    static string?[] BuildFTypes()
    {
        var f = new string?[19];
        var names = new[] { "double", "float", "int64", "uint64", "int32", "fixed64", "fixed32", "bool", "string" };
        for (int i = 0; i < names.Length; i++) f[i + 1] = names[i];
        f[12] = "bytes"; f[13] = "uint32"; f[15] = "sfixed32"; f[16] = "sfixed64"; f[17] = "sint32"; f[18] = "sint64";
        return f;
    }

    static (double F, double Wt) Tag(Reader r) { var t = r.Varint(); return (Math.Floor(t / 8), t % 8); }

    sealed class FieldDesc
    {
        public string Name = "", TypeName = "";
        public double Type = 0, Label = 1;
        public bool Proto3Opt;
        public List<double> Behavior = new();
    }

    static void ReadEnum(ProtoModel m, Reader r, string scope)
    {
        var name = "";
        var values = new List<string>();
        while (r.More())
        {
            var (f, wt) = Tag(r);
            if (f == 1 && wt == 2) name = r.Str();
            else if (f == 2 && wt == 2)
            {
                var v = r.Len();
                while (v.More()) { var (vf, vwt) = Tag(v); if (vf == 1 && vwt == 2) values.Add(v.Str()); else v.Skip(vwt); }
            }
            else r.Skip(wt);
        }
        var full = scope.Length == 0 ? name : scope + "." + name;
        m.Enums[full] = new PEnum { Full = full, Values = values };
    }

    static string BehaviorName(double b) => b == 2 ? "REQUIRED" : b == 3 ? "OUTPUT_ONLY" : b == 4 ? "INPUT_ONLY" : b == 5 ? "IMMUTABLE" : "";

    static void ReadMsg(ProtoModel m, Reader r, string scope, int depth)
    {
        if (depth > 32) throw new ActionKitError("import_limit", "descriptor message nesting is too deep");
        var name = "";
        var fields = new List<FieldDesc>();
        var nested = new List<Reader>(); var enums = new List<Reader>();
        bool mapEntry = false;
        while (r.More())
        {
            var (f, wt) = Tag(r);
            if (f == 1 && wt == 2) name = r.Str();
            else if (f == 2 && wt == 2)
            {
                var fr = r.Len();
                var fd = new FieldDesc();
                while (fr.More())
                {
                    var (ff, fwt) = Tag(fr);
                    if (ff == 1 && fwt == 2) fd.Name = fr.Str();
                    else if (ff == 4 && fwt == 0) fd.Label = fr.Varint();
                    else if (ff == 5 && fwt == 0) fd.Type = fr.Varint();
                    else if (ff == 6 && fwt == 2) fd.TypeName = fr.Str();
                    else if (ff == 17 && fwt == 0) fd.Proto3Opt = fr.Varint() == 1;
                    else if (ff == 8 && fwt == 2)
                    {
                        var o = fr.Len();
                        while (o.More())
                        {
                            var (of, owt) = Tag(o);
                            if (of == 1052 && owt == 0) fd.Behavior.Add(o.Varint());
                            else if (of == 1052 && owt == 2) { var pk = o.Len(); while (pk.More()) fd.Behavior.Add(pk.Varint()); }
                            else o.Skip(owt);
                        }
                    }
                    else fr.Skip(fwt);
                }
                fields.Add(fd);
            }
            else if (f == 3 && wt == 2) nested.Add(r.Len());
            else if (f == 4 && wt == 2) enums.Add(r.Len());
            else if (f == 7 && wt == 2)
            {
                var o = r.Len();
                while (o.More()) { var (of, owt) = Tag(o); if (of == 7 && owt == 0) mapEntry = o.Varint() == 1; else o.Skip(owt); }
            }
            else r.Skip(wt);
        }
        var full = scope.Length == 0 ? name : scope + "." + name;
        var msg = new PMsg { Full = full, MapEntry = mapEntry };
        foreach (var fdd in fields)
        {
            var pf = new PField { Name = fdd.Name, Scope = full, Repeated = fdd.Label == 3, Optional = fdd.Proto3Opt };
            pf.Type = fdd.TypeName.Length > 0 ? fdd.TypeName : (fdd.Type >= 1 && fdd.Type <= 18 && fdd.Type == Math.Round(fdd.Type) && FTypes[(int)fdd.Type] != null ? FTypes[(int)fdd.Type]! : "bytes");
            foreach (var bh in fdd.Behavior) pf.Behavior.Add(BehaviorName(bh));
            msg.Fields.Add(pf);
        }
        m.Messages[full] = msg;
        foreach (var nr in nested) ReadMsg(m, nr, full, depth + 1);
        foreach (var er in enums) ReadEnum(m, er, full);
    }

    public static ProtoModel ParseDescriptorSet(byte[] bytes)
    {
        var m = new ProtoModel();
        var top = new Reader(bytes, 0, bytes.Length);
        while (top.More())
        {
            var (f, wt) = Tag(top);
            if (f != 1 || wt != 2) { top.Skip(wt); continue; }
            var fr = top.Len();
            var pkg = "";
            var msgs = new List<Reader>(); var enums = new List<Reader>(); var svcs = new List<Reader>();
            // package may follow the messages in the wire order: collect first, then resolve scopes
            while (fr.More())
            {
                var (ff, fwt) = Tag(fr);
                if (ff == 2 && fwt == 2) pkg = fr.Str();
                else if (ff == 4 && fwt == 2) msgs.Add(fr.Len());
                else if (ff == 5 && fwt == 2) enums.Add(fr.Len());
                else if (ff == 6 && fwt == 2) svcs.Add(fr.Len());
                else fr.Skip(fwt);
            }
            foreach (var mr0 in msgs) ReadMsg(m, mr0, pkg, 0);
            foreach (var er in enums) ReadEnum(m, er, pkg);
            foreach (var r in svcs)
            {
                var name = "";
                var methods = new List<PMethod>();
                while (r.More())
                {
                    var (sf, swt) = Tag(r);
                    if (sf == 1 && swt == 2) name = r.Str();
                    else if (sf == 2 && swt == 2)
                    {
                        var mr = r.Len();
                        var me = new PMethod { Scope = pkg };
                        while (mr.More())
                        {
                            var (mf, mwt) = Tag(mr);
                            if (mf == 1 && mwt == 2) me.Name = mr.Str();
                            else if (mf == 2 && mwt == 2) me.Input = mr.Str();
                            else if (mf == 3 && mwt == 2) me.Output = mr.Str();
                            else if (mf == 5 && mwt == 0) me.Cs = mr.Varint() == 1;
                            else if (mf == 6 && mwt == 0) me.Ss = mr.Varint() == 1;
                            else if (mf == 4 && mwt == 2)
                            {
                                var o = mr.Len();
                                while (o.More())
                                {
                                    var (of, owt) = Tag(o);
                                    if (of == 34 && owt == 0) { var lv = o.Varint(); me.Idem = lv == 1 ? "NO_SIDE_EFFECTS" : lv == 2 ? "IDEMPOTENT" : "IDEMPOTENCY_UNKNOWN"; }
                                    else if (of == 72295728 && owt == 2)
                                    {
                                        var h = o.Len();
                                        while (h.More())
                                        {
                                            var (hf, hwt) = Tag(h);
                                            string? verb = hf == 2 ? "GET" : hf == 3 ? "PUT" : hf == 4 ? "POST" : hf == 5 ? "DELETE" : hf == 6 ? "PATCH" : null;
                                            if (verb != null && hwt == 2) { if (me.Http == null) me.Http = new PHttp { Method = verb, Path = h.Str() }; else h.Str(); }
                                            else if (hf == 7 && hwt == 2) { var bd = h.Str(); if (me.Http != null) me.Http.Body = bd; }
                                            else h.Skip(hwt);
                                        }
                                    }
                                    else o.Skip(owt);
                                }
                            }
                            else mr.Skip(mwt);
                        }
                        methods.Add(me);
                    }
                    else r.Skip(swt);
                }
                m.Services.Add(new PService { Full = pkg.Length == 0 ? name : pkg + "." + name, Name = name, Methods = methods });
            }
        }
        return m;
    }

    // ---- model to params ----

    static string? ResolveName(ProtoModel m, string name, string scope)
    {
        if (name.StartsWith(".", StringComparison.Ordinal)) return name.Substring(1);
        var parts = scope.Length == 0 ? Array.Empty<string>() : scope.Split('.');
        for (int k = parts.Length; k >= 0; k--)
        {
            var cand = new StringBuilder();
            for (int j = 0; j < k; j++) cand.Append(parts[j]).Append('.');
            cand.Append(name);
            var cs = cand.ToString();
            if (m.Messages.ContainsKey(cs) || m.Enums.ContainsKey(cs)) return cs;
        }
        return m.Messages.ContainsKey(name) || m.Enums.ContainsKey(name) ? name : null;
    }

    static readonly HashSet<string> WktString = new() { "google.protobuf.StringValue", "google.protobuf.BytesValue" };
    static readonly HashSet<string> WktInt = new() { "google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value" };

    static D One(ProtoModel m, string type, string scope, Ctx c, List<string> stack, string where, int[] budget)
    {
        if (ScalarNames.Contains(type))
        {
            if (type.Contains("int") || type.Contains("fixed")) return ImportJx.Obj(("type", "integer"), ("format", "int64"));
            if (type == "bool") return ImportJx.Obj(("type", "boolean"));
            if (type == "string") return ImportJx.Obj(("type", "string"));
            if (type == "bytes") return ImportJx.Obj(("type", "string"));
            return ImportJx.Obj(("type", "number"));
        }
        var abs = type.StartsWith(".", StringComparison.Ordinal) ? type.Substring(1) : null;
        var eff = abs ?? type;
        if (abs == "google.protobuf.Timestamp" || type == "google.protobuf.Timestamp") return ImportJx.Obj(("type", "string"), ("format", "date-time"));
        if (WktString.Contains(eff)) return ImportJx.Obj(("type", "string"));
        if (WktInt.Contains(eff)) return ImportJx.Obj(("type", "integer"), ("format", "int64"));
        if (eff == "google.protobuf.BoolValue") return ImportJx.Obj(("type", "boolean"));
        if (eff.StartsWith("google.protobuf.", StringComparison.Ordinal)) return new D();
        var full = ResolveName(m, type, scope);
        if (full == null) { AddTodo(c, where, "unknown_type", "type '" + Clip(type, 60) + "' is not defined in the proto source (declared string)"); return new D(); }
        if (m.Enums.TryGetValue(full, out var en)) return ImportJx.Obj(("type", "string"), ("enum", Ak.ToL(en.Values.Distinct(StringComparer.Ordinal))));
        return MsgSchema(m, full, c, stack, where, budget);
    }

    static D FieldSchema(ProtoModel m, PField f, Ctx c, List<string> stack, string where, int[] budget)
    {
        if (f.Map != null) return ImportJx.Obj(("type", "object"));
        var s = One(m, f.Type, f.Scope, c, stack, where, budget);
        return f.Repeated ? ImportJx.Obj(("type", "array"), ("items", s)) : s;
    }

    static D MsgSchema(ProtoModel m, string full, Ctx c, List<string> stack, string where, int[] budget)
    {
        if (!m.Messages.TryGetValue(full, out var msg)) return new D();
        if (stack.Contains(full)) { AddTodo(c, where, "cyclic_ref", "message '" + Clip(full, 80) + "' is recursive (declared string; refine or drop)"); return new D(); }
        if (stack.Count > c.Lim.MaxRefDepth || --budget[0] <= 0) { AddTodo(c, where, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)"); return new D(); }
        var properties = new D();
        var required = new L();
        var ns = new List<string>(stack) { full };
        foreach (var f in msg.Fields)
        {
            if (f.Behavior.Contains("OUTPUT_ONLY")) continue;
            PutProp(properties, f.Name, FieldSchema(m, f, c, ns, where + "." + f.Name, budget));
            if (f.Behavior.Contains("REQUIRED")) required.Add(f.Name);
        }
        return ImportJx.Obj(("type", "object"), ("properties", properties), ("required", required));
    }

    public static D ImportGrpc(object? source, D opts)
    {
        var c = NewCtx("grpc", source, opts);
        ProtoModel m;
        if (source is string text) m = ParseProto(text);
        else if (source is byte[] bytes) m = ParseDescriptorSet(bytes);
        else throw new ActionKitError("bad_source", "a gRPC source is .proto text or a binary FileDescriptorSet");
        var cmp = Comparer<string>.Create(IntentJs.CompareUtf8);
        foreach (var svc in m.Services.OrderBy(x => x.Full, cmp).ToList())
        {
            foreach (var me in svc.Methods.OrderBy(x => x.Name, cmp).ToList())
            {
                var where = svc.Name + "/" + me.Name;
                c.Root = null;
                var bud = NewBudget(c);
                var rn = ResolveName(m, me.Input, me.Scope);
                var input = rn ?? (me.Input.StartsWith(".", StringComparison.Ordinal) ? me.Input.Substring(1) : me.Input);
                var schema = MsgSchema(m, input, c, new List<string>(), where, new[] { (int)c.Lim.MaxRefNodes });
                var parms = new D();
                if (schema.GetValueOrDefault("properties") != null) FlattenObject(schema, c, bud, where, parms);
                else if (!m.Messages.ContainsKey(input) && !input.StartsWith("google.protobuf.", StringComparison.Ordinal)) AddTodo(c, where, "unknown_type", "request type '" + Clip(me.Input, 60) + "' is not defined in the source (no parameters)");
                var hm = me.Http?.Method;
                var eff = hm == "GET" ? "read" : hm == "DELETE" ? "delete" : hm == "POST" ? "create" : hm == "PUT" || hm == "PATCH" ? "update" : me.Idem == "NO_SIDE_EFFECTS" ? "read" : "update";
                bool natural = me.Idem == "NO_SIDE_EFFECTS" || me.Idem == "IDEMPOTENT" || hm == "GET" || hm == "PUT" || hm == "DELETE";
                List<string>? traits = null;
                if (me.Cs || me.Ss) { traits = WithTrait(traits, "pca.bulk"); AddTodo(c, where, "streaming", "a streaming method: acts on many messages (pca.bulk added)"); }
                var d = new Draft
                {
                    Name = svc.Name + " " + me.Name,
                    Title = Regex.Replace(me.Name, "([a-z0-9])([A-Z])", "$1 $2"),
                    Effects = new List<string> { eff },
                    Scope = "one",
                    Params = parms,
                };
                if (natural) d.Idempotency = ImportJx.Obj(("mode", "natural"));
                if (traits != null) d.Traits = traits;
                var b = ImportJx.Obj(("grpc", ImportJx.Obj(("service", Clip(svc.Full, 250)), ("method", Clip(me.Name, 250)))));
                if (me.Http != null && !string.IsNullOrEmpty(me.Http.Path)) b["http"] = ImportJx.Obj(("method", me.Http.Method), ("path", Clip(me.Http.Path, 250)));
                d.Bindings = b;
                EmitDef(c, d);
            }
        }
        return Finish(c);
    }
}
