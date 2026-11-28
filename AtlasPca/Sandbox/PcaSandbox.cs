// Sandbox policy compile, OS profile generators (seccomp, Landlock, macOS SBPL), the receipt hash chain, runtime-class claims and the reference
// WebAssembly builders. Policies, profiles and receipts are JSON trees (insertion-ordered dictionaries and lists) whose canonical form is
// byte-identical to the reference's. Running WebAssembly (a wasmtime host, the component runner) and the HTTP proxy server need a runtime and sockets
// the SDK does not carry and are not part of this port; the pure core of each is.
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Sandbox;

/// <summary>One authorized operation: the authorization result and the operation it must allow exactly.</summary>
public sealed record AuthorizedOp(AuthorizeResult Result, Operation Operation);

public static partial class PcaSandbox
{
    // ---- JavaScript value helpers over the JSON tree ----

    /// <summary><c>o[k]</c> for a read that throws on null; a non-object has no members.</summary>
    internal static object? Member(object? o, string k)
    {
        if (o == null) throw new ArgumentException("cannot read '" + k + "' of null or undefined");
        return o is D m ? m.GetValueOrDefault(k) : null;
    }

    internal static object? Opt(object? o, string k) => o is D m ? m.GetValueOrDefault(k) : null;

    /// <summary>`${o[k]}`: an absent member prints "undefined".</summary>
    internal static string StrMember(object? o, string k) => o is D m && m.ContainsKey(k) ? JsJson.ToJsString(m[k]) : "undefined";

    /// <summary>Number.isInteger for a JSON number (any magnitude), else null.</summary>
    internal static double? IntOf(object? o) => IntentJs.NumOf(o) is double d && double.IsFinite(d) && d == Math.Round(d) ? d : null;

    /// <summary>for (const x of v ?? []): a list iterates; null and the empty string are empty; anything else throws.</summary>
    static List<object?> Iter(object? v)
    {
        if (v == null) return new L();
        if (v is L l) return l;
        if (v is string s && s.Length == 0) return new L();
        throw new ArgumentException("not iterable");
    }

    // ---- constants ----

    public const string ImportModule = "pca:act";
    public static readonly IReadOnlyList<string> AllowedImports = new[] { "invoke", "handle_count", "handle_verb" };
    public const string Genesis = "genesis";
    public static readonly IReadOnlyList<string> RuntimeClasses = new[] { "none", "os_confined", "egress_default_deny", "wasi_no_ambient" };
    public const string RuntimeClaimDomain = "atlas-pca/runtime-class-claim/v1\0";

    /// <summary>Negative return codes of a handle use (the WASM ABI returns them as i32).</summary>
    public static readonly IReadOnlyDictionary<string, long> UseErr = new Dictionary<string, long>
    {
        ["unknown_handle"] = -1, ["spent"] = -2, ["out_too_small"] = -3, ["bad_memory"] = -4, ["executor_error"] = -5, ["no_executor"] = -6,
    };

    /// <summary>True only when both names are known and <paramref name="attested"/> is at least <paramref name="required"/>. An unknown name never satisfies.</summary>
    public static bool SatisfiesRuntimeClass(object? attested, object? required)
    {
        int a = attested is string x ? ClassIndex(x) : -1;
        int r = required is string y ? ClassIndex(y) : -1;
        return a >= 0 && r >= 0 && a >= r;
    }

    static int ClassIndex(string s) { for (int i = 0; i < RuntimeClasses.Count; i++) if (RuntimeClasses[i] == s) return i; return -1; }

    // ---- receipts ----

    /// <summary>Append-only hash chain of use receipts: every handle use and every egress decision, refusals included.</summary>
    public sealed class ReceiptLog
    {
        readonly List<D> _entries = new();
        readonly Func<object?> _now;
        readonly Func<string, string>? _sign;
        readonly object _lock = new();

        /// <param name="now">The host clock as a JSON number (default: epoch ms).</param>
        /// <param name="sign">Optional host signature over a digest.</param>
        public ReceiptLog(Func<object?>? now = null, Func<string, string>? sign = null)
        {
            _now = now ?? (() => AtlasPca.ReplayClock.NowMs());
            _sign = sign;
        }

        public IReadOnlyList<D> Entries { get { lock (_lock) return _entries.ToList(); } }

        /// <summary>Append a receipt; <paramref name="body"/> carries kind, subject, outcome and reason. A throwing clock or signer appends nothing.</summary>
        public D Append(string runtimeClass, D body)
        {
            lock (_lock)
            {
                var unsigned = new D
                {
                    ["v"] = 1L,
                    ["seq"] = (long)_entries.Count,
                    ["prev"] = _entries.Count == 0 ? Genesis : _entries[^1]["digest"],
                    ["at"] = _now(),
                    ["runtime_class"] = runtimeClass,
                };
                foreach (var (k, v) in body) unsigned[k] = v; // a member of the body overrides in place, as an object spread does
                var digest = Pca.HashCanonical(unsigned);
                var r = new D(unsigned) { ["digest"] = digest };
                if (_sign != null) r["sig"] = _sign(digest);
                _entries.Add(r);
                return r;
            }
        }
    }

    static D ChainFail(long at, string reason) => new() { ["ok"] = false, ["at"] = at, ["reason"] = reason };

    /// <summary>Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with <paramref name="verifySig"/>) a bad signature.
    /// Returns {ok:true} or {ok:false, at, reason}. A receipt list that is not a list, or a null receipt, throws.</summary>
    public static D VerifyReceiptChain(object? receipts, Func<string, string, bool>? verifySig = null)
    {
        if (receipts is not L list) throw new ArgumentException("receipts is not iterable");
        string prev = Genesis;
        for (int i = 0; i < list.Count; i++)
        {
            var r = list[i];
            var v = IntentJs.NumOf(Member(r, "v"));
            var sn = IntentJs.NumOf(Opt(r, "seq"));
            if (v == null || v != 1.0 || sn == null || sn != (double)i) return ChainFail(i, "bad_seq");
            if (!(Opt(r, "prev") is string ps && ps == prev)) return ChainFail(i, "broken_link");
            var m = (D)r!;
            var rest = new D();
            foreach (var (k, val) in m) if (k != "digest" && k != "sig") rest[k] = val;
            var digest = m.GetValueOrDefault("digest");
            if (!(digest is string ds && Pca.HashCanonical(rest) == ds)) return ChainFail(i, "bad_digest");
            var sig = m.GetValueOrDefault("sig");
            if (verifySig != null && !(sig is string ss && verifySig(ds, ss))) return ChainFail(i, "bad_sig");
            prev = ds;
        }
        return new D { ["ok"] = true };
    }

    // ---- policy compile ----

    // Absolute, normalized, and only characters that need no escaping in a seccomp/Landlock/SBPL string. Refuse, never escape.
    static readonly Regex PathRe = new(@"\A/[A-Za-z0-9._+@=,:~ /-]*\z", RegexOptions.CultureInvariant);
    static readonly Regex PolicyHostRe = new(@"\A[a-z0-9]([a-z0-9.-]*[a-z0-9])?\z", RegexOptions.CultureInvariant);

    static string CheckPath(object? p)
    {
        if (p is not string s) throw new ArgumentException("bad_path");
        if (!PathRe.IsMatch(s) || s.Contains("//", StringComparison.Ordinal) || (s.Length > 1 && s.EndsWith('/'))) throw new ArgumentException("bad_path");
        foreach (var seg in s.Split('/')) if (seg is "." or "..") throw new ArgumentException("bad_path");
        return s;
    }

    /// <summary>Compile the OS policy from what was actually authorized: only operations that IsAuthorizedFor allows contribute, so a denied or
    /// unrelated operation widens nothing. <paramref name="needsOf"/> maps an operation to its needs (a JSON object) or null.</summary>
    public static D CompilePolicy(IEnumerable<AuthorizedOp> items, Func<Operation, object?> needsOf, object? proxyPort = null)
    {
        var needs = new L();
        foreach (var it in items)
        {
            if (!Pca.IsAuthorizedFor(it.Result, it.Operation)) throw new ArgumentException("not_authorized: result does not allow exactly this operation");
            var n = needsOf(it.Operation);
            if (n != null) needs.Add(n);
        }
        return PolicyFromNeeds(needs, proxyPort);
    }

    /// <summary>The pure core of <see cref="CompilePolicy"/>: validate, merge, sort. <paramref name="proxyPort"/> null means no proxy.</summary>
    public static D PolicyFromNeeds(object? needs, object? proxyPort = null)
    {
        if (needs is not L nl) throw new ArgumentException("needs is not iterable");
        var read = new SortedSet<string>(StringComparer.Ordinal);
        var write = new SortedSet<string>(StringComparer.Ordinal);
        var exec = new SortedSet<string>(StringComparer.Ordinal);
        var hosts = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var n in nl)
        {
            foreach (var f in Iter(Member(n, "fs")))
            {
                var p = CheckPath(Member(f, "path"));
                var mode = Opt(f, "mode");
                if (mode is "x") exec.Add(p);
                else if (mode is "r" or "rw")
                {
                    read.Add(p);
                    if (mode is "rw") write.Add(p);
                }
                else throw new ArgumentException("bad_mode");
            }
            foreach (var h in Iter(Member(n, "net")))
            {
                var port = Member(h, "port");
                var pi = IntOf(port);
                if (!PolicyHostRe.IsMatch(StrMember(h, "host")) || pi == null || pi < 1 || pi > 65535) throw new ArgumentException("bad_net_need");
                hosts.Add(StrMember(h, "host") + ":" + ((long)pi.Value).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        if (hosts.Count > 0 && proxyPort == null) throw new ArgumentException("net_needs_proxy: network access exists only through the egress proxy; pass its port");
        double? pp = null;
        if (proxyPort != null)
        {
            pp = IntOf(proxyPort);
            if (pp == null || pp < 1 || pp > 65535) throw new ArgumentException("bad_proxy_port");
        }
        return new D
        {
            ["v"] = 1L,
            ["fs"] = new D { ["read"] = Strs(read), ["write"] = Strs(write), ["exec"] = Strs(exec) },
            ["net"] = new D { ["proxy"] = pp == null ? null : new D { ["host"] = "127.0.0.1", ["port"] = (long)pp.Value }, ["hosts"] = Strs(hosts) },
        };
    }

    static L Strs(IEnumerable<string> xs) => xs.Select(x => (object?)x).ToList();

    // ---- profiles ----

    static readonly string[] Base = SortedOrd("read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64", "fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep", "clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "uname", "tgkill", "exit", "exit_group");
    static readonly string[] Net = SortedOrd("connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown");
    static readonly string[] Exec = { "execve", "execveat" };

    static string[] SortedOrd(params string[] xs)
    {
        var l = xs.ToList();
        l.Sort(StringComparer.Ordinal);
        return l.ToArray();
    }

    static D Rule(IEnumerable<string> names, L? args = null)
    {
        var m = new D { ["names"] = Strs(names), ["action"] = "SCMP_ACT_ALLOW" };
        if (args != null) m["args"] = args;
        return m;
    }

    static D Obj(object? o) => (D)o!;
    static object? ProxyOf(D p) => Obj(p["net"])["proxy"];

    /// <summary>Docker/OCI-format seccomp profile: deny by default; network syscalls only with a proxy; <c>socket</c> only for AF_INET/AF_INET6; exec only when the grant names a binary.</summary>
    public static D SeccompProfile(D p)
    {
        var syscalls = new L { Rule(Base) };
        if (ProxyOf(p) != null)
        {
            syscalls.Add(Rule(Net));
            foreach (long d in new long[] { 2, 10 })
                syscalls.Add(Rule(new[] { "socket" }, new L { new D { ["index"] = 0L, ["value"] = d, ["op"] = "SCMP_CMP_EQ" } }));
        }
        if (((L)Obj(p["fs"])["exec"]!).Count > 0) syscalls.Add(Rule(Exec));
        var arch = new L();
        foreach (var a in new[] { "SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64" }) arch.Add(new D { ["architecture"] = a, ["subArchitectures"] = new L() });
        return new D { ["defaultAction"] = "SCMP_ACT_ERRNO", ["defaultErrnoRet"] = 1L, ["archMap"] = arch, ["syscalls"] = syscalls };
    }

    static IEnumerable<string> Prefixed(string prefix, IEnumerable<string> xs) => xs.Select(x => prefix + x);

    /// <summary>Landlock ruleset (kernel UAPI access-right names; network rules need ABI 4). Handle every right, allow only what the grant names.</summary>
    public static D LandlockRuleset(D p)
    {
        var handledFs = Prefixed("LANDLOCK_ACCESS_FS_", new[] { "EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE" });
        var fsP = Obj(p["fs"]);
        var read = (L)fsP["read"]!; var write = (L)fsP["write"]!; var exec = (L)fsP["exec"]!;
        var paths = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var x in read) paths.Add((string)x!);
        foreach (var x in write) paths.Add((string)x!);
        foreach (var x in exec) paths.Add((string)x!);
        var fs = new L();
        foreach (var path in paths)
        {
            var acc = new List<string>();
            void Add(params string[] xs) { foreach (var x in xs) if (!acc.Contains(x)) acc.Add(x); }
            if (exec.Contains(path)) Add("EXECUTE", "READ_FILE"); // execve opens the binary for reading
            if (read.Contains(path)) Add("READ_FILE", "READ_DIR");
            if (write.Contains(path)) Add("WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR");
            fs.Add(new D { ["path"] = path, ["access"] = Strs(Prefixed("LANDLOCK_ACCESS_FS_", acc)) });
        }
        var net = new L();
        var proxy = ProxyOf(p);
        if (proxy != null) net.Add(new D { ["port"] = Obj(proxy)["port"], ["access"] = new L { "LANDLOCK_ACCESS_NET_CONNECT_TCP" } });
        return new D
        {
            ["v"] = 1L,
            ["abi_min"] = 4L,
            ["handled_access_fs"] = Strs(handledFs),
            ["handled_access_net"] = new L { "LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP" },
            ["rules"] = new D { ["fs"] = fs, ["net"] = net },
        };
    }

    /// <summary>macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; the base lines are what a dynamically linked binary needs to start.</summary>
    public static string MacosProfile(D p)
    {
        var lines = new List<string>
        {
            "(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)", "(allow file-read-metadata)",
            "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/private/var/db/dyld\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))",
        };
        var fs = Obj(p["fs"]);
        foreach (var x in (L)fs["exec"]!)
        {
            lines.Add("(allow process-exec (literal \"" + x + "\"))");
            lines.Add("(allow file-read* (literal \"" + x + "\"))");
        }
        foreach (var r in (L)fs["read"]!) lines.Add("(allow file-read* (subpath \"" + r + "\"))");
        foreach (var w in (L)fs["write"]!) lines.Add("(allow file-write* (subpath \"" + w + "\"))");
        var proxy = ProxyOf(p);
        if (proxy != null) lines.Add("(allow network-outbound (remote tcp \"localhost:" + JsJson.ToJsString(Obj(proxy)["port"]) + "\"))");
        return string.Join("\n", lines) + "\n";
    }

    // ---- confine ----

    static string ShortName(object? n) => Regex.Replace((string)n!, "^LANDLOCK_ACCESS_", "");
    static string JoinShort(L xs) => string.Join(",", xs.Select(ShortName));

    /// <summary>The flags of a reference confinement helper for a policy; run as <c>helper flags -- command</c>. Flattens the GENERATED profiles.</summary>
    public static List<string> ConfineArgs(D policy)
    {
        var ll = LandlockRuleset(policy);
        var sc = SeccompProfile(policy);
        var rules = Obj(ll["rules"]);
        var netRules = (L)rules["net"]!;
        var args = new List<string> { "--fs-handled", JoinShort((L)ll["handled_access_fs"]!) };
        if (netRules.Count > 0 || ProxyOf(policy) != null)
        {
            args.Add("--net-handled");
            args.Add(JoinShort((L)ll["handled_access_net"]!));
        }
        foreach (var r in (L)rules["fs"]!)
        {
            var m = Obj(r);
            args.Add("--fs");
            args.Add(m["path"] + ":" + JoinShort((L)m["access"]!));
        }
        foreach (var r in netRules)
        {
            var m = Obj(r);
            args.Add("--net");
            args.Add(JsJson.ToJsString(m["port"]) + ":" + JoinShort((L)m["access"]!));
        }
        foreach (var s in (L)sc["syscalls"]!)
        {
            var m = Obj(s);
            var names = (L)m["names"]!;
            if (m.GetValueOrDefault("args") != null)
            {
                foreach (var a in (L)m["args"]!)
                {
                    var am = Obj(a);
                    foreach (var n in names) { args.Add("--allow-arg"); args.Add(n + ":" + JsJson.ToJsString(am["index"]) + ":" + JsJson.ToJsString(am["value"])); }
                }
            }
            else foreach (var n in names) { args.Add("--allow"); args.Add((string)n!); }
        }
        return args;
    }

    // ---- runtime claims ----

    static readonly HashSet<string> ClaimKeys = new() { "v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig" };

    static byte[] ClaimBody(object? claimWithoutSig) => Encoding.UTF8.GetBytes(RuntimeClaimDomain).Concat(IntentJs.CanonBytes(claimWithoutSig)).ToArray();

    /// <summary>Sign a claim (class, passport_digest, evidence_digest, iat, exp) with the attestor's Ed25519 key (a 32-byte seed). Returns the claim with v, attestor and sig.</summary>
    public static D SignRuntimeClaim(byte[] secretKey, byte[] publicKey, D c)
    {
        var unsigned = new D { ["v"] = 1L };
        foreach (var (k, v) in c) unsigned[k] = v;
        unsigned["attestor"] = Pca.B64u(publicKey);
        using var key = EdKey.FromSeed(secretKey); // a seed of any other length throws
        var sig = key.Sign(ClaimBody(unsigned));
        var o = new D(unsigned) { ["sig"] = Pca.B64u(sig) };
        return o;
    }

    static bool NegZero(object? o) => IntentJs.NumOf(o) is double d && IntentJs.IsNegZero(d);
    /// <summary>A safe integer &gt;= 0, never -0: a negative time is never valid.</summary>
    static bool Nat(object? o) => IntOf(o) is double d && !NegZero(o) && d >= 0 && d <= 9007199254740991.0;
    /// <summary>A non-empty string of at most 128 UTF-16 code units.</summary>
    static bool Str128(object? o) => o is string s && s.Length > 0 && s.Length <= 128;
    static bool Includes(object? list, object? x) => list is L l && l.Any(e => e is string a && x is string b && a == b);

    /// <summary>The class the claim proves, or "none" for anything missing, unsigned, unpinned, expired, for another passport or malformed.
    /// <paramref name="trust"/> carries pinnedAttestors, passportDigest, verifiedEvidenceDigests and now.</summary>
    public static string VerifiedRuntimeClass(object? claim, object? trust)
    {
        try
        {
            if (claim is not D c || trust is not D t) return "none";
            if (c.Count != ClaimKeys.Count || !c.Keys.All(ClaimKeys.Contains)) return "none";
            var v = IntentJs.NumOf(c.GetValueOrDefault("v"));
            if (v == null || v != 1.0 || c.GetValueOrDefault("class") is not string cls || !RuntimeClasses.Contains(cls)) return "none";
            if (c.GetValueOrDefault("sig") is not string sig || c.GetValueOrDefault("attestor") is not string attestor || !Str128(attestor)
                || !Str128(c.GetValueOrDefault("passport_digest")) || !Str128(c.GetValueOrDefault("evidence_digest")) || !Includes(t.GetValueOrDefault("pinnedAttestors"), attestor)) return "none";
            var now = t.GetValueOrDefault("now");
            var pd = c.GetValueOrDefault("passport_digest");
            if (pd == null || !(t.GetValueOrDefault("passportDigest") is string tp && pd is string pds && pds == tp)) return "none";
            if (!Nat(c.GetValueOrDefault("iat")) || !Nat(c.GetValueOrDefault("exp")) || !Nat(now)) return "none";
            if (IntentJs.NumOf(now)! < IntentJs.NumOf(c["iat"])! || IntentJs.NumOf(now)! >= IntentJs.NumOf(c["exp"])!) return "none";
            if (c.GetValueOrDefault("evidence_digest") is not string ed || !Includes(t.GetValueOrDefault("verifiedEvidenceDigests"), ed)) return "none";
            var rest = new D(c);
            rest.Remove("sig");
            return Pca.VerifyEdInternal(attestor, ClaimBody(rest), sig) ? cls : "none";
        }
        catch (Exception) { return "none"; }
    }

    /// <summary>hashCanonical of the signed passport a claim is about.</summary>
    public static string PassportDigest(object? signedPassport) => Pca.HashCanonical(signedPassport);

    /// <summary>The digest a claim's evidence_digest must equal for this attestation document.</summary>
    public static string EvidenceDigest(object? document) => Pca.HashCanonical(document);

    /// <summary>Run an attestation verifier over the evidence; only if it answers {ok: true, bound: true} is the evidence's digest admitted into the
    /// trust. Anything else (a throw, a malformed answer, not bound) leaves the list empty, so every claim is "none".</summary>
    public static D TrustFromAttestation(object? document, Func<object?> verify, long nowMs, IEnumerable<string> pinnedAttestors, string passportDigest)
    {
        bool ok;
        try { ok = verify() is D h && h.GetValueOrDefault("ok") is true && h.GetValueOrDefault("bound") is true; }
        catch (Exception) { ok = false; }
        var digests = new L();
        if (ok) digests.Add(EvidenceDigest(document));
        return new D { ["pinnedAttestors"] = Strs(pinnedAttestors), ["passportDigest"] = passportDigest, ["verifiedEvidenceDigests"] = digests, ["now"] = nowMs };
    }

    // ---- reference tool / component (hand-assembled WebAssembly for tests, demos and guides) ----

    static void U(List<byte> o, double n)
    {
        do
        {
            int b = (int)(long)n & 0x7f;
            n = Math.Floor(n / 128);
            if (n > 0) b |= 0x80;
            o.Add((byte)b);
        } while (n > 0);
    }

    static byte[] U(double n) { var o = new List<byte>(); U(o, n); return o.ToArray(); }

    static void Sleb(List<byte> o, double d)
    {
        int n = (int)(long)d;
        for (; ; )
        {
            int b = n & 0x7f;
            n >>= 7;
            if ((n == 0 && (b & 0x40) == 0) || (n == -1 && (b & 0x40) != 0)) { o.Add((byte)b); return; }
            o.Add((byte)(b | 0x80));
        }
    }

    static void I32c(List<byte> o, double n) { o.Add(0x41); Sleb(o, n); }

    /// <summary>A name with the reference's habit of writing its UTF-16 length as the length prefix.</summary>
    static byte[] Name(string x)
    {
        var o = new List<byte>();
        U(o, x.Length);
        o.AddRange(Encoding.UTF8.GetBytes(x));
        return o.ToArray();
    }

    static byte[] Bs(params int[] xs) => xs.Select(x => (byte)x).ToArray();
    static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    static byte[] Vec(IReadOnlyList<byte[]> items) => Cat(new[] { U(items.Count) }.Concat(items).ToArray());
    static byte[] Section(int id, byte[] body) => Cat(Bs(id), U(body.Length), body);
    static readonly byte[] WasmHeader = Bs(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0);

    static double NumArg(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");

    /// <summary>A module that calls <c>pca:act.invoke(handle, ptr, cap)</c> for each call of spec.calls and returns either the last call's return code or
    /// the first byte of linear memory. spec: calls [{handle, ptr, cap}], returns ("last" | "byte0"), extraImports [{module, name}], memory {min, max (null: none)}, spin.</summary>
    public static byte[] BuildTool(D spec)
    {
        var extra = spec.GetValueOrDefault("extraImports") as L ?? new L();
        var calls = (L)spec["calls"]!;
        var types = Vec(new[] { Bs(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), Bs(0x60, 0, 1, 0x7f), Bs(0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f) });
        var imp = new List<byte[]> { Cat(Name("pca:act"), Name("invoke"), Bs(0, 0)) };
        foreach (var e in extra) imp.Add(Cat(Name(StrMemberOf(e, "module")), Name(StrMemberOf(e, "name")), Bs(0, 2)));
        double min = 1, max = 1;
        bool noMax = false;
        if (spec.GetValueOrDefault("memory") is D mm)
        {
            min = NumArg(mm.GetValueOrDefault("min"));
            if (mm.GetValueOrDefault("max") == null) noMax = true; else max = NumArg(mm["max"]);
        }
        var memory = Vec(new[] { noMax ? Cat(Bs(0), U(min)) : Cat(Bs(1), U(min), U(max)) });
        int runIndex = 1 + extra.Count;
        var body = new List<byte> { 0 };
        bool last = spec.GetValueOrDefault("returns") is not "byte0";
        for (int i = 0; i < calls.Count; i++)
        {
            var c = (D)calls[i]!;
            I32c(body, NumArg(c.GetValueOrDefault("handle")));
            I32c(body, NumArg(c.GetValueOrDefault("ptr")));
            I32c(body, NumArg(c.GetValueOrDefault("cap")));
            body.Add(0x10); body.Add(0);
            if (!(i == calls.Count - 1 && last)) body.Add(0x1a);
        }
        if (JsX.Truthy(spec.GetValueOrDefault("spin"))) body.AddRange(Bs(0x03, 0x40, 0x0c, 0x00, 0x0b));
        if (spec.GetValueOrDefault("returns") is "byte0") { I32c(body, 0); body.AddRange(Bs(0x2d, 0, 0)); }
        if (calls.Count == 0) I32c(body, 0);
        body.Add(0x0b);
        var bodyB = body.ToArray();
        var code = Vec(new[] { Cat(U(bodyB.Length), bodyB) });
        var exports = Vec(new[] { Cat(Name("memory"), Bs(2, 0)), Cat(Name("run"), Bs(0), U(runIndex)) });
        return Cat(WasmHeader, Section(1, types), Section(2, Vec(imp)), Section(3, Vec(new[] { Bs(1) })), Section(5, memory), Section(7, exports), Section(10, code));
    }

    static string StrMemberOf(object? o, string k) => o == null ? throw new ArgumentException("cannot read '" + k + "' of null") : StrMember(o, k);

    /// <summary>A tool that asks the table what it holds: returns <c>handle_count() * 256 + first byte of handle 1's verb</c> (the verb window is <paramref name="cap"/> bytes).</summary>
    public static byte[] BuildProbeTool(object? cap = null)
    {
        double capN = cap == null ? 64 : NumArg(cap);
        var types = Vec(new[] { Bs(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), Bs(0x60, 0, 1, 0x7f) });
        var imports = Vec(new[]
        {
            Cat(Name("pca:act"), Name("invoke"), Bs(0, 0)),
            Cat(Name("pca:act"), Name("handle_count"), Bs(0, 1)),
            Cat(Name("pca:act"), Name("handle_verb"), Bs(0, 0)),
        });
        var body = new List<byte> { 0 };
        I32c(body, 1); I32c(body, 0); I32c(body, capN);
        body.AddRange(Bs(0x10, 2, 0x1a, 0x10, 1));
        I32c(body, 256);
        body.Add(0x6c);
        I32c(body, 0);
        body.AddRange(Bs(0x2d, 0, 0, 0x6a, 0x0b));
        var bodyB = body.ToArray();
        var code = Vec(new[] { Cat(U(bodyB.Length), bodyB) });
        var exports = Vec(new[] { Cat(Name("memory"), Bs(2, 0)), Cat(Name("run"), Bs(0, 3)) });
        return Cat(WasmHeader, Section(1, types), Section(2, imports), Section(3, Vec(new[] { Bs(1) })), Section(5, Vec(new[] { Bs(1, 1, 1) })), Section(7, exports), Section(10, code));
    }

    const string ComponentTemplate = ""
        + "(component\n"
        + "  (import \"pca:act/invoke@0.1.0\" (instance $inv\n"
        + "    (export \"handle-count\" (func (result u32)))\n"
        + "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))\n"
        + "  @EXTRA@\n"
        + "  (core module $libc\n"
        + "    (memory (export \"memory\") 1 1)\n"
        + "    (global $bump (mut i32) (i32.const 1024))\n"
        + "    (func (export \"realloc\") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)\n"
        + "      (local $p i32)\n"
        + "      (local.set $p (global.get $bump))\n"
        + "      (global.set $bump (i32.add (local.get $p) (local.get $new)))\n"
        + "      (local.get $p)))\n"
        + "  (core instance $libc (instantiate $libc))\n"
        + "  (alias core export $libc \"memory\" (core memory $mem))\n"
        + "  (alias core export $libc \"realloc\" (core func $realloc))\n"
        + "  (core func $count (canon lower (func $inv \"handle-count\")))\n"
        + "  (core func $invoke (canon lower (func $inv \"invoke\") (memory $mem) (realloc $realloc)))\n"
        + "  (core module $main\n"
        + "    (import \"libc\" \"memory\" (memory 1))\n"
        + "    (import \"host\" \"count\" (func $count (result i32)))\n"
        + "    (import \"host\" \"invoke\" (func $invoke (param i32 i32)))\n"
        + "    (func (export \"run\") (result i32)\n"
        + "      @BODY@))\n"
        + "  (core instance $host (export \"count\" (func $count)) (export \"invoke\" (func $invoke)))\n"
        + "  (core instance $main (instantiate $main (with \"libc\" (instance $libc)) (with \"host\" (instance $host))))\n"
        + "  (alias core export $main \"run\" (core func $run))\n"
        + "  (func $lifted (result s32) (canon lift (core func $run)))\n"
        + "  (export \"run\" (func $lifted)))\n";

    /// <summary>The reference tool as a component in the WebAssembly text format. Options: handle (default 1), spin (loop forever), extraImport (an import the host must refuse). Null means all defaults.</summary>
    public static string ReferenceComponentWat(D? o = null)
    {
        var extraImport = o?.GetValueOrDefault("extraImport");
        var extra = JsX.Truthy(extraImport)
            ? "(import \"" + JsJson.ToJsString(extraImport) + "\" (instance (export \"get-arguments\" (func (result (list string))))))"
            : "";
        string body;
        if (o != null && JsX.Truthy(o.GetValueOrDefault("spin"))) body = "(loop $l (br $l)) (i32.const 0)";
        else
        {
            var h = o?.GetValueOrDefault("handle");
            body = "(call $invoke (i32.const " + (h == null ? "1" : JsJson.ToJsString(h)) + ") (i32.const 16))\n"
                + "       (if (result i32) (i32.load8_u (i32.const 16))\n"
                + "         (then (i32.load (i32.const 20)))\n"
                + "         (else (i32.load8_u (i32.load (i32.const 20)))))";
        }
        return ComponentTemplate.Replace("@EXTRA@", extra).Replace("@BODY@", body);
    }
}
