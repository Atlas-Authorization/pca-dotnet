// A per-sandbox capability table (a CSpace): indices are small integers meaningful only inside one table, like file descriptors. A slot exists only
// because a verified authorization allowed exactly that operation, so the authority a tool holds is the set of operations someone with the right to
// approve them approved. Derivation is monotone; revoking a slot revokes everything derived from it. Handle indices are 1-based.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Sandbox;

/// <summary>What a tool may do with a handle: run the one authorized operation. A null result or a throw is an executor error.</summary>
public delegate byte[]? SandboxExecutor(string verb, string resource, D @params);

public static partial class PcaSandbox
{
    /// <summary>Outcome of a handle use.</summary>
    public sealed record UseResult(bool Ok, byte[]? Result, string? Reason)
    {
        /// <summary>{ok:true, result} or {ok:false, reason}.</summary>
        public D ToMap() => Ok ? new D { ["ok"] = true, ["result"] = Result } : new D { ["ok"] = false, ["reason"] = Reason };
    }

    /// <summary>Options of <see cref="HandleTable.Mint"/>: JSON numbers (null for the default) and an optional minimum runtime class.</summary>
    public sealed class MintOptions
    {
        /// <summary>How many times the handle may be used. Default 1.</summary>
        public object? Uses;
        /// <summary>Epoch ms after which the handle is spent. Default never.</summary>
        public object? ExpiresAt;
        /// <summary>Refuse to mint into a table below this class.</summary>
        public string? Requires;
    }

    sealed class Slot
    {
        public string Verb = "", Resource = "", ParamsDigest = "", OpId = "";
        public D Params = new();
        public long Uses;
        public double ExpiresAt;
        public bool Revoked;
        public readonly List<int> Children = new();
    }

    static object? DeepCopy(object? v) => v switch
    {
        D m => m.ToDictionary(e => e.Key, e => DeepCopy(e.Value)),
        L l => l.Select(DeepCopy).ToList(),
        _ => v,
    };

    /// <summary>The capability table of one sandbox.</summary>
    public sealed class HandleTable
    {
        readonly List<Slot> _slots = new();
        readonly string _runtimeClass;
        readonly ReceiptLog _log;
        readonly IReadOnlyDictionary<string, SandboxExecutor> _executors;
        readonly Func<double> _now;
        readonly object _lock = new();

        public HandleTable(string runtimeClass, ReceiptLog log, IReadOnlyDictionary<string, SandboxExecutor> executors, Func<double>? now = null)
        {
            _runtimeClass = runtimeClass; _log = log; _executors = executors;
            _now = now ?? (() => (double)AtlasPca.ReplayClock.NowMs());
        }

        public string RuntimeClass => _runtimeClass;
        public int Size { get { lock (_lock) return _slots.Count; } }

        Slot? SlotAt(long index) => index >= 1 && index <= _slots.Count ? _slots[(int)(index - 1)] : null;

        int Push(Slot s) { _slots.Add(s); return _slots.Count; }

        Slot? Live(long index)
        {
            var s = SlotAt(index);
            return s != null && !s.Revoked && s.Uses > 0 && _now() < s.ExpiresAt ? s : null;
        }

        /// <summary>Mint a handle for the operation <paramref name="result"/> allowed. Throws (fail closed) if the result does not allow exactly the operation.</summary>
        public int Mint(AuthorizeResult result, Operation operation, MintOptions? opts = null)
        {
            opts ??= new MintOptions();
            if (opts.Requires != null && !SatisfiesRuntimeClass(_runtimeClass, opts.Requires))
                throw new ArgumentException("runtime_class_too_weak: table is " + _runtimeClass + ", grant requires " + opts.Requires);
            if (!Pca.IsAuthorizedFor(result, operation)) throw new ArgumentException("not_authorized: result does not allow exactly this operation");
            var u = IntOf(opts.Uses ?? 1L);
            if (u == null || u < 1 || u > 1_000_000) throw new ArgumentException("bad_uses");
            var prms = (D)DeepCopy(operation.Params)!;
            var s = new Slot
            {
                Verb = operation.Verb,
                Resource = operation.Resource,
                Params = prms,
                ParamsDigest = Pca.HashCanonical(prms),
                OpId = result.Operation?.Id ?? "",
                Uses = (long)u.Value,
                ExpiresAt = opts.ExpiresAt == null ? double.PositiveInfinity : IntentJs.NumOf(opts.ExpiresAt) ?? double.PositiveInfinity,
            };
            lock (_lock) return Push(s);
        }

        /// <summary>Derive a narrower handle: takes <paramref name="uses"/> from the parent (never more than it has) and an expiry no later than the parent's.</summary>
        public int Attenuate(long index, object? uses = null, object? expiresAt = null)
        {
            lock (_lock)
            {
                var p = Live(index) ?? throw new ArgumentException("unknown_handle");
                var u = IntOf(uses ?? p.Uses);
                if (u == null || u < 1 || u > p.Uses) throw new ArgumentException("attenuate_widens");
                double? ex = expiresAt == null ? p.ExpiresAt : IntentJs.NumOf(expiresAt);
                if (ex == null || !(ex <= p.ExpiresAt)) throw new ArgumentException("attenuate_widens");
                p.Uses -= (long)u.Value;
                var c = new Slot
                {
                    Verb = p.Verb, Resource = p.Resource, Params = (D)DeepCopy(p.Params)!, ParamsDigest = p.ParamsDigest, OpId = p.OpId,
                    Uses = (long)u.Value, ExpiresAt = ex.Value,
                };
                var child = Push(c);
                p.Children.Add(child);
                return child;
            }
        }

        /// <summary>Revoke a handle and, transitively, every handle derived from it.</summary>
        public void Revoke(long index)
        {
            lock (_lock)
            {
                var s = SlotAt(index);
                if (s == null || s.Revoked) return;
                s.Revoked = true;
                foreach (var c in s.Children) Revoke(c);
            }
        }

        /// <summary>The verb a handle carries, or null.</summary>
        public string? VerbOf(long index) { lock (_lock) return SlotAt(index)?.Verb; }

        /// <summary>Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs and stays
        /// consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).</summary>
        public UseResult Use(long index)
        {
            Slot s; SandboxExecutor exec; string verb, resource; D prms;
            lock (_lock)
            {
                var found = SlotAt(index);
                if (found == null)
                {
                    _log.Append(_runtimeClass, Body("", "", "", "", "refused", "unknown_handle"));
                    return new UseResult(false, null, "unknown_handle");
                }
                s = found;
                var live = Live(index);
                if (live == null) return Finish(s, new UseResult(false, null, "spent"));
                if (!_executors.TryGetValue(s.Verb, out var e) || e == null) return Finish(s, new UseResult(false, null, "no_executor"));
                exec = e;
                live.Uses -= 1;
                verb = s.Verb; resource = s.Resource; prms = (D)DeepCopy(s.Params)!;
            }
            UseResult r;
            try
            {
                var result = exec(verb, resource, prms);
                r = result == null ? new UseResult(false, null, "executor_error") : new UseResult(true, result, null);
            }
            catch (Exception) { r = new UseResult(false, null, "executor_error"); }
            lock (_lock) return Finish(s, r);
        }

        UseResult Finish(Slot s, UseResult r)
        {
            var outcome = r.Ok ? "ok" : r.Reason == "executor_error" ? "error" : "refused";
            _log.Append(_runtimeClass, Body(s.OpId, s.Verb, s.Resource, s.ParamsDigest, outcome, r.Ok ? "used" : r.Reason!));
            return r;
        }
    }

    static D Body(string opId, string verb, string resource, string paramsDigest, string outcome, string reason) => new()
    {
        ["kind"] = "handle_use",
        ["subject"] = new D { ["op_id"] = opId, ["verb"] = verb, ["resource"] = resource, ["params_digest"] = paramsDigest },
        ["outcome"] = outcome,
        ["reason"] = reason,
    };
}
