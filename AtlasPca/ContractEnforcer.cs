using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The decision of <see cref="ContractEnforcer.Check"/>: <c>Reason</c> is <c>ok</c>, <c>violated</c>, <c>latched</c>, <c>permission</c>, <c>state-error</c> or <c>store-error</c>.</summary>
public sealed record EnforceResult(bool Allow, string Reason, IReadOnlyList<string> Violated, IReadOnlyList<string> Reasons, long Seq);

public sealed class ContractEnforcerError : Exception
{
    public ContractEnforcerError(string m) : base("ContractEnforcer: " + m) { }
}

/// <summary>Runtime enforcement of a signed contract over a durable key-value store (<see cref="IAtomicKv"/>): each admitted action advances ONE hash-chained state under an atomic
/// read-modify-write, a contract violation latches (nothing is admitted until the principal signs a reset for that sequence), and any store fault is a denial.</summary>
public sealed class ContractEnforcer
{
    public const string ResetDomain = "atlas-pca/contract-reset/v1\0";
    readonly IAtomicKv _kv;
    readonly JD _contract;
    readonly string _id, _key;
    readonly Func<double> _now;
    readonly bool _latch;

    ContractEnforcer(IAtomicKv kv, JD contract, string key, Func<double> now, bool latch) { _kv = kv; _contract = contract; _id = (string)contract["id"]!; _key = key; _now = now; _latch = latch; }

    /// <summary>Throws <see cref="ContractEnforcerError"/> unless the contract verifies under the pinned <paramref name="principal"/> (no trust on first use).</summary>
    public static ContractEnforcer Open(IAtomicKv kv, JD contract, string principal, string? key = null, Func<double>? now = null, bool latchOnViolation = true)
    {
        if (string.IsNullOrEmpty(principal)) throw new ContractEnforcerError("a pinned principal is required");
        var v = Contracts.Verify(contract, principal);
        if (!v.Ok) throw new ContractEnforcerError($"contract refused: {v.Reason}");
        return new ContractEnforcer(kv, contract, key ?? $"contract/{(string)contract["id"]!}", now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()), latchOnViolation);
    }

    static byte[] ResetMsg(string id, long seq) => Encoding.UTF8.GetBytes(ResetDomain).Concat(SHA256.HashData(Encoding.UTF8.GetBytes($"{id}:{seq}"))).ToArray();

    /// <summary>The principal's authorisation to un-latch <paramref name="contractId"/> at sequence <paramref name="seq"/> (it binds both, so it cannot be replayed later).</summary>
    public static string SignReset(EdKey principal, string contractId, long seq) => Pca.B64u(principal.Sign(ResetMsg(contractId, seq)));

    bool IsDoc(object? d)
    {
        if (d is not JD x || !(IntentJs.NumOf(x.GetValueOrDefault("v")) == 1) || !Equals(x.GetValueOrDefault("contract_id"), _id) || Prohibitions.StateProblem(x.GetValueOrDefault("state")) != null) return false;
        if (!x.ContainsKey("latched")) return true;
        return x["latched"] is JD l && IntentJs.NumOf(l.GetValueOrDefault("seq")) is double s && Math.Floor(s) == s && !IntentJs.IsNegZero(s) && l.GetValueOrDefault("violated") is JL v && v.All(e => e is string);
    }

    static long SeqOf(JD doc) => (long)IntentJs.NumOf(((JD)doc["state"]!)["seq"])!.Value;
    static string[] Strs(object? l) => ((JL)l!).Select(e => (string)e!).ToArray();
    static object NumObj(double d) => d == Math.Floor(d) && Math.Abs(d) < 9e15 ? (object)(long)d : d;

    JD? Read(out bool corrupt)
    {
        corrupt = false;
        var s = _kv.Get(_key);
        if (s == null) return null;
        object? d;
        try { d = Pca.ParseJson(s); } catch (Exception) { corrupt = true; return null; }
        if (!IsDoc(d)) { corrupt = true; return null; }
        return (JD)d!;
    }

    /// <summary>Checks one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws.</summary>
    public EnforceResult Check(Dictionary<string, object?>? action, bool permitted = true)
    {
        var o = new EnforceResult(false, "store-error", Array.Empty<string>(), new[] { "store unavailable" }, 0);
        try
        {
            var wall = _now();
            _kv.Update(_key, prevText =>
            {
                JD? prev = null;
                if (prevText != null)
                {
                    object? d; try { d = Pca.ParseJson(prevText); } catch (Exception) { d = null; }
                    if (!IsDoc(d))
                    {
                        o = new(false, "state-error", Array.Empty<string>(), new[] { "<state>: stored state is corrupt or belongs to another contract" }, 0);
                        return null;
                    }
                    prev = (JD)d!;
                    if (!double.IsFinite(wall))
                    {
                        o = new(false, "state-error", Array.Empty<string>(), new[] { "<state>: clock is not finite" }, SeqOf(prev));
                        return null;
                    }
                }
                var doc = prev ?? new JD { ["v"] = 1L, ["contract_id"] = _id, ["state"] = Prohibitions.EmptyState(double.IsFinite(wall) ? (long)wall : 0) };
                var state = (JD)doc["state"]!;
                if (doc.GetValueOrDefault("latched") is JD lt)
                {
                    o = new(false, "latched", Strs(lt["violated"]), new[] { $"<latched>: contract violated at seq {JsCanon.NumberString(IntentJs.NumOf(lt["seq"])!.Value)}" }, SeqOf(doc));
                    return null;
                }
                var (r, allow) = Contracts.CheckAndAdvance(permitted, state, action, _contract, SeqOf(doc), null, Math.Max(wall, IntentJs.NumOf(state["now"])!.Value));
                if (allow)
                {
                    o = new(true, "ok", Array.Empty<string>(), Array.Empty<string>(), (long)IntentJs.NumOf(r.Next["seq"])!.Value);
                    return Pca.Canonicalize(new JD(doc) { ["state"] = r.Next });
                }
                var structural = r.DecidedBy == "state";
                var real = !structural && r.Violated.Count > 0;
                o = new(false, structural ? "state-error" : real ? "violated" : "permission", real ? r.Violated : Array.Empty<string>(), r.Reasons, SeqOf(doc));
                return real && _latch ? Pca.Canonicalize(new JD(doc) { ["latched"] = new JD { ["seq"] = SeqOf(doc), ["violated"] = r.Violated.Select(v => (object?)v).ToList() } }) : null;
            });
        }
        catch (Exception) { o = new(false, "store-error", Array.Empty<string>(), new[] { "store error (fail closed)" }, 0); }
        return o;
    }

    /// <summary>Read-only evaluation against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay counter is spent. Never throws.</summary>
    public EnforceResult Peek(Dictionary<string, object?>? action)
    {
        try
        {
            var doc = Read(out var corrupt);
            if (corrupt) return new(false, "state-error", Array.Empty<string>(), new[] { "<state>: stored state is corrupt or belongs to another contract" }, 0);
            if (doc?.GetValueOrDefault("latched") is JD lt)
                return new(false, "latched", Strs(lt["violated"]), new[] { $"<latched>: contract violated at seq {JsCanon.NumberString(IntentJs.NumOf(lt["seq"])!.Value)}" }, SeqOf(doc));
            var wall = _now();
            var r = Contracts.Check(action, _contract, doc?["state"] ?? Prohibitions.EmptyState(double.IsFinite(wall) ? (long)wall : 0));
            var seq = doc != null ? SeqOf(doc) : 0;
            return r.Ok ? new(true, "ok", Array.Empty<string>(), Array.Empty<string>(), seq) : new(false, "violated", r.Violated, r.Reasons, seq);
        }
        catch (Exception) { return new(false, "store-error", Array.Empty<string>(), new[] { "store error (fail closed)" }, 0); }
    }

    /// <summary>The current stored state (and whether it is latched), or null when nothing was admitted yet. Throws <see cref="ContractEnforcerError"/> on a corrupt document.</summary>
    public (JD State, bool Latched)? State()
    {
        var doc = Read(out var corrupt);
        if (corrupt) throw new ContractEnforcerError("stored state is corrupt or belongs to another contract");
        return doc == null ? null : ((JD)doc["state"]!, doc.ContainsKey("latched"));
    }

    /// <summary>Un-latches with the principal's signature (see <see cref="SignReset"/>) at the latched sequence. Returns whether it cleared.</summary>
    public bool Reset(string sig)
    {
        bool cleared = false;
        try
        {
            _kv.Update(_key, prevText =>
            {
                if (prevText == null) return null;
                object? d; try { d = Pca.ParseJson(prevText); } catch (Exception) { return null; }
                if (!IsDoc(d) || ((JD)d!).GetValueOrDefault("latched") is not JD lt) return null;
                var seq = (long)IntentJs.NumOf(lt["seq"])!.Value;
                if (sig == null || !Pca.VerifyEdInternal((string)_contract["principal"]!, ResetMsg(_id, seq), sig)) return null;
                cleared = true;
                var rest = new JD((JD)d!); rest.Remove("latched");
                return Pca.Canonicalize(rest);
            });
        }
        catch (Exception) { return false; }
        return cleared;
    }
}
