// ERC-7715 (wallet_requestExecutionPermissions) for PCA grants: the mapping of a grant to a permission request, the supported-permissions
// filter, revoke params and the check of what the wallet actually granted (packages/pca-erc7715; the TypeScript is authoritative).
// Pure mapping and verification: no chain access, no redemption through a delegation manager. Values are JSON trees and are read with the
// reference's JavaScript semantics (String() coercion, RegExp.test coercion, BigInt parsing), because a wallet's response is untrusted input.
using System.Globalization;
using System.Numerics;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Erc7715;

public static class Erc7715
{
    const string NativeType = "native-token-allowance";
    const string Erc20Type = "erc20-token-allowance";
    static readonly Regex HexAddr = new(@"\A0x[0-9a-fA-F]{40}\z", RegexOptions.CultureInvariant);
    static readonly Regex HexQty = new(@"\A0x(0|[1-9a-fA-F][0-9a-fA-F]*)\z", RegexOptions.CultureInvariant);
    static readonly Regex Dec = new(@"\A(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant);
    static readonly Regex Ctx = new(@"\A0x[0-9a-fA-F]+\z", RegexOptions.CultureInvariant);

    // ---- JavaScript value semantics over the JSON tree ----

    /// <summary>A member of an object value; every other value has no members (undefined). Null/absent is undefined.</summary>
    static object? Prop(object? o, string k) => o is JD d && d.TryGetValue(k, out var v) ? v : null;

    static bool IsObject(object? o) => o is JD || o is JL;

    /// <summary>Reading a member of null or undefined throws in JavaScript.</summary>
    static object? Read(object? o, string k, bool exists) => !exists ? throw new InvalidOperationException("cannot read a member of undefined") : Prop(o, k);

    /// <summary>String(x): the template-literal text (undefined, null, arrays and objects included).</summary>
    static string Str(object? x, bool present = true) => IntentRevocation.JsText(x, present);

    static string Lower(string s) => s.ToLowerInvariant();

    /// <summary>The reference's <c>lower</c>: a non-string throws.</summary>
    static string LowerOf(object? x) => x is string s ? Lower(s) : throw new InvalidOperationException("toLowerCase of a non-string");

    /// <summary>RegExp.test coerces its argument to a string first.</summary>
    static bool Test(Regex re, object? x, bool present = true) => re.IsMatch(Str(x, present));

    static string Hex(BigInteger n)
    {
        var h = n.ToString("x", CultureInfo.InvariantCulture).TrimStart('0');
        return "0x" + (h.Length == 0 ? "0" : h);
    }

    /// <summary>BigInt(value): numbers must be integers, strings follow StringToBigInt (trimmed, empty is 0, 0x/0o/0b prefixes, optional sign on decimals),
    /// booleans are 0/1, an array or object goes through its string form; null and undefined throw.</summary>
    static BigInteger JsBigInt(object? x, bool present = true)
    {
        switch (x)
        {
            case null: throw new InvalidOperationException("BigInt of " + (present ? "null" : "undefined"));
            case bool b: return b ? BigInteger.One : BigInteger.Zero;
            case Num n:
                {
                    var d = IntentJs.NumOf(n) ?? double.NaN;
                    if (!double.IsFinite(d) || d != Math.Round(d)) throw new InvalidOperationException("BigInt of a non-integer");
                    return new BigInteger(d);
                }
            case string s: return FromString(s);
            default: return FromString(Str(x));
        }
    }

    static BigInteger FromString(string raw)
    {
        var s = raw.Trim(' ', '\t', '\n', '\r', '\v', '\f', ' ', '﻿', '\u2028', '\u2029');
        if (s.Length == 0) return BigInteger.Zero;
        if (s.Length > 2 && s[0] == '0' && (s[1] is 'x' or 'X' or 'o' or 'O' or 'b' or 'B'))
        {
            int radix = char.ToLowerInvariant(s[1]) switch { 'x' => 16, 'o' => 8, _ => 2 };
            BigInteger v = BigInteger.Zero;
            foreach (var ch in s[2..])
            {
                int dgt = ch is >= '0' and <= '9' ? ch - '0' : ch is >= 'a' and <= 'f' ? ch - 'a' + 10 : ch is >= 'A' and <= 'F' ? ch - 'A' + 10 : 99;
                if (dgt >= radix) throw new FormatException("SyntaxError: cannot convert to a BigInt");
                v = v * radix + dgt;
            }
            return v;
        }
        var digits = s.StartsWith('+') || s.StartsWith('-') ? s[1..] : s;
        if (digits.Length == 0 || !digits.All(c => c is >= '0' and <= '9')) throw new FormatException("SyntaxError: cannot convert to a BigInt");
        return BigInteger.Parse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
    }

    // ---- grant -> permission request ----

    /// <summary>The permission request that grants a PCA grant's cap to a session account.
    /// <paramref name="g"/>: <c>{grantDigest, capMinor, expiresAtSec}</c>. <paramref name="o"/>: <c>{chainId (BigInteger), sessionAccount, tokenAddress?, baseUnitsPerMinor,
    /// from?, isAdjustmentAllowed?}</c>. There is no price oracle: <c>baseUnitsPerMinor</c> is an exact integer ratio. Throws on a malformed envelope, address, ratio or chain.</summary>
    public static JD GrantToPermissionRequest(object? g, object? o)
    {
        if (g is not JD gd || !IntentJs.IsSafeInteger(Prop(gd, "capMinor")) || IntentJs.NumOf(gd["capMinor"])!.Value <= 0
            || !IntentJs.IsSafeInteger(Prop(gd, "expiresAtSec")) || IntentJs.NumOf(gd["expiresAtSec"])!.Value <= 0) throw new ArgumentException("grantToPermissionRequest: bad envelope");
        if (o is not JD od) throw new ArgumentException("grantToPermissionRequest: bad address");
        bool hasFrom = od.ContainsKey("from"), hasToken = od.ContainsKey("tokenAddress");
        if (!Test(HexAddr, Prop(od, "sessionAccount"), od.ContainsKey("sessionAccount")) || (hasFrom && !Test(HexAddr, od["from"])) || (hasToken && !Test(HexAddr, od["tokenAddress"])))
            throw new ArgumentException("grantToPermissionRequest: bad address");
        var ratio = Prop(od, "baseUnitsPerMinor");
        if (!Test(Dec, ratio, od.ContainsKey("baseUnitsPerMinor")) || ratio is "0") throw new ArgumentException("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string");
        if (od.GetValueOrDefault("chainId") is not BigInteger chain) throw new ArgumentException("grantToPermissionRequest: bad chain");
        if (chain <= 0) throw new ArgumentException("grantToPermissionRequest: bad chain");
        var allowance = Hex(new BigInteger(IntentJs.NumOf(gd["capMinor"])!.Value) * JsBigInt(ratio));
        var req = new JD { ["chainId"] = Hex(chain) };
        if (hasFrom) req["from"] = od["from"];
        req["to"] = od["sessionAccount"];
        var adj = od.GetValueOrDefault("isAdjustmentAllowed") ?? true;
        req["permission"] = hasToken
            ? new JD { ["type"] = Erc20Type, ["isAdjustmentAllowed"] = adj, ["data"] = new JD { ["tokenAddress"] = od["tokenAddress"], ["allowance"] = allowance } }
            : new JD { ["type"] = NativeType, ["isAdjustmentAllowed"] = adj, ["data"] = new JD { ["allowance"] = allowance } };
        req["rules"] = new JL { new JD { ["type"] = "expiry", ["data"] = new JD { ["timestamp"] = gd["expiresAtSec"] } } };
        return req;
    }

    // ---- supported permissions ----

    /// <summary>The wallet_getSupportedExecutionPermissions result, filtered to what a request could use (the chain and every rule type must be listed). Never throws.</summary>
    public static bool SupportsRequest(object? supported, object? req)
    {
        try
        {
            if (req is not JD rq || Prop(rq, "permission") is not JD perm) return false;
            // supported[req.permission.type]: only an own member of an object can hold the entry
            if (supported is not JD sup || Prop(perm, "type") is not string type || !sup.TryGetValue(type, out var s) || s is not JD sd) return false;
            if (Prop(sd, "chainIds") is not JL ids) return false;
            var lowered = ids.Select(LowerOf).ToList();
            if (!lowered.Contains(LowerOf(Prop(rq, "chainId")))) return false;
            var rt = sd.GetValueOrDefault("ruleTypes") ?? sd.GetValueOrDefault("rulesTypes"); // the draft spells both
            var rules = rq.GetValueOrDefault("rules");
            if (rules == null) return true;
            if (rules is not JL rl) return false; // not an array: .every is not a function
            foreach (var r in rl)
                if (!(rt is JL rtl && r is JD rd && rd.GetValueOrDefault("type") is string t && rtl.Any(x => x is string xs && xs == t))) return false;
            return true;
        }
        catch (Exception) { return false; }
    }

    /// <summary>The wallet_revokeExecutionPermission params: <c>{permissionContext}</c>.</summary>
    public static JD RevokeParams(object? context) => new() { ["permissionContext"] = context };

    // ---- the granted permission ----

    /// <summary>Verify what the wallet actually granted against the request sent and the grant. Null when the permission is within the grant, else a reason.
    /// A wallet may NARROW (when isAdjustmentAllowed); it may never widen: amount, a later expiry, another token, chain, recipient or manager are all refused.
    /// <paramref name="g"/>: <c>{grantDigest, expiresAtSec}</c>; <paramref name="allowedManagers"/>: the trusted delegation managers (a list of strings);
    /// <paramref name="contextOwner"/>: the grant digest a context handle is already bound to, if any.</summary>
    public static string? VerifyGrantedPermission(object? g, object? sent, object? got, object? allowedManagers, Func<string, string?>? contextOwner = null)
    {
        try
        {
            if (got is not JD || Prop(got, "permission") is not { } perm || !IsObject(perm)) return "response_malformed";
            var r = got;
            if (Prop(r, "context") is not string ctx || !Ctx.IsMatch(ctx)) return "context_malformed";
            var owner = contextOwner?.Invoke(ctx);
            if (owner != null && owner != (Read(g, "grantDigest", g != null) as string)) return "context_bound_to_other_grant";
            if (Prop(r, "delegationManager") is not string mgr || !HexAddr.IsMatch(mgr)) return "delegation_manager_not_allowed";
            if (allowedManagers is not JL managers) throw new InvalidOperationException("allowedManagers.map is not a function");
            if (!managers.Select(LowerOf).ToList().Contains(Lower(mgr))) return "delegation_manager_not_allowed";
            if (Lower(Str(Prop(r, "chainId"), HasKey(r, "chainId"))) != LowerOf(Prop(sent, "chainId"))) return "chain_mismatch";
            if (Lower(Str(Prop(r, "to"), HasKey(r, "to"))) != LowerOf(Prop(sent, "to"))) return "recipient_mismatch";
            if (HasKey(sent, "from") && Lower(Str(Prop(r, "from"), HasKey(r, "from"))) != LowerOf(Prop(sent, "from"))) return "from_mismatch";
            var sperm = Read(sent, "permission", sent is JD sd0 && sd0.GetValueOrDefault("permission") != null);
            var pt = Prop(perm, "type");
            if (pt is not string pts || !Equals(pt, Prop(sperm, "type")) || (pts != NativeType && pts != Erc20Type)) return "permission_type_mismatch";
            var d = Read(perm, "data", HasKey(perm, "data") && Prop(perm, "data") != null);
            var sd = Read(sperm, "data", HasKey(sperm, "data") && Prop(sperm, "data") != null);
            static string Tok(object? o) { var t = Prop(o, "tokenAddress"); return t == null ? "" : Str(t); }
            if (Lower(Tok(d)) != Lower(Tok(sd))) return "token_mismatch";
            if (Prop(d, "allowance") is not string al || !HexQty.IsMatch(al)) return "amount_malformed";
            if (JsBigInt(al) > JsBigInt(Prop(sd, "allowance"), HasKey(sd, "allowance"))) return "amount_widened";
            if (Prop(perm, "isAdjustmentAllowed") is true && Prop(sperm, "isAdjustmentAllowed") is not true) return "adjustment_widened";
            if (Prop(r, "rules") is not JL rules) return "expiry_missing";
            bool have = false;
            long expiry = 0;
            foreach (var rule in rules)
            {
                if (Prop(rule, "type") is not "expiry") return "unknown_rule_type";
                if (have) return "duplicate_expiry";
                var data = Read(rule, "data", Prop(rule, "data") != null);
                if (!Pca.SafeInt(Prop(data, "timestamp"), out var ts)) return "expiry_malformed";
                have = true;
                expiry = ts;
            }
            if (!have) return "expiry_missing";
            var limit = Read(g, "expiresAtSec", g != null);
            // expiry > g.expiresAtSec: an absent member compares false, null reads as 0
            var lim = limit switch { null => HasKey(g, "expiresAtSec") ? 0.0 : double.NaN, _ => IntentJs.NumOf(limit) ?? double.NaN };
            return expiry > lim ? "expiry_extended" : null;
        }
        catch (Exception) { return "response_malformed"; }
    }

    static bool HasKey(object? o, string k) => o is JD d && d.ContainsKey(k);

    /// <summary>The content address of a grant: hashCanonical(grant). Throws when the value has no strict canonical form.</summary>
    public static string GrantDigestOf(object? grant) => Pca.HashCanonical(grant);
}
