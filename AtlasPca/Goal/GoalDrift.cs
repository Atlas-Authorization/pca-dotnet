using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.GoalPkg;


/**
 * Runtime drift monitoring, tighten-only. A monitor compares the action stream to the goal's expected profile (verbs, resources,
 * magnitude, rate, novelty). Anomalies convert allow to escalate; the strike counter is a ratchet; at {@code lockdown} strikes every
 * allow becomes escalate. {@link #applyDrift} can never relax a decision.
 */
public static class GoalDrift {

    /** Defaults: windowMs 60000, maxPerWindow 20, maxNovel 3, magnitudeFactor 3, warmup 5, lockdown 5. */
    public static D Defaults() {
        return G.map("windowMs", G.num(60000), "maxPerWindow", G.num(20), "maxNovel", G.num(3), "magnitudeFactor", G.num(3), "warmup", G.num(5), "lockdown", G.num(5));
    }

    private static D mm(object? o) { return G.m(o); }

    /** The verbs of the goal's grants. */
    public static HashSet<string> ExpectedVerbs(D g) {
        HashSet<string> outp = new();
        foreach (object? gr in G.arr(g.get("grants"), "grants")) outp.add((string) G.get(gr, "verb"));
        return outp;
    }

    private static void resIds(D s, HashSet<string> outp) {
        switch (G.kind(s)) {
            case "exact": outp.add((string) s.get("id")); break;
            case "oneof": foreach (object? i in G.arr(s.get("ids"), "ids")) outp.add((string) i); break;
            case "all_of": foreach (object? p in G.arr(s.get("parts"), "parts")) resIds(mm(p), outp); break;
            default: break;
        }
    }

    private static HashSet<string> knownResources(D g) {
        HashSet<string> outp = new();
        foreach (object? gr in G.arr(g.get("grants"), "grants")) resIds(mm(G.get(gr, "res")), outp);
        return outp;
    }

    private static string numStr(object? o) {
        double? d = G.dbl(o);
        if (d == null) return G.jsStr(o);
        if (d == Math.Round(d.Value) && Math.Abs(d.Value) < 1e21) return new BigInteger(d.Value).ToString();
        return G.jsStr(o);
    }

    private static D freshState() {
        return G.map("strikes", G.num(0), "times", new L(), "novel", new L(), "seen", new D());
    }

    private static byte[] hmac(byte[] key, string text) {
        return System.Security.Cryptography.HMACSHA256.HashData(key.Length == 0 ? new byte[1] : key, Encoding.UTF8.GetBytes(text));
    }

    private static string hex(byte[] b) {
        return Convert.ToHexString(b).ToLowerInvariant();
    }

    /** Node's Buffer.from(s, 'hex'): decoding stops at the first non-hex pair. */
    private static int HexVal(char c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

    private static byte[] hexLenient(string s) {
        List<byte> outp = new();
        for (int i = 0; i + 1 < s.Length; i += 2) {
            int hi = HexVal(s[i]), lo = HexVal(s[i + 1]);
            if (hi < 0 || lo < 0 || s[i] > 127 || s[i + 1] > 127) break;
            outp.add((byte) (hi * 16 + lo));
        }
        byte[] r = new byte[outp.Count];
        for (int i = 0; i < r.Length; i++) r[i] = outp[i];
        return r;
    }

    /** One drift monitor over a goal. */
    public sealed class Monitor {
        private D goal;
        private D o;
        private D st = freshState();

        public Monitor(D goal, D opts) {
            this.goal = goal;
            this.o = Defaults();
            if (opts != null) foreach (var kv in opts) o[kv.Key] = kv.Value;
        }

        private double opt(string k) { return G.toNum(o.get(k)); }

        /** Observe an action at time {@code t}: {anomalous, strikes, lockdown, reasons}. */
        public D observe(D a, object? t) {
            L reasons = new();
            if (!ExpectedVerbs(goal).contains(a.get("verb"))) reasons.add("verb " + G.jsStr(a.get("verb")) + " outside the goal profile");
            HashSet<string> known = knownResources(goal);
            L novel = G.l(st.get("novel"));
            if (!known.isEmpty() && !known.contains(a.get("res")) && !novel.contains(a.get("res"))) novel.add(a.get("res"));
            if (novel.size() > opt("maxNovel")) reasons.add("novel resources beyond the allowance");
            L times = new();
            foreach (object? x in G.arr(st.get("times"), "times")) if (G.toNum(x) > G.toNum(t) - opt("windowMs")) times.add(x);
            times.add(t);
            st.put("times", times);
            if (times.size() > opt("maxPerWindow")) reasons.add("rate above the profile");
            D prm = mm(a.get("params"));
            if (prm == null) throw new IrError("params expected");
            D seen = mm(st.get("seen"));
            foreach (KeyValuePair<string, object?> e in prm) {
                D l = mm(e.Value);
                if (!G.kind(l).equals("q")) continue;
                string p = e.Key;
                L hist = seen.get(p) == null ? new() : G.l(seen.get(p));
                object? v = mm(l.get("q")).get("n");
                if (hist.size() >= opt("warmup")) {
                    double sum = 0;
                    foreach (object? x in hist) sum += G.toNum(x);
                    double mean = sum / hist.size();
                    if (mean > 0 && G.toNum(v) > mean * opt("magnitudeFactor")) reasons.add(p + " magnitude " + numStr(o.get("magnitudeFactor")) + "x above the running mean");
                }
                L next = new(hist);
                next.add(v);
                seen.put(p, new L(next.GetRange(Math.Max(0, next.size() - 50), next.size() - Math.Max(0, next.size() - 50))));
            }
            if (!reasons.isEmpty()) st.put("strikes", G.num(G.safeInt(st.get("strikes"))!.Value + 1));
            long strikes = G.safeInt(st.get("strikes"))!.Value;
            return G.map("anomalous", !reasons.isEmpty(), "strikes", G.num(strikes), "lockdown", strikes >= opt("lockdown"), "reasons", reasons);
        }

        public D state() { return st; }

        /** Sealed state: {state, mac} (HMAC-SHA256 over the state's JSON text, hex). */
        public D seal(byte[] key) { return G.map("state", st, "mac", hex(hmac(key, G.stringify(st)))); }

        /** Restore; a state that fails its MAC locks down (fail closed). */
        public static Monitor Restore(D goal, D sealedM, byte[] key, D opts) {
            Monitor m = new Monitor(goal, opts);
            byte[] want = hmac(key, G.stringify(sealedM.get("state")));
            byte[] got = hexLenient(G.jsStr(sealedM.get("mac")));
            if (got.Length == want.Length && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(got, want)) m.st = mm(sealedM.get("state"));
            else {
                m.st = freshState();
                m.st.put("strikes", G.num((long) m.opt("lockdown")));
            }
            return m;
        }
    }

    /** Tighten-only: allow becomes escalate on an anomaly or lockdown; nothing else changes. */
    public static string ApplyDrift(string d, D signal) {
        return "allow".equals(d) && (G.truthy(signal.get("anomalous")) || G.truthy(signal.get("lockdown"))) ? "escalate" : d;
    }

    /** Decide, observe, tighten: {decision, signal}. {@code c} = {act, rels, hist?}. */
    public static D GuardedDecide(D goal, D ont, Monitor mon, D c, object? t) {
        string baseD = (string) GoalExamples.DecideCase(goal, ont, c).get("decision");
        D signal = mon.observe(mm(c.get("act")), t);
        return G.map("decision", ApplyDrift(baseD, signal), "signal", signal);
    }
}
