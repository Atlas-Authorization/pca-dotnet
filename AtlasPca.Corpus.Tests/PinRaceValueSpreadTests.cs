using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The racing-raise check hands the highest value to a copy in the middle of the sequence (copy i raises (i + copies/2) % copies + 1),
// so a store that keeps the first or the last write cannot pass by thread start order alone. Which values each handle receives is
// fixed by that formula, whatever order the threads run in.
public class PinRaceValueSpreadTests
{
    sealed class Recording : IPinStore
    {
        static readonly object Gate = new();
        public static readonly Dictionary<string, long> Pins = new();
        public readonly SortedSet<long> RacedValues = new();
        public long? Pin(string key) { lock (Gate) return Pins.TryGetValue(key, out var v) ? v : null; }
        public long RaisePin(string key, long value)
        {
            if (value < 0 || string.IsNullOrEmpty(key)) throw new ArgumentException("bad");
            lock (Gate)
            {
                if (key.Contains("pin-concurrent")) RacedValues.Add(value);
                if (!Pins.TryGetValue(key, out var cur) || value > cur) Pins[key] = cur = value;
                return cur;
            }
        }
    }

    [Fact]
    public void EachHandleRaisesTheValuesOfItsCopies()
    {
        var opened = new List<Recording>();
        var r = StoreConformance.RunPinStore(new PinStoreConformance
        {
            Name = "spread", Shared = true, Rounds = 1, Copies = 5, Handles = 2,
            Open = () => { var s = new Recording(); lock (opened) opened.Add(s); return s; },
        });
        Assert.Equal("pass", r.Checks.First(c => c.Name == "raise-concurrent").Status);
        var spread = opened.Where(s => s.RacedValues.Count > 0).Select(s => string.Join(",", s.RacedValues)).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        // copies 0, 2, 4 on the first handle raise 3, 5, 2; copies 1, 3 on the second raise 4, 1
        Assert.Equal(new[] { "1,4", "2,3,5" }, spread);
    }
}
