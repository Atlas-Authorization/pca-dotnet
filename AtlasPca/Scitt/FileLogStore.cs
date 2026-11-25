// A file-backed IScittLogStore: one append-only file of checksummed transactions (entry plus its new subtree hashes), flushed to disk before
// Append returns, so a crash leaves either the whole transaction or none of it. A torn final record is discarded on open; corruption anywhere
// else throws store_corrupt. SINGLE PROCESS: it does not lock the file, so run one writer per directory (use a database-backed store for a
// fleet). Memory use is the 32-byte hash of every subtree plus one offset per entry; entry bytes are read from disk on demand.
//
// Record: u32be payload length | payload | SHA-256(payload); payload: u32be entry length | entry | u16be node count | per node
// (u8 level, u32be index, 3 zero bytes, 32-byte hash).
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AtlasPca.Scitt;

public sealed class FileScittLogStore : IScittLogStore, IDisposable
{
    readonly object _gate = new();
    readonly FileStream _fs;
    readonly Dictionary<(int, long), byte[]> _nodes = new();
    readonly List<(long At, long Len)> _offsets = new();
    long _end;

    FileScittLogStore(FileStream fs) { _fs = fs; }

    /// <summary>Open (creating if absent) the log file at <paramref name="path"/> and rebuild the index.</summary>
    public static FileScittLogStore Open(string path)
    {
        var s = new FileScittLogStore(new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read));
        try { s.Load(); }
        catch { s.Dispose(); throw; }
        return s;
    }

    public void Dispose() => _fs.Dispose();
    public void Close() => Dispose();

    byte[] Read(long at, long len)
    {
        var b = new byte[len];
        _fs.Position = at;
        int got = 0;
        while (got < len)
        {
            int n = _fs.Read(b, got, (int)(len - got));
            if (n == 0) break;
            got += n;
        }
        return got == len ? b : b[..got];
    }

    void Load()
    {
        long total = _fs.Length, pos = 0;
        while (pos < total)
        {
            var head = Read(pos, 4);
            long len = head.Length == 4 ? (long)BinaryPrimitives.ReadUInt32BigEndian(head) : -1L;
            long recEnd = pos + 4 + len + 32;
            if (len < 6 || recEnd > total) { DiscardTail(pos, recEnd > total); return; }
            var payload = Read(pos + 4, len);
            var sum = Read(pos + 4 + len, 32);
            if (!SHA256.HashData(payload).AsSpan().SequenceEqual(sum)) { DiscardTail(pos, recEnd == total); return; }
            long entryLen = BinaryPrimitives.ReadUInt32BigEndian(payload);
            long p = 4 + entryLen;
            if (p + 2 > len) throw new ScittException("The value of \"offset\" is out of range.", "ERR_OUT_OF_RANGE");
            int count = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan((int)p));
            p += 2;
            if (p + count * 40L != len) throw new ScittLogException("store_corrupt", "a log record has an inconsistent length");
            _offsets.Add((pos + 8, entryLen));
            for (int i = 0; i < count; i++, p += 40)
                _nodes[(payload[p], BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan((int)p + 1)))] = payload.AsSpan((int)p + 8, 32).ToArray();
            pos = recEnd;
        }
        _end = pos;
    }

    void DiscardTail(long pos, bool isTail)
    {
        if (!isTail) throw new ScittLogException("store_corrupt", $"the log file is corrupt at offset {pos}");
        _fs.SetLength(pos);
        _fs.Flush(true);
        _end = pos;
    }

    public long Size() { lock (_gate) return _offsets.Count; }

    public byte[]? GetEntry(long index)
    {
        lock (_gate)
        {
            if (index < 0 || index >= _offsets.Count) return null;
            var o = _offsets[(int)index];
            return Read(o.At, o.Len);
        }
    }

    public byte[]? GetNode(int level, long index)
    {
        lock (_gate) return _nodes.TryGetValue((level, index), out var h) ? (byte[])h.Clone() : null;
    }

    public bool Append(long expectedSize, byte[] entry, IReadOnlyList<StoredNode> nodes)
    {
        lock (_gate)
        {
            if (_offsets.Count != expectedSize) return false;
            foreach (var n in nodes)
                if (n.Level < 0 || n.Level > 255 || n.Index < 0 || n.Index > 0xffffffffL || n.Hash.Length != 32 || nodes.Count > 0xffff)
                    throw new ScittLogException("store_corrupt", "a subtree node is malformed");
            var payload = new byte[4 + entry.Length + 2 + nodes.Count * 40];
            BinaryPrimitives.WriteUInt32BigEndian(payload, (uint)entry.Length);
            entry.CopyTo(payload, 4);
            int p = 4 + entry.Length;
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(p), (ushort)nodes.Count);
            p += 2;
            foreach (var n in nodes)
            {
                payload[p] = (byte)n.Level;
                BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(p + 1), (uint)n.Index);
                n.Hash.CopyTo(payload, p + 8);
                p += 40;
            }
            var record = new byte[4 + payload.Length + 32];
            BinaryPrimitives.WriteUInt32BigEndian(record, (uint)payload.Length);
            payload.CopyTo(record, 4);
            SHA256.HashData(payload).CopyTo(record, 4 + payload.Length);
            _fs.Position = _end;
            _fs.Write(record, 0, record.Length);
            _fs.Flush(true);
            _offsets.Add((_end + 8, entry.Length));
            foreach (var n in nodes) _nodes[(n.Level, n.Index)] = (byte[])n.Hash.Clone();
            _end += record.Length;
            return true;
        }
    }
}
