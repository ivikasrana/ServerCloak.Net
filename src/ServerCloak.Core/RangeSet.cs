using System.Net;
using System.Net.Sockets;

namespace ServerCloak.Core;

/// <summary>
/// A set of IP ranges on a single 128-bit number line (IPv4 is stored as IPv4-mapped IPv6), with union and
/// subtraction. Used to turn countries and block lists into firewall address lists that never cover whitelisted addresses.
/// </summary>
public class RangeSet
{
    private static readonly UInt128 V4Start = (UInt128)0xFFFF << 32;
    private static readonly UInt128 V4End = V4Start | 0xFFFFFFFF;

    /// <summary>Addresses that are never blocked by country or block list rules.</summary>
    public static readonly string[] Reserved =
    [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
        "::/127", "fc00::/7", "fe80::/10", "ff00::/8"
    ];

    private readonly List<(UInt128 Start, UInt128 End)> _ranges = [];
    private bool _normalized = true;

    public int Count
    {
        get
        {
            Normalize();
            return _ranges.Count;
        }
    }

    public IReadOnlyList<(UInt128 Start, UInt128 End)> Ranges
    {
        get
        {
            Normalize();
            return _ranges;
        }
    }

    public void Add(UInt128 start, UInt128 end)
    {
        if (end < start)
            (start, end) = (end, start);
        _ranges.Add((start, end));
        _normalized = false;
    }

    public void Add(byte[] startKey, byte[] endKey) => Add(FromKey(startKey), FromKey(endKey));

    /// <summary>Adds an IP, CIDR network or a-b range. Returns false if the text is not one of those.</summary>
    public bool Add(string entry)
    {
        if (!TryParse(entry, out var start, out var end))
            return false;
        Add(start, end);
        return true;
    }

    public void AddRange(IEnumerable<string> entries)
    {
        foreach (var e in entries)
            Add(e);
    }

    public bool Contains(IPAddress ip)
    {
        var v = FromAddress(ip);
        Normalize();
        int lo = 0, hi = _ranges.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (v < _ranges[mid].Start)
                hi = mid - 1;
            else if (v > _ranges[mid].End)
                lo = mid + 1;
            else
                return true;
        }
        return false;
    }

    /// <summary>Removes every address in <paramref name="other"/> from this set.</summary>
    public void Subtract(RangeSet other)
    {
        Normalize();
        var cut = other.Ranges;
        var result = new List<(UInt128, UInt128)>(_ranges.Count);
        int j = 0;
        foreach (var (s0, e) in _ranges)
        {
            var s = s0;
            bool done = false;
            while (j < cut.Count && cut[j].End < s)
                j++;
            for (int k = j; k < cut.Count && cut[k].Start <= e; k++)
            {
                if (cut[k].Start > s)
                    result.Add((s, cut[k].Start - 1));
                if (cut[k].End >= e)
                {
                    done = true;
                    break;
                }
                s = cut[k].End + 1;
            }
            if (!done)
                result.Add((s, e));
        }
        _ranges.Clear();
        _ranges.AddRange(result);
    }

    private void Normalize()
    {
        if (_normalized)
            return;
        _ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<(UInt128 Start, UInt128 End)>(_ranges.Count);
        foreach (var r in _ranges)
        {
            if (merged.Count > 0)
            {
                var last = merged[^1];
                if (last.End == UInt128.MaxValue || r.Start <= last.End + 1)
                {
                    if (r.End > last.End)
                        merged[^1] = (last.Start, r.End);
                    continue;
                }
            }
            merged.Add(r);
        }
        _ranges.Clear();
        _ranges.AddRange(merged);
        _normalized = true;
    }

    /// <summary>Firewall RemoteAddresses entries: single addresses or a-b ranges, IPv4 written as IPv4.</summary>
    public List<string> ToFirewallEntries()
    {
        var list = new List<string>();
        foreach (var (start, end) in Ranges)
        {
            // Split at the edges of the IPv4-mapped block so each part is written in one family.
            foreach (var (s, e) in SplitAtV4(start, end))
            {
                var a = ToAddress(s);
                list.Add(s == e ? a.ToString() : $"{a}-{ToAddress(e)}");
            }
        }
        return list;
    }

    private static IEnumerable<(UInt128, UInt128)> SplitAtV4(UInt128 s, UInt128 e)
    {
        if (s < V4Start && e >= V4Start)
        {
            yield return (s, V4Start - 1);
            s = V4Start;
        }
        if (s <= V4End && e > V4End)
        {
            yield return (s, V4End);
            s = V4End + 1;
        }
        yield return (s, e);
    }

    // Conversions

    public static UInt128 FromKey(ReadOnlySpan<byte> key)
    {
        UInt128 v = 0;
        foreach (var b in key)
            v = (v << 8) | b;
        return v;
    }

    public static UInt128 FromAddress(IPAddress ip) => FromKey(IpUtil.ToKey(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip));

    public static IPAddress ToAddress(UInt128 v)
    {
        bool v4 = v >= V4Start && v <= V4End;
        var bytes = new byte[16];
        for (int i = 15; i >= 0; i--)
        {
            bytes[i] = (byte)(v & 0xFF);
            v >>= 8;
        }
        return v4 ? new IPAddress(bytes.AsSpan(12, 4)) : new IPAddress(bytes);
    }

    public static bool TryParse(string? entry, out UInt128 start, out UInt128 end)
    {
        start = end = 0;
        if (string.IsNullOrWhiteSpace(entry))
            return false;
        entry = entry.Trim();

        if (entry.Contains('/'))
        {
            int slash = entry.IndexOf('/');
            if (!IPAddress.TryParse(entry[..slash].Trim(), out var baseAddr)
                || !int.TryParse(entry[(slash + 1)..].Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefix))
                return false;
            bool v4 = baseAddr.AddressFamily == AddressFamily.InterNetwork;
            if (prefix > (v4 ? 32 : 128))
                return false;
            int bits = v4 ? prefix + 96 : prefix;
            start = FromAddress(baseAddr);
            var hostMask = bits >= 128 ? UInt128.Zero : (UInt128.MaxValue >> bits);
            start &= ~hostMask;
            end = start | hostMask;
            return true;
        }

        int dash = entry.IndexOf('-');
        if (dash > 0)
        {
            if (!IPAddress.TryParse(entry[..dash].Trim(), out var a) || !IPAddress.TryParse(entry[(dash + 1)..].Trim(), out var b))
                return false;
            start = FromAddress(a);
            end = FromAddress(b);
            if (end < start)
                (start, end) = (end, start);
            return true;
        }

        if (!IPAddress.TryParse(entry, out var ip))
            return false;
        start = end = FromAddress(ip);
        return true;
    }
}
