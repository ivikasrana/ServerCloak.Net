using System.Net;
using ServerCloak.Core;

namespace ServerCloak.Tests;

public class IpUtilTests
{
    [Theory]
    [InlineData("203.0.113.5", "203.0.113.5")]
    [InlineData(" 203.0.113.5 ", "203.0.113.5")]
    [InlineData("::ffff:203.0.113.5", "203.0.113.5")]
    [InlineData("[2001:db8::1]", "2001:db8::1")]
    [InlineData("fe80::1%12", "fe80::1")]
    [InlineData("not an ip", null)]
    [InlineData("", null)]
    [InlineData("-", null)]
    public void Normalize(string input, string? expected) => Assert.Equal(expected, IpUtil.Normalize(input));

    [Theory]
    [InlineData("Login failed for user 'sa'. [CLIENT: 198.51.100.7]", "198.51.100.7")]
    [InlineData("connection from 2001:db8::42 port 22", "2001:db8::42")]
    [InlineData("version 1.2.3 build 4", null)]
    [InlineData("999.1.1.1 is not valid", null)]
    public void FindIp(string text, string? expected) => Assert.Equal(expected, IpUtil.FindIp(text));

    [Theory]
    [InlineData("10.0.0.0/8", "10.20.30.40", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.10-192.168.1.20", "192.168.1.15", true)]
    [InlineData("192.168.1.10-192.168.1.20", "192.168.1.21", false)]
    [InlineData("203.0.113.5", "203.0.113.5", true)]
    [InlineData("203.0.113.5", "::ffff:203.0.113.5", true)]
    [InlineData("2001:db8::/32", "2001:db8:1::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("# 10.0.0.1", "10.0.0.1", false)]
    public void WhitelistMatches(string entry, string ip, bool expected) => Assert.Equal(expected, IpUtil.Matches(entry, IPAddress.Parse(ip)));

    [Theory]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("10.0.0.1-10.0.0.9", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("10.0.0.0/33", false)]
    [InlineData("hello", false)]
    public void ValidWhitelistEntry(string entry, bool expected) => Assert.Equal(expected, IpUtil.IsValidWhitelistEntry(entry));
}

public class RangeSetTests
{
    [Fact]
    public void MergesOverlappingAndAdjacentRanges()
    {
        var set = new RangeSet();
        set.Add("10.0.0.0/24");
        set.Add("10.0.1.0/24");
        set.Add("10.0.0.128/25");
        Assert.Equal(["10.0.0.0-10.0.1.255"], set.ToFirewallEntries());
    }

    [Fact]
    public void SubtractSplitsRanges()
    {
        var set = new RangeSet();
        set.Add("10.0.0.0/24");
        var cut = new RangeSet();
        cut.Add("10.0.0.10");
        cut.Add("10.0.0.200-10.0.0.255");
        set.Subtract(cut);
        Assert.Equal(["10.0.0.0-10.0.0.9", "10.0.0.11-10.0.0.199"], set.ToFirewallEntries());
    }

    [Fact]
    public void SubtractWholeRangeLeavesNothing()
    {
        var set = new RangeSet();
        set.Add("198.51.100.0/24");
        var cut = new RangeSet();
        cut.Add("198.51.0.0/16");
        set.Subtract(cut);
        Assert.Empty(set.ToFirewallEntries());
    }

    [Fact]
    public void ReservedNetworksAreRemoved()
    {
        var set = new RangeSet();
        set.Add("0.0.0.0/0");
        var reserved = new RangeSet();
        reserved.AddRange(RangeSet.Reserved);
        set.Subtract(reserved);
        Assert.False(set.Contains(IPAddress.Parse("192.168.1.1")));
        Assert.False(set.Contains(IPAddress.Parse("10.1.2.3")));
        Assert.True(set.Contains(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void Ipv6IsWrittenAsIpv6()
    {
        var set = new RangeSet();
        set.Add("2001:db8::/126");
        Assert.Equal(["2001:db8::-2001:db8::3"], set.ToFirewallEntries());
    }

    [Theory]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3.0/24", true)]
    [InlineData("1.2.3.4-1.2.3.9", true)]
    [InlineData("1.2.3.4/40", false)]
    [InlineData("nonsense", false)]
    public void TryParse(string entry, bool ok) => Assert.Equal(ok, RangeSet.TryParse(entry, out _, out _));

    [Fact]
    public void CidrHostBitsAreMasked()
    {
        Assert.True(RangeSet.TryParse("203.0.113.77/24", out var s, out var e));
        Assert.Equal("203.0.113.0", RangeSet.ToAddress(s).ToString());
        Assert.Equal("203.0.113.255", RangeSet.ToAddress(e).ToString());
    }
}
