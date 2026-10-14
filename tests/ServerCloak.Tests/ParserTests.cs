using System.Net;
using System.Text.RegularExpressions;
using ServerCloak.Core;
using ServerCloak.Service.Cloaks;

namespace ServerCloak.Tests;

public class LogParserTests
{
    [Theory]
    [InlineData("Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2", "203.0.113.5", "admin", false)]
    [InlineData("Failed password for administrator from 203.0.113.6 port 4000 ssh2", "203.0.113.6", "administrator", true)]
    [InlineData("Invalid user oracle from 2001:db8::9 port 22", "2001:db8::9", "oracle", false)]
    [InlineData("Failed publickey for root from 198.51.100.1 port 1 ssh2", "198.51.100.1", "root", true)]
    public void Ssh(string payload, string ip, string user, bool real)
    {
        var hit = LogParsers.ParseSsh(payload);
        Assert.NotNull(hit);
        Assert.Equal(ip, hit.Ip);
        Assert.Equal(user, hit.User);
        Assert.Equal(real, hit.RealAccount);
    }

    [Fact]
    public void SshIgnoresSuccess() => Assert.Null(LogParsers.ParseSsh("Accepted password for admin from 203.0.113.5 port 1 ssh2"));

    [Fact]
    public void SqlWrongPassword()
    {
        var hit = LogParsers.ParseSql("Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 198.51.100.20]");
        Assert.Equal("198.51.100.20", hit.Ip);
        Assert.Equal("sa", hit.User);
        Assert.True(hit.RealAccount);
    }

    [Fact]
    public void SqlUnknownLogin()
    {
        var hit = LogParsers.ParseSql("Login failed for user 'bob'. Reason: Could not find a login matching the name provided. [CLIENT: 198.51.100.21]");
        Assert.Equal("bob", hit.User);
        Assert.False(hit.RealAccount);
    }

    [Theory]
    [InlineData("0xC000006A", true)]
    [InlineData("0xc0000234", true)]
    [InlineData("0xC0000064", false)]
    [InlineData("0x18", true)]
    [InlineData("0x6", false)]
    [InlineData(null, false)]
    public void RealAccountStatus(string? status, bool expected) => Assert.Equal(expected, LogParsers.IsRealAccountStatus(status));

    [Fact]
    public void CustomPattern()
    {
        var r = new Regex(@"auth failed user=(?<user>\S+) ip=(?<ip>\S+)");
        var hit = LogParsers.ParseCustom(r, "2026-10-14 auth failed user=alice ip=203.0.113.9");
        Assert.NotNull(hit);
        Assert.Equal("203.0.113.9", hit.Ip);
        Assert.Equal("alice", hit.User);
    }

    [Theory]
    [InlineData(@"from (?<ip>\S+)", true, null)]
    [InlineData(@"from (\S+)", true, "named group")]
    [InlineData(@"(", true, "")]
    [InlineData("", false, null)]
    [InlineData("", true, "required")]
    public void ValidatePattern(string pattern, bool required, string? errorContains)
    {
        var error = LogParsers.ValidatePattern(pattern, required);
        if (errorContains == null)
            Assert.Null(error);
        else
            Assert.Contains(errorContains, error!);
    }

    [Fact]
    public void EscalationSteps()
    {
        var steps = CloakStore.ParseSteps("1h, 1d, 2w, permanent");
        Assert.Equal([TimeSpan.FromHours(1), TimeSpan.FromDays(1), TimeSpan.FromDays(14), null], steps);
        Assert.Throws<FormatException>(() => CloakStore.ParseSteps("1x"));
    }

    [Fact]
    public void FeedParsing()
    {
        var text = """
            # FireHOL style
            1.2.3.0/24
            5.6.7.8 ; comment
            {"cidr":"9.9.9.0/24","sblid":"SBL1","rir":"ripenet"}
            {"type":"metadata","timestamp":1}
            not-an-ip
            2001:db8::/32
            """;
        Assert.Equal(["1.2.3.0/24", "5.6.7.8", "9.9.9.0/24", "2001:db8::/32"], BlockFeeds.Parse(text));
    }
}

public class IisDetectorTests
{
    private static readonly string[] Fields = "date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken".Split(' ');

    private static Dictionary<string, string> Row(string line) => IisLogCloak.ParseRow(Fields, line);

    [Fact]
    public void Web401_1()
    {
        var row = Row("2026-10-14 10:00:00 10.0.0.5 GET /secure - 443 bob 203.0.113.5 Mozilla 401 1 1326 15");
        Assert.True(IisLogCloak.IsWebLogonFailure(row));
        Assert.False(IisLogCloak.IsExchangeLogonFailure(row));
    }

    [Fact]
    public void Web401_2IsNotCounted()
        => Assert.False(IisLogCloak.IsWebLogonFailure(Row("2026-10-14 10:00:00 10.0.0.5 GET /secure - 443 - 203.0.113.5 Mozilla 401 2 5 15")));

    [Fact]
    public void Exchange()
        => Assert.True(IisLogCloak.IsExchangeLogonFailure(Row("2026-10-14 10:00:00 10.0.0.5 POST /Microsoft-Server-ActiveSync/default.eas - 443 bob 203.0.113.5 Phone 401 1 1326 15")));

    [Fact]
    public void RdWeb()
    {
        Assert.True(IisLogCloak.IsRdWebLogonFailure(Row("2026-10-14 10:00:00 10.0.0.5 POST /RDWeb/Pages/en-US/login.aspx - 443 - 203.0.113.5 Mozilla 200 0 0 15")));
        Assert.False(IisLogCloak.IsRdWebLogonFailure(Row("2026-10-14 10:00:00 10.0.0.5 POST /RDWeb/Pages/en-US/login.aspx - 443 - 203.0.113.5 Mozilla 302 0 0 15")));
    }

    [Fact]
    public void Ftp()
    {
        var fields = "date time c-ip cs-username s-ip s-port cs-method cs-uri-stem sc-status sc-win32-status sc-substatus".Split(' ');
        var row = IisLogCloak.ParseRow(fields, "2026-10-14 10:00:00 203.0.113.5 admin 10.0.0.5 21 PASS *** 530 1326 41");
        Assert.True(IisLogCloak.IsFtpLogonFailure(row));
    }
}

public class SnifferTests
{
    private static readonly byte[] Local4 = [10, 0, 0, 5];
    private static readonly byte[] Local6 = IPAddress.Parse("2001:db8::5").GetAddressBytes();

    private static byte[] Tcp(int srcPort, string payload)
    {
        var data = System.Text.Encoding.ASCII.GetBytes(payload);
        var tcp = new byte[20 + data.Length];
        tcp[0] = (byte)(srcPort >> 8);
        tcp[1] = (byte)srcPort;
        tcp[12] = 5 << 4;
        data.CopyTo(tcp, 20);
        return tcp;
    }

    [Fact]
    public void Ipv4Reply()
    {
        var tcp = Tcp(25, "535 5.7.8 Authentication failed\r\n");
        var p = new byte[20 + tcp.Length];
        p[0] = 0x45;
        p[2] = (byte)(p.Length >> 8);
        p[3] = (byte)p.Length;
        p[9] = 6;
        Local4.CopyTo(p, 12);
        new byte[] { 203, 0, 113, 5 }.CopyTo(p, 16);
        tcp.CopyTo(p, 20);

        var reply = PacketSnifferCloak.FindReply(p, Local4, 25);
        Assert.NotNull(reply);
        Assert.Equal("203.0.113.5", reply.Remote.ToString());
        Assert.True(PacketSnifferCloak.StartsWithCode(reply.Payload, "535"));
        Assert.Null(PacketSnifferCloak.FindReply(p, Local4, 21));
    }

    [Fact]
    public void Ipv6Reply()
    {
        var tcp = Tcp(21, "530 Login incorrect.\r\n");
        var p = new byte[40 + tcp.Length];
        p[0] = 0x60;
        p[4] = (byte)(tcp.Length >> 8);
        p[5] = (byte)tcp.Length;
        p[6] = 6;
        Local6.CopyTo(p, 8);
        IPAddress.Parse("2001:db8::99").GetAddressBytes().CopyTo(p, 24);
        tcp.CopyTo(p, 40);

        var reply = PacketSnifferCloak.FindReply(p, Local6, 21);
        Assert.NotNull(reply);
        Assert.Equal("2001:db8::99", reply.Remote.ToString());
        Assert.True(PacketSnifferCloak.StartsWithCode(reply.Payload, "530"));
    }

    [Fact]
    public void TlsAlert() => Assert.True(PacketSnifferCloak.IsTlsAlert(new byte[] { 0x15, 3, 3, 0, 2, 2, 40 }));
}
