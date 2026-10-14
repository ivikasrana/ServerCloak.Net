using System.Text.RegularExpressions;

namespace ServerCloak.Core;

/// <summary>Text parsers for log messages, kept here so they can be unit tested without event logs.</summary>
public static partial class LogParsers
{
    [GeneratedRegex(@"Failed (?:password|publickey|keyboard-interactive/pam) for (?<invalid>invalid user )?(?<user>.*?) from (?<ip>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SshFailed();

    [GeneratedRegex(@"Invalid user (?<user>.*?) from (?<ip>\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex SshInvalid();

    [GeneratedRegex(@"authentication failure;.*rhost=(?<ip>\S+)(?:.*user=(?<user>\S+))?", RegexOptions.IgnoreCase)]
    private static partial Regex SshPam();

    [GeneratedRegex(@"Login failed for user '(?<user>[^']*)'", RegexOptions.IgnoreCase)]
    private static partial Regex SqlUser();

    /// <summary>OpenSSH failure line, for example "Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2".</summary>
    public static Hit? ParseSsh(string? payload)
    {
        if (string.IsNullOrEmpty(payload))
            return null;
        var m = SshFailed().Match(payload);
        if (m.Success)
            return new Hit(IpUtil.Normalize(m.Groups["ip"].Value), Clean(m.Groups["user"].Value), !m.Groups["invalid"].Success);
        m = SshInvalid().Match(payload);
        if (m.Success)
            return new Hit(IpUtil.Normalize(m.Groups["ip"].Value), Clean(m.Groups["user"].Value), false);
        m = SshPam().Match(payload);
        if (m.Success)
            return new Hit(IpUtil.Normalize(m.Groups["ip"].Value), Clean(m.Groups["user"].Value), false);
        return null;
    }

    /// <summary>SQL Server 18456. "Password did not match" means the login exists.</summary>
    public static Hit ParseSql(string text)
    {
        var user = SqlUser().Match(text) is { Success: true } m ? Clean(m.Groups["user"].Value) : null;
        bool real = text.Contains("Password did not match", StringComparison.OrdinalIgnoreCase);
        return new Hit(IpUtil.FindIp(ClientPart(text)), user, real);
    }

    // SQL Server puts the client address in "[CLIENT: x]"; prefer it over other numbers in the text.
    private static string ClientPart(string text)
    {
        int i = text.IndexOf("CLIENT:", StringComparison.OrdinalIgnoreCase);
        return i >= 0 ? text[i..] : text;
    }

    /// <summary>
    /// NTSTATUS / Kerberos codes from 4625, 4776 and 4771 that mean the account exists (wrong password, locked,
    /// disabled, expired, outside logon hours).
    /// </summary>
    public static bool IsRealAccountStatus(string? status)
    {
        if (string.IsNullOrEmpty(status))
            return false;
        return status.Trim().ToLowerInvariant() switch
        {
            "0xc000006a" or "0xc0000234" or "0xc0000072" or "0xc000006f" or "0xc0000070" or
            "0xc0000071" or "0xc0000193" or "0xc0000224" or "0xc0000413" => true,
            "0x18" or "0x12" or "0x17" => true,
            _ => false
        };
    }

    public static string? Clean(string? user)
    {
        user = user?.Trim().Trim('\'', '"');
        return string.IsNullOrEmpty(user) || user == "-" ? null : user.Length > 128 ? user[..128] : user;
    }

    /// <summary>Applies a custom rule regex. The pattern needs a named group "ip"; "user" is optional.</summary>
    public static Hit? ParseCustom(Regex pattern, string text)
    {
        var m = pattern.Match(text);
        if (!m.Success)
            return null;
        var ipGroup = m.Groups["ip"];
        var ip = ipGroup.Success ? IpUtil.Normalize(ipGroup.Value) : IpUtil.FindIp(m.Value);
        if (ip == null)
            return null;
        var user = m.Groups["user"];
        return new Hit(ip, user.Success ? Clean(user.Value) : null);
    }

    /// <summary>Checks a custom rule pattern. Returns an error message, or null when it is usable.</summary>
    public static string? ValidatePattern(string? pattern, bool required)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return required ? "A pattern is required." : null;
        try
        {
            var r = new Regex(pattern);
            return r.GetGroupNames().Contains("ip") ? null : "The pattern needs a named group (?<ip>...).";
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }
}
