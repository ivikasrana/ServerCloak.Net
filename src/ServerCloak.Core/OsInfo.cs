using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;

namespace ServerCloak.Core;

/// <summary>Windows version detection used to switch features on per release.</summary>
public static class OsInfo
{
    public const int BuildServer2016 = 14393;
    public const int BuildServer2019 = 17763;
    public const int BuildServer2022 = 20348;
    public const int BuildServer2025 = 26100;

    public static int Build => Environment.OSVersion.Version.Build;

    private static string? Reg(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue(name)?.ToString();
        }
        catch { return null; }
    }

    public static string ProductName
    {
        get
        {
            var name = Reg("ProductName") ?? "Windows";
            // Windows 11 still reports "Windows 10" in ProductName.
            if (Build >= 22000 && name.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
                name = "Windows 11" + name["Windows 10".Length..];
            var display = Reg("DisplayVersion") ?? Reg("ReleaseId");
            return string.IsNullOrEmpty(display) ? name : $"{name} {display}";
        }
    }

    public static bool IsServer => string.Equals(Reg("InstallationType"), "Server", StringComparison.OrdinalIgnoreCase) || IsServerCore;

    public static bool IsServerCore => string.Equals(Reg("InstallationType"), "Server Core", StringComparison.OrdinalIgnoreCase);

    public static bool IsSupported => Build >= BuildServer2016;

    /// <summary>Windows Firewall dynamic keywords: Windows Server 2022 / Windows 11 and later.</summary>
    public static bool SupportsDynamicKeywords => Build >= BuildServer2022;

    /// <summary>OpenSSH Server ships in-box from Windows Server 2019; on 2016 it can be installed separately.</summary>
    public static bool HasOpenSshInBox => Build >= BuildServer2019;

    public static bool LogExists(string logName)
    {
        try
        {
            using var config = new EventLogConfiguration(logName);
            return true;
        }
        catch { return false; }
    }
}
