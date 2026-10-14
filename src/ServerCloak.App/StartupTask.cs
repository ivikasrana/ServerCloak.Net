using System.Diagnostics;
using System.IO;

namespace ServerCloak.App;

/// <summary>
/// Starts the app in the tray at sign-in. The app needs administrator rights, so a scheduled task with highest
/// privileges is used instead of the Run key (which cannot elevate).
/// </summary>
public static class StartupTask
{
    private const string TaskName = "ServerCloak Tray";

    public static bool Exists() => Run($"/query /tn \"{TaskName}\"", out _) == 0;

    public static void Enable()
    {
        var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "ServerCloak.exe");
        var user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        if (Run($"/create /f /tn \"{TaskName}\" /tr \"\\\"{exe}\\\" --tray\" /sc onlogon /ru \"{user}\" /rl highest /it", out var output) != 0)
            throw new InvalidOperationException($"The sign-in task could not be created: {output.Trim()}");
    }

    public static void Disable()
    {
        if (Exists())
            Run($"/delete /f /tn \"{TaskName}\"", out _);
    }

    private static int Run(string args, out string output)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var p = Process.Start(psi)!;
        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(30000);
        return p.ExitCode;
    }
}
