using System.Diagnostics;
using System.ServiceProcess;

namespace ServerCloak.Core;

public enum ServiceState
{
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
    Other
}

/// <summary>Installs and controls the ServerCloak Windows service (replaces installutil/ProjectInstaller).</summary>
public static class ServiceManager
{
    public static ServiceState GetState()
    {
        using var sc = Find();
        if (sc == null)
            return ServiceState.NotInstalled;
        return sc.Status switch
        {
            ServiceControllerStatus.Running => ServiceState.Running,
            ServiceControllerStatus.Stopped => ServiceState.Stopped,
            ServiceControllerStatus.StartPending => ServiceState.Starting,
            ServiceControllerStatus.StopPending => ServiceState.Stopping,
            _ => ServiceState.Other
        };
    }

    private static ServiceController? Find()
    {
        foreach (var s in ServiceController.GetServices())
        {
            if (s.ServiceName.Equals(AppPaths.ServiceName, StringComparison.OrdinalIgnoreCase))
                return s;
            s.Dispose();
        }
        return null;
    }

    public static void Install(string exePath)
    {
        Sc($"create {AppPaths.ServiceName} binPath= \"\\\"{exePath}\\\"\" start= delayed-auto DisplayName= \"ServerCloak\"");
        Sc($"description {AppPaths.ServiceName} \"Blocks IP addresses that repeatedly fail to log in, using Windows Firewall.\"");
        Sc($"failure {AppPaths.ServiceName} reset= 86400 actions= restart/60000/restart/60000/restart/300000");
    }

    public static void Uninstall()
    {
        Stop();
        Sc($"delete {AppPaths.ServiceName}");
    }

    public static void Start()
    {
        using var sc = Find() ?? throw new InvalidOperationException("The service is not installed.");
        if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            return;
        sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    public static void Stop()
    {
        using var sc = Find();
        if (sc == null || sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
            return;
        sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
    }

    public static void Restart()
    {
        Stop();
        Start();
    }

    private static void Sc(string args)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true
        };
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit(30000);
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"sc.exe {args.Split(' ')[0]} failed: {output.Trim()}");
    }
}
