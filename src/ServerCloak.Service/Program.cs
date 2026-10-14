using Microsoft.Extensions.Logging.EventLog;
using ServerCloak.Core;
using ServerCloak.Service;

// Used by the installer: ServerCloakService.exe install | uninstall
if (args.Length == 1 && args[0] is "install" or "uninstall")
{
    try
    {
        if (args[0] == "install")
        {
            if (ServiceManager.GetState() == ServiceState.NotInstalled)
                ServiceManager.Install(Environment.ProcessPath!);
            ServiceManager.Start();
        }
        else
        {
            if (ServiceManager.GetState() != ServiceState.NotInstalled)
                ServiceManager.Uninstall();
            FirewallPolicyManager.Instance.RemoveAll();
        }
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        AppPaths.LogError($"Service {args[0]}", ex);
        return 1;
    }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = AppPaths.ServiceName);
builder.Logging.AddFilter<EventLogLoggerProvider>("ServerCloak", LogLevel.Information);
builder.Services.Configure<EventLogSettings>(o =>
{
    o.SourceName = AppPaths.EventSource;
    o.LogName = "Application";
});
builder.Services.AddHostedService<CloakWorker>();

builder.Build().Run();
return 0;
