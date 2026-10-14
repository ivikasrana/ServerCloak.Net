using System.Windows;
using System.Windows.Threading;
using ServerCloak.Core;

namespace ServerCloak.App;

public partial class App : Application
{
    private Mutex? _single;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        // One copy per session; a second start (for example from the sign-in task) just exits.
        _single = new Mutex(true, @"Local\ServerCloakApp", out bool first);
        if (!first)
        {
            Shutdown();
            return;
        }

        try
        {
            CloakStore.Initialize();
        }
        catch (Exception ex)
        {
            AppPaths.LogError("Database initialise", ex);
            MessageBox.Show($"The database at {AppPaths.DbPath} could not be opened.\n\n{ex.Message}", "ServerCloak", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
            return;
        }

        ThemeManager.Apply(ThemeManager.Load());
        bool tray = e.Args.Any(a => a.Equals("--tray", StringComparison.OrdinalIgnoreCase));
        var window = new MainWindow(tray);
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _single?.Dispose();
        base.OnExit(e);
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        AppPaths.LogError("UI", e.Exception);
        MessageBox.Show(e.Exception.Message, "ServerCloak", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
