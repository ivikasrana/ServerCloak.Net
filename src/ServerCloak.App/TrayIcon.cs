using System.Windows;
using System.Windows.Threading;
using ServerCloak.Core;
using Forms = System.Windows.Forms;

namespace ServerCloak.App;

/// <summary>Tray icon with pop-ups for blocks, alerts and the daily summary written by the service.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(10) };
    private readonly Window _window;
    private long _lastId;

    public TrayIcon(Window window)
    {
        _window = window;
        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/ServerCloak.ico"))!.Stream;
        _icon = new Forms.NotifyIcon
        {
            Icon = new System.Drawing.Icon(stream),
            Text = "ServerCloak",
            Visible = false
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open ServerCloak", null, (_, _) => ShowWindow());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitRequested?.Invoke());
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => ShowWindow();
        _icon.BalloonTipClicked += (_, _) => ShowWindow();

        try { _lastId = CloakStore.GetLastNotificationId(); } catch { }
        _poll.Tick += (_, _) => Poll();
    }

    public event Action? ExitRequested;

    public bool Enabled
    {
        get => _icon.Visible;
        set
        {
            _icon.Visible = value;
            if (value) _poll.Start(); else _poll.Stop();
        }
    }

    public bool Popups { get; set; } = true;

    public void ShowWindow()
    {
        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
            _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    public void Show(string title, string text, Forms.ToolTipIcon icon = Forms.ToolTipIcon.Info)
    {
        if (_icon.Visible)
            _icon.ShowBalloonTip(5000, title, text, icon);
    }

    private void Poll()
    {
        List<Notification> items;
        try { items = CloakStore.GetNotificationsAfter(_lastId); }
        catch { return; }
        if (items.Count == 0)
            return;
        _lastId = items[^1].Id;
        if (!Popups)
            return;

        // Several at once (an attack wave) become one pop-up.
        var blocks = items.Where(x => x.Level == NotificationLevel.Block).ToList();
        var others = items.Where(x => x.Level != NotificationLevel.Block).ToList();
        if (blocks.Count == 1)
            Show(blocks[0].Title, blocks[0].Text);
        else if (blocks.Count > 1)
            Show($"{blocks.Count} addresses blocked", string.Join("\n", blocks.TakeLast(3).Select(x => x.Text.Split(' ')[0])) + (blocks.Count > 3 ? "\n…" : ""));
        foreach (var n in others.TakeLast(2))
            Show(n.Title, n.Text.Length > 250 ? n.Text[..250] + "…" : n.Text, n.Level == NotificationLevel.Warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _poll.Stop();
        _icon.Visible = false;
        _icon.Dispose();
    }
}
