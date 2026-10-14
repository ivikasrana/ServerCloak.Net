using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using ServerCloak.Core;

namespace ServerCloak.App;

public partial class MainWindow : Window
{
    private const int PageSize = 200;

    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(3) };
    private readonly DispatcherTimer _searchTimer = new() { Interval = TimeSpan.FromMilliseconds(350) };
    private readonly TrayIcon _tray;
    private List<CloakRow> _cloakRows = [];
    private List<IpRow> _ipRows = [];
    private List<CountryPick> _countries = [];
    private List<FeedRow> _feeds = [];
    private Updater.Release? _release;
    private int _page;
    private int _total;
    private bool _refreshing;
    private bool _busy;
    private bool _exiting;

    public MainWindow(bool startHidden = false)
    {
        InitializeComponent();
        VersionText.Text = $"v{AppPaths.Version}";
        GeoAttribution.Text = GeoIp.Attribution;
        UpdateThemeButton();
        ThemeManager.Changed += UpdateThemeButton;
        StateChanged += (_, _) => MaxButton.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";

        _toastTimer.Tick += (_, _) => { Toast.Visibility = Visibility.Collapsed; _toastTimer.Stop(); };
        _refreshTimer.Tick += async (_, _) => { if (IsVisible) await RefreshAsync(); };
        _searchTimer.Tick += async (_, _) => { _searchTimer.Stop(); _page = 0; await RefreshAsync(); };

        _tray = new TrayIcon(this);
        _tray.ExitRequested += ExitApp;

        LoadSystemInfo();
        LoadCloaks();
        LoadSettings();
        WhitelistBox.Text = string.Join(Environment.NewLine, CloakStore.GetWhitelist());

        if (startHidden && _tray.Enabled)
        {
            ShowInTaskbar = false;
            WindowState = WindowState.Minimized;
            Loaded += (_, _) => { Hide(); ShowInTaskbar = true; };
        }

        Loaded += async (_, _) =>
        {
            await RefreshAsync();
            _refreshTimer.Start();
            if (Updater.ShouldAutoCheck())
                await CheckForUpdateAsync(quiet: true);
        };
    }

    // Title bar and window

    private void UpdateThemeButton() => ThemeButton.Content = ThemeManager.IsDark ? "\uE706" : "\uE708";
    private void ThemeButton_Click(object sender, RoutedEventArgs e) => ThemeManager.Toggle();
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        // Keep the content inside the screen when maximised with WindowChrome.
        Root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
        if (WindowState == WindowState.Minimized && _tray.Enabled)
        {
            Hide();
            WindowState = WindowState.Normal;
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        base.OnClosing(e);
        if (!_exiting)
            _tray.Dispose();
    }

    private void ExitApp()
    {
        _exiting = true;
        _tray.Dispose();
        Close();
    }

    // Mouse wheel: inner lists scroll while they can, otherwise the page scrolls.
    private void MainScroll_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        for (var d = e.OriginalSource as DependencyObject; d != null && d != MainScroll; d = GetParent(d))
        {
            if (d is ComboBox { IsDropDownOpen: true })
                return;
            if (d is ScrollViewer inner && inner.ScrollableHeight > 0)
            {
                bool canScroll = e.Delta > 0 ? inner.VerticalOffset > 0 : inner.VerticalOffset < inner.ScrollableHeight;
                if (canScroll)
                    return;
            }
        }
        MainScroll.ScrollToVerticalOffset(MainScroll.VerticalOffset - e.Delta);
        e.Handled = true;
    }

    private static DependencyObject? GetParent(DependencyObject d)
        => d is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(d) : LogicalTreeHelper.GetParent(d);

    // Hold the left button for 2 seconds anywhere to move the window.
    private readonly DispatcherTimer _holdTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private Point _holdStart;

    protected override void OnPreviewMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonDown(e);
        _holdStart = e.GetPosition(this);
        _holdTimer.Tick -= HoldTimer_Tick;
        _holdTimer.Tick += HoldTimer_Tick;
        _holdTimer.Start();
    }

    protected override void OnPreviewMouseMove(MouseEventArgs e)
    {
        base.OnPreviewMouseMove(e);
        if (_holdTimer.IsEnabled && (e.GetPosition(this) - _holdStart).Length > 8)
            _holdTimer.Stop();
    }

    protected override void OnPreviewMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        base.OnPreviewMouseLeftButtonUp(e);
        _holdTimer.Stop();
    }

    private void HoldTimer_Tick(object? sender, EventArgs e)
    {
        _holdTimer.Stop();
        if (Mouse.LeftButton != MouseButtonState.Pressed)
            return;
        Mouse.Capture(null);
        if (WindowState == WindowState.Maximized)
            WindowState = WindowState.Normal;
        Cursor = Cursors.SizeAll;
        try { DragMove(); }
        catch (InvalidOperationException) { }
        finally { Cursor = null; }
    }

    private void ShowToast(string text)
    {
        ToastText.Text = text;
        Toast.Visibility = Visibility.Visible;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    private void ShowError(string message) => MessageBox.Show(this, message, "ServerCloak", MessageBoxButton.OK, MessageBoxImage.Warning);

    private bool Confirm(string message) => MessageBox.Show(this, message, "ServerCloak", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

    private async Task RunBusy(Func<Task> action)
    {
        if (_busy)
            return;
        _busy = true;
        Cursor = Cursors.Wait;
        try { await action(); }
        catch (Exception ex)
        {
            AppPaths.LogError("UI action", ex);
            ShowError(ex.Message);
        }
        finally
        {
            Cursor = null;
            _busy = false;
            await RefreshAsync();
        }
    }

    private static int ParseInt(TextBox box, string name, int min, int max)
    {
        if (!int.TryParse(box.Text.Trim(), NumberStyles.Integer, CultureInfo.CurrentCulture, out var v) || v < min || v > max)
            throw new ArgumentException($"{name} must be a number from {min} to {max}.");
        return v;
    }

    // Static data

    private void LoadSystemInfo()
    {
        OsText.Text = OsInfo.ProductName;
        OsDetail.Text = $"Build {OsInfo.Build}" + (OsInfo.IsServerCore ? " · Server Core" : "") + (OsInfo.IsSupported ? "" : " · older than Windows Server 2016, not supported");
        FeatureList.ItemsSource = new List<FeatureRow>
        {
            new() { Name = "Event log cloaks", Available = true, Note = "Windows logon, RDP, RD Gateway, NTLM, Kerberos, SQL Server, RRAS, FileMaker" },
            new() { Name = "IIS log cloaks", Available = Directory.Exists(Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", @"inetpub\logs\LogFiles")), Note = "IIS web, Exchange, RD Web, FTP, SMTP. Needs IIS logging in W3C format" },
            new() { Name = "OpenSSH Server log", Available = OsInfo.LogExists("OpenSSH/Operational"), Note = OsInfo.HasOpenSshInBox ? "In-box from Windows Server 2019" : "Install OpenSSH for Windows to use this cloak" },
            new() { Name = "Remote Desktop log", Available = OsInfo.LogExists("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"), Note = "RdpCoreTS operational log" },
            new() { Name = "Firewall dynamic keywords", Available = OsInfo.SupportsDynamicKeywords, Note = "Windows Server 2022 and later" },
            new() { Name = "IPv4 and IPv6", Available = true, Note = "Blocking, sniffers and country lookup for both" }
        };

        DynamicKeywordPanel.Visibility = OsInfo.SupportsDynamicKeywords ? Visibility.Visible : Visibility.Collapsed;
        DynamicKeywordSwitch.IsChecked = CloakStore.GetSetting(CloakStore.KeyUseDynamicKeywords) != "false";
    }

    private void LoadCloaks()
    {
        _cloakRows = CloakStore.GetCloaks().Select(x => new CloakRow(x)).ToList();
        CloakGrid.ItemsSource = _cloakRows;

        var selected = (CloakFilterBox.SelectedItem as CloakFilter)?.Id;
        var filters = new List<CloakFilter> { new() { Id = null, Name = "All cloaks" }, new() { Id = CloakEnum.Manual, Name = "Manual" } };
        filters.AddRange(_cloakRows.Select(x => new CloakFilter { Id = x.Id, Name = x.Name }));
        CloakFilterBox.ItemsSource = filters;
        CloakFilterBox.SelectedItem = filters.FirstOrDefault(x => x.Id == selected) ?? filters[0];
    }

    private Dictionary<CloakEnum, string> CloakNames()
    {
        var names = _cloakRows.ToDictionary(x => x.Id, x => x.Name);
        names[CloakEnum.Manual] = "Manual";
        return names;
    }

    private void LoadSettings()
    {
        // Protection
        EscalationSwitch.IsChecked = CloakStore.GetBool(CloakStore.KeyEscalation, true);
        EscalationBox.Text = CloakStore.GetSetting(CloakStore.KeyEscalationSteps) ?? CloakStore.DefaultEscalationSteps;
        DryRunSwitch.IsChecked = BlockEngine.DryRun;
        HealthHoursBox.Text = CloakStore.GetInt(CloakStore.KeyHealthHours, 24).ToString();
        RetentionBox.Text = CloakStore.GetInt(CloakStore.KeyLogRetentionDays, 180).ToString();

        // Alerts
        var a = AlertSettings.Load();
        SmtpHostBox.Text = a.SmtpHost;
        SmtpPortBox.Text = a.SmtpPort.ToString();
        SmtpSslSwitch.IsChecked = a.SmtpSsl;
        SmtpUserBox.Text = a.SmtpUser;
        SmtpPasswordBox.Password = a.SmtpPassword;
        MailFromBox.Text = a.MailFrom;
        MailToBox.Text = a.MailTo;
        WebhookBox.Password = a.WebhookUrl;
        OnBlockBox.IsChecked = a.OnBlock;
        OnServiceStopBox.IsChecked = a.OnServiceStop;
        OnRealAccountBox.IsChecked = a.OnRealAccount;
        OnHealthBox.IsChecked = a.OnHealth;
        OnSpikeBox.IsChecked = a.OnSpike;
        SpikeBlocksBox.Text = a.SpikeBlocks.ToString();
        SpikeMinutesBox.Text = a.SpikeMinutes.ToString();
        DailySummaryBox.IsChecked = a.DailySummary;
        SummaryHourBox.Text = a.SummaryHour.ToString();

        // Countries
        CountryModeBox.ItemsSource = new Dictionary<CountryMode, string>
        {
            [CountryMode.Off] = "Off",
            [CountryMode.BlockListed] = "Block these countries",
            [CountryMode.AllowListed] = "Allow only these countries"
        };
        CountryModeBox.SelectedValue = CloakStore.GetCountryMode();
        var chosen = CloakStore.GetCountryRules().ToHashSet(StringComparer.OrdinalIgnoreCase);
        _countries = GeoIp.AllCountries.Select(c => new CountryPick { Code = c.Code, Name = c.Name, Selected = chosen.Contains(c.Code) })
            .OrderByDescending(x => x.Selected).ThenBy(x => x.Name).ToList();
        ApplyCountrySearch();

        // Feeds
        LoadFeeds();
        AbuseKeyBox.Password = CloakStore.GetSecret(CloakStore.KeyAbuseIpDbKey);
        AbuseReportSwitch.IsChecked = CloakStore.GetBool(CloakStore.KeyAbuseIpDbReport, false);
        FeedHoursBox.Text = CloakStore.GetInt(CloakStore.KeyFeedHours, 12).ToString();

        // App
        TraySwitch.IsChecked = CloakStore.GetBool(CloakStore.KeyTrayEnabled, true);
        PopupSwitch.IsChecked = CloakStore.GetBool(CloakStore.KeyTrayPopups, true);
        _tray.Enabled = TraySwitch.IsChecked == true;
        _tray.Popups = PopupSwitch.IsChecked == true;
        StartupSwitch.IsChecked = StartupTask.Exists();
        RepoBox.Text = Updater.Repo;
    }

    private void LoadFeeds()
    {
        _feeds = CloakStore.GetFeeds().Select(x => new FeedRow(x)).ToList();
        FeedList.ItemsSource = _feeds;
    }

    // Refresh

    private record Snapshot(
        ServiceState State, bool? FirewallOn, List<CloakStore.CloakStats> CloakStats, List<CloakStore.CountryStats> Countries,
        CloakStore.IpPage Ips, List<AttackEvent> Events, int Today, int Total, int Blocked, string? GeoUpdated,
        List<CloakStore.TimelinePoint> Timeline, List<CloakStore.UserStats> Users, bool DryRun, int Sessions);

    private (DateTime From, TimeSpan Bucket, string Format, string Name) ChartRange()
        => Range7d.IsChecked == true ? (DateTime.Today.AddDays(-6), TimeSpan.FromHours(6), "ddd dd", "last 7 days")
         : Range30d.IsChecked == true ? (DateTime.Today.AddDays(-29), TimeSpan.FromDays(1), "dd MMM", "last 30 days")
         : (new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day, DateTime.Now.Hour, 0, 0).AddHours(-23), TimeSpan.FromHours(1), "HH:mm", "last 24 hours");

    private async Task RefreshAsync()
    {
        if (_refreshing)
            return;
        _refreshing = true;
        try
        {
            var filter = (CloakFilterBox.SelectedItem as CloakFilter)?.Id;
            bool blockedOnly = BlockedOnlySwitch.IsChecked == true;
            var search = SearchBox.Text;
            int skip = _page * PageSize;
            var range = ChartRange();
            var snap = await Task.Run(() =>
            {
                bool? fw;
                try { fw = FirewallPolicyManager.Instance.FirewallEnabled; } catch { fw = null; }
                return new Snapshot(
                    ServiceManager.GetState(), fw, CloakStore.GetCloakStats(), CloakStore.GetCountryStats(),
                    CloakStore.GetIpLogs(filter, blockedOnly, search, skip, PageSize), CloakStore.GetRecentEvents(60),
                    CloakStore.GetAttacksSince(DateTime.Now.AddDays(-1)), CloakStore.GetTotalEvents(), CloakStore.GetBlockedCount(),
                    CloakStore.GetSetting(CloakStore.KeyGeoUpdated),
                    CloakStore.GetTimeline(range.From, range.Bucket), CloakStore.GetTopUsernames(DateTime.Now.AddDays(-30), 50),
                    BlockEngine.DryRun, SessionGuard.SessionAddresses.Count);
            });
            Apply(snap);
        }
        catch (Exception ex)
        {
            AppPaths.LogError("Refresh", ex);
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void Apply(Snapshot s)
    {
        // Service
        var (text, brush, detail) = s.State switch
        {
            ServiceState.Running => ("Protected", "Green", "The service is running and watching for failed logins."),
            ServiceState.Starting => ("Starting…", "Amber", "The service is starting."),
            ServiceState.Stopping => ("Stopping…", "Amber", "The service is stopping."),
            ServiceState.Stopped => ("Stopped", "Accent", "The service is installed but not running. Attacks are not being blocked."),
            ServiceState.NotInstalled => ("Not installed", "Accent", "Install the service to start blocking attackers."),
            _ => ("Paused", "Amber", "The service is paused.")
        };
        if (s.DryRun && s.State == ServiceState.Running)
            (text, brush, detail) = ("Test mode", "Amber", "The service records attacks but blocks nothing.");
        StatusText.Text = text;
        StatusDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, brush);
        StatusDetail.Text = detail;
        InstallButton.Content = s.State == ServiceState.NotInstalled ? "Install service" : "Uninstall service";
        InstallButton.Style = (Style)FindResource(s.State == ServiceState.NotInstalled ? "PrimaryButton" : "DangerButton");
        StartStopButton.Visibility = s.State == ServiceState.NotInstalled ? Visibility.Collapsed : Visibility.Visible;
        RestartButton.Visibility = s.State == ServiceState.Running ? Visibility.Visible : Visibility.Collapsed;
        StartStopButton.Content = s.State == ServiceState.Running ? "Stop" : "Start";
        DryRunBanner.Visibility = s.DryRun ? Visibility.Visible : Visibility.Collapsed;

        // Firewall
        FirewallText.Text = s.FirewallOn switch { true => "On", false => "Off", _ => "Unknown" };
        FirewallGlyph.SetResourceReference(TextBlock.ForegroundProperty, s.FirewallOn == true ? "Green" : "Accent");
        FirewallOnButton.Visibility = s.FirewallOn == false ? Visibility.Visible : Visibility.Collapsed;
        FirewallMode.Text = s.FirewallOn == false
            ? "Blocking needs the firewall. The service turns it back on within 30 seconds while running."
            : OsInfo.SupportsDynamicKeywords && DynamicKeywordSwitch.IsChecked == true
                ? "Blocks inbound traffic using one dynamic keyword."
                : "Blocks inbound traffic with ServerCloak Block rules.";

        // Stats
        AttacksTodayText.Text = s.Today.ToString("N0");
        AttacksTotalText.Text = $"{s.Total:N0} attempts in the log";
        BlockedText.Text = s.Blocked.ToString("N0");
        var top = s.Countries.FirstOrDefault(x => x.Country != "");
        TopCountryText.Text = top == null ? "No attackers yet" : $"Most attempts from {GeoIp.CountryName(top.Country)}";

        foreach (var row in _cloakRows)
        {
            var st = s.CloakStats.FirstOrDefault(x => x.Cloak == row.Id);
            row.Attacks = st?.Attacks ?? 0;
            row.Blocked = st?.Blocked ?? 0;
        }

        // Geo
        if (DateTime.TryParse(s.GeoUpdated, CultureInfo.InvariantCulture, DateTimeStyles.None, out var geoDate))
        {
            GeoText.Text = $"Updated {geoDate:dd MMM yyyy}";
            GeoDetail.Text = "IPv4 and IPv6 country ranges, refreshed monthly by the service.";
        }
        else
        {
            GeoText.Text = "Not downloaded";
            GeoDetail.Text = "The service downloads it when it starts, or use Update now.";
        }

        // Chart and users
        var range = ChartRange();
        Chart.SetData(s.Timeline, range.Format);
        ChartSummary.Text = $"{s.Timeline.Sum(x => x.Attempts):N0} attempts and {s.Timeline.Sum(x => x.Blocks):N0} blocks in the {range.Name}";
        UserList.ItemsSource = s.Users.Select(u => new UserRow { User = u.User, Attempts = u.Attempts, Ips = u.Ips, RealAccount = u.RealAccount }).ToList();

        // IPs
        var names = CloakNames();
        _total = s.Ips.Total;
        _ipRows = s.Ips.Rows.Select(x => new IpRow(x, names)).ToList();
        IpGrid.ItemsSource = _ipRows;
        int pages = Math.Max(1, (int)Math.Ceiling(_total / (double)PageSize));
        PageText.Text = $"Page {_page + 1} of {pages}";
        PrevPage.IsEnabled = _page > 0;
        NextPage.IsEnabled = _page + 1 < pages;
        IpCountText.Text = $"{_total:N0} found";
        SearchHint.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

        // Countries
        int max = Math.Max(1, s.Countries.Select(x => x.Attacks).DefaultIfEmpty(0).Max());
        CountryList.ItemsSource = s.Countries.Take(50).Select(x => new CountryRow
        {
            Code = x.Country == "" ? "--" : x.Country,
            Name = GeoIp.CountryName(x.Country),
            Ips = x.Ips,
            Attacks = x.Attacks,
            Blocked = x.Blocked,
            Bar = (double)x.Attacks / max
        }).ToList();

        EventList.ItemsSource = s.Events.Select(x => new EventRow
        {
            Time = x.Time.ToString(x.Time.Date == DateTime.Today ? "HH:mm:ss" : "dd MMM HH:mm"),
            Ip = x.Ip,
            Cloak = names.TryGetValue(x.Cloak, out var n) ? n : x.Cloak.ToString(),
            Message = (x.Blocked ? "Blocked · " : "") + (x.Message ?? "")
        }).ToList();

        SessionGuardText.Text = s.Sessions == 0
            ? "Lockout guard: no signed-in Remote Desktop clients right now."
            : $"Lockout guard: {s.Sessions} signed-in Remote Desktop client address(es) are never blocked.";
    }

    private void Search_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchHint.Visibility = SearchBox.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        _searchTimer.Stop();
        _searchTimer.Start();
    }

    private async void Filter_Changed(object sender, RoutedEventArgs e)
    {
        _page = 0;
        if (IsLoaded)
            await RefreshAsync();
    }

    private async void Range_Checked(object sender, RoutedEventArgs e)
    {
        if (IsLoaded)
            await RefreshAsync();
    }

    private async void PrevPage_Click(object sender, RoutedEventArgs e)
    {
        if (_page == 0)
            return;
        _page--;
        await RefreshAsync();
    }

    private async void NextPage_Click(object sender, RoutedEventArgs e)
    {
        _page++;
        await RefreshAsync();
    }

    private void CloakGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CloakGrid.SelectedItem is CloakRow row && CloakFilterBox.ItemsSource is List<CloakFilter> filters)
            CloakFilterBox.SelectedItem = filters.FirstOrDefault(x => x.Id == row.Id);
    }

    // Service

    private async void Install_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        if (ServiceManager.GetState() == ServiceState.NotInstalled)
        {
            var exe = Path.Combine(AppContext.BaseDirectory, AppPaths.ServiceExe);
            if (!File.Exists(exe))
                throw new FileNotFoundException($"{AppPaths.ServiceExe} was not found next to ServerCloak.exe.");
            await Task.Run(() =>
            {
                ServiceManager.Install(exe);
                ServiceManager.Start();
            });
            ShowToast("Service installed and started");
        }
        else
        {
            if (!Confirm("Uninstall the ServerCloak service? Blocked addresses stay blocked in the firewall until you unblock them."))
                return;
            await Task.Run(ServiceManager.Uninstall);
            ShowToast("Service uninstalled");
        }
    });

    private async void StartStop_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        bool running = ServiceManager.GetState() == ServiceState.Running;
        await Task.Run(running ? ServiceManager.Stop : ServiceManager.Start);
        ShowToast(running ? "Service stopped" : "Service started");
    });

    private async void Restart_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        await Task.Run(ServiceManager.Restart);
        ShowToast("Service restarted");
    });

    private static async Task RestartServiceIfRunning()
    {
        if (ServiceManager.GetState() == ServiceState.Running)
            await Task.Run(ServiceManager.Restart);
    }

    // Cloaks

    private void ReloadCloaks_Click(object sender, RoutedEventArgs e)
    {
        LoadCloaks();
        _ = RefreshAsync();
    }

    private async void SaveCloaks_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        CloakGrid.CommitEdit(DataGridEditingUnit.Row, true);
        foreach (var row in _cloakRows)
        {
            if (row.Limit < 1 || row.Limit > 999)
                throw new ArgumentException($"{row.Name}: the limit must be between 1 and 999.");
            if (row.IsSniffer && (row.Port < 1 || row.Port > 65535))
                throw new ArgumentException($"{row.Name}: the port must be between 1 and 65535.");
        }
        await Task.Run(() => CloakStore.SaveCloaks(_cloakRows.Select(x => x.ToSetting())));
        await RestartServiceIfRunning();
        ShowToast("Cloaks saved");
    });

    private async void AddCustomRule_Click(object sender, RoutedEventArgs e) => await EditCustomRule(null);

    private async void EditCustomRule_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is CloakRow row)
            await EditCustomRule(row.Source);
    }

    private async Task EditCustomRule(CloakSetting? existing)
    {
        var dialog = new CustomRuleWindow(existing) { Owner = this };
        if (dialog.ShowDialog() != true)
            return;
        await RunBusy(async () =>
        {
            await Task.Run(() => CloakStore.SaveCustomCloak(dialog.Rule));
            LoadCloaks();
            await RestartServiceIfRunning();
            ShowToast($"Rule '{dialog.Rule.Name}' saved");
        });
    }

    private async void DeleteCustomRule_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not CloakRow row || !Confirm($"Delete the rule '{row.Name}' and its address history?"))
            return;
        await RunBusy(async () =>
        {
            await Task.Run(() =>
            {
                CloakStore.DeleteCustomCloak(row.Id);
                BlockEngine.SyncIps();
            });
            LoadCloaks();
            await RestartServiceIfRunning();
            ShowToast($"Rule '{row.Name}' deleted");
        });
    }
}
