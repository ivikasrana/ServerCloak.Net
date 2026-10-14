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

public partial class MainWindow
{
    // IPs

    private string? SelectedIp => (IpGrid.SelectedItem as IpRow)?.Ip;

    private void IpGrid_RightButtonDown(object sender, MouseButtonEventArgs e)
    {
        // Select the row under the mouse so the context menu acts on it.
        for (var d = e.OriginalSource as DependencyObject; d != null; d = GetParent(d))
            if (d is DataGridRow row)
            {
                row.IsSelected = true;
                IpGrid.SelectedItem = row.Item;
                return;
            }
    }

    private async Task UnblockAsync(string ip)
    {
        await Task.Run(() =>
        {
            CloakStore.UnblockIp(ip);
            BlockEngine.SyncIps();
        });
        ShowToast($"{ip} unblocked");
    }

    private async void Unblock_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is string ip)
            await RunBusy(() => UnblockAsync(ip));
    }

    private async void UnblockMenu_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is { } ip)
            await RunBusy(() => UnblockAsync(ip));
    }

    private async Task WhitelistAsync(string entry, string ip)
    {
        await Task.Run(() =>
        {
            CloakStore.AddToWhitelist(entry, $"added {DateTime.Now:dd MMM yyyy}");
            CloakStore.UnblockIp(ip);
            BlockEngine.SyncAll();
        });
        WhitelistBox.Text = string.Join(Environment.NewLine, CloakStore.GetWhitelist());
        ShowToast($"{entry} whitelisted and unblocked");
    }

    private async void WhitelistIp_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is { } ip)
            await RunBusy(() => WhitelistAsync(ip, ip));
    }

    private async void WhitelistNet_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is not { } ip || !System.Net.IPAddress.TryParse(ip, out var address))
            return;
        int prefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 24 : 64;
        // Mask the host part: 203.0.113.7 becomes 203.0.113.0/24.
        var text = RangeSet.TryParse($"{ip}/{prefix}", out var s, out _) ? $"{RangeSet.ToAddress(s)}/{prefix}" : ip;
        if (Confirm($"Whitelist the whole network {text}?"))
            await RunBusy(() => WhitelistAsync(text, ip));
    }

    private async void BlockMenu_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is { } ip)
            await ManualBlockAsync(ip);
    }

    private async void ManualBlock_Click(object sender, RoutedEventArgs e) => await ManualBlockAsync(ManualIpBox.Text.Trim());

    private async Task ManualBlockAsync(string ip) => await RunBusy(async () =>
    {
        if (IpUtil.Normalize(ip) == null)
            throw new ArgumentException($"'{ip}' is not a valid IP address.");
        if (CloakStore.IsWhitelisted(ip))
            throw new ArgumentException($"{ip} is whitelisted, a local address or a signed-in Remote Desktop client, so it cannot be blocked.");
        await Task.Run(() =>
        {
            CloakStore.ManualBlock(ip, null);
            BlockEngine.SyncIps();
        });
        ManualIpBox.Text = "";
        ShowToast($"{ip} blocked permanently");
    });

    private void CopyIp_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is { } ip)
        {
            Clipboard.SetText(ip);
            ShowToast("Copied");
        }
    }

    private void LookupIp_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedIp is { } ip)
            Process.Start(new ProcessStartInfo($"https://www.abuseipdb.com/check/{Uri.EscapeDataString(ip)}") { UseShellExecute = true });
    }

    private async void SaveWhitelist_Click(object sender, RoutedEventArgs e) => await RunBusy(async () =>
    {
        var lines = WhitelistBox.Text.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
        var bad = lines.Where(x => !x.StartsWith('#') && !IpUtil.IsValidWhitelistEntry(x)).ToList();
        if (bad.Count > 0)
            throw new ArgumentException("These lines are not valid IP addresses, networks or ranges:\n\n" + string.Join("\n", bad.Take(10)));
        await Task.Run(() =>
        {
            CloakStore.SaveWhitelist(lines);
            // Whitelisted addresses come out of country and block list rules.
            BlockEngine.SyncRanges();
        });
        ShowToast("Whitelist saved");
    });

    // Reports

    private string? AskSavePath(string name, string filter)
    {
        var dlg = new SaveFileDialog { FileName = name, Filter = filter };
        return dlg.ShowDialog(this) == true ? dlg.FileName : null;
    }

    private async void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        var range = ChartRange();
        if (AskSavePath($"ServerCloak attempts {DateTime.Now:yyyy-MM-dd}.csv", "CSV file|*.csv") is not { } path)
            return;
        var names = CloakNames();
        await RunBusy(async () =>
        {
            await Task.Run(() => Reports.ExportEventsCsv(path, range.From, names));
            ShowToast("CSV saved");
        });
    }

    private async void ExportIpsCsv_Click(object sender, RoutedEventArgs e)
    {
        if (AskSavePath($"ServerCloak addresses {DateTime.Now:yyyy-MM-dd}.csv", "CSV file|*.csv") is not { } path)
            return;
        var filter = (CloakFilterBox.SelectedItem as CloakFilter)?.Id;
        bool blockedOnly = BlockedOnlySwitch.IsChecked == true;
        var search = SearchBox.Text;
        var names = CloakNames();
        await RunBusy(async () =>
        {
            await Task.Run(() =>
            {
                var rows = CloakStore.GetIpLogs(filter, blockedOnly, search, 0, int.MaxValue).Rows.Select(x => new IpRow(x, names));
                Reports.ExportIpsCsv(path, rows);
            });
            ShowToast("CSV saved");
        });
    }

    private async void ExportPdf_Click(object sender, RoutedEventArgs e)
    {
        var range = ChartRange();
        if (AskSavePath($"ServerCloak report {DateTime.Now:yyyy-MM-dd}.pdf", "PDF file|*.pdf") is not { } path)
            return;
        var names = CloakNames();
        await RunBusy(async () =>
        {
            await Task.Run(() => Reports.ExportPdf(path, range.Name, range.From, range.Bucket, range.Format, names));
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        });
    }
}
