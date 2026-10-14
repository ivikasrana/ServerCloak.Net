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
    // App

    private void Tray_Click(object sender, RoutedEventArgs e)
    {
        CloakStore.SetBool(CloakStore.KeyTrayEnabled, TraySwitch.IsChecked == true);
        CloakStore.SetBool(CloakStore.KeyTrayPopups, PopupSwitch.IsChecked == true);
        _tray.Enabled = TraySwitch.IsChecked == true;
        _tray.Popups = PopupSwitch.IsChecked == true;
    }

    private void Startup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (StartupSwitch.IsChecked == true)
            {
                StartupTask.Enable();
                if (TraySwitch.IsChecked != true)
                {
                    TraySwitch.IsChecked = true;
                    Tray_Click(sender, e);
                }
                ShowToast("ServerCloak will start in the tray at sign-in");
            }
            else
            {
                StartupTask.Disable();
                ShowToast("Start at sign-in turned off");
            }
        }
        catch (Exception ex)
        {
            StartupSwitch.IsChecked = StartupTask.Exists();
            ShowError(ex.Message);
        }
    }

    private async void ExportSettings_Click(object sender, RoutedEventArgs e)
    {
        if (AskSavePath($"ServerCloak settings {Environment.MachineName}.json", "JSON file|*.json") is not { } path)
            return;
        await RunBusy(async () =>
        {
            var json = await Task.Run(SettingsBackup.Export);
            await File.WriteAllTextAsync(path, json);
            ShowToast("Settings exported (passwords and keys are not included)");
        });
    }

    private async void ImportSettings_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "JSON file|*.json" };
        if (dlg.ShowDialog(this) != true)
            return;
        if (!Confirm("Import these settings? Cloaks, countries, block lists, alerts and options are replaced; whitelist entries are added."))
            return;
        await RunBusy(async () =>
        {
            var json = await File.ReadAllTextAsync(dlg.FileName);
            var summary = await Task.Run(() =>
            {
                var s = SettingsBackup.Import(json);
                BlockEngine.SyncAll();
                return s;
            });
            LoadCloaks();
            LoadSettings();
            WhitelistBox.Text = string.Join(Environment.NewLine, CloakStore.GetWhitelist());
            ThemeManager.Apply(ThemeManager.Load());
            await RestartServiceIfRunning();
            ShowError(summary);
        });
    }

    // Updates

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e)
    {
        var repo = RepoBox.Text.Trim();
        if (repo.Count(c => c == '/') != 1)
        {
            ShowError("Enter the repository as owner/name.");
            return;
        }
        CloakStore.SetSetting(CloakStore.KeyUpdateRepo, repo);
        await CheckForUpdateAsync(quiet: false);
    }

    private async Task CheckForUpdateAsync(bool quiet)
    {
        CheckUpdateButton.IsEnabled = false;
        UpdateStatus.Text = "Checking…";
        try
        {
            _release = await Updater.CheckAsync();
            if (_release == null)
            {
                UpdateStatus.Text = $"You have the latest version ({AppPaths.Version}).";
                UpdateBanner.Visibility = Visibility.Collapsed;
            }
            else
            {
                UpdateStatus.Text = $"Version {_release.Version.ToString(3)} is available.";
                UpdateText.Text = $"ServerCloak {_release.Version.ToString(3)} is available (you have {AppPaths.Version}).";
                InstallUpdateButton.Visibility = _release.InstallerUrl != null ? Visibility.Visible : Visibility.Collapsed;
                UpdateBanner.Visibility = Visibility.Visible;
            }
        }
        catch (Exception ex)
        {
            UpdateStatus.Text = $"Update check failed: {ex.Message}";
            if (!quiet)
                AppPaths.LogError("Update check", ex);
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private void ReleaseNotes_Click(object sender, RoutedEventArgs e)
    {
        if (_release != null)
            Process.Start(new ProcessStartInfo(_release.Url) { UseShellExecute = true });
    }

    private async void InstallUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (_release == null)
            return;
        var warning = Updater.IsSigned ? "" : "\n\nThis copy of ServerCloak is not code signed, so the download cannot be verified. Only continue if you trust the repository.";
        if (!Confirm($"Download and install ServerCloak {_release.Version.ToString(3)}? The service restarts during the update.{warning}"))
            return;
        await RunBusy(async () =>
        {
            InstallUpdateButton.IsEnabled = false;
            UpdateText.Text = "Downloading…";
            var path = await Updater.DownloadAsync(_release);
            Updater.RunInstaller(path);
            ExitApp();
        });
    }
}
