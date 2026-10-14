using System.Text.RegularExpressions;
using System.Windows;
using ServerCloak.Core;

namespace ServerCloak.App;

public partial class CustomRuleWindow : Window
{
    public CloakSetting Rule { get; }

    public CustomRuleWindow(CloakSetting? existing)
    {
        InitializeComponent();
        Rule = existing ?? new CloakSetting { Kind = CloakKind.EventLog, Limit = 5, BlockDuration = BlockDurationEnum.Month3, FileFilter = "*.log", IsCustom = true };
        TitleText.Text = existing == null ? "New custom rule" : $"Edit {existing.Name}";

        NameBox.Text = Rule.Name;
        EventLogRadio.IsChecked = Rule.Kind == CloakKind.EventLog;
        LogFileRadio.IsChecked = Rule.Kind == CloakKind.LogFile;
        LogNameBox.Text = Rule.EventLogName ?? "";
        EventIdsBox.Text = Rule.EventIds ?? "";
        FolderBox.Text = Rule.LogPath ?? "";
        FilterBox.Text = Rule.FileFilter ?? "*.log";
        PatternBox.Text = Rule.Pattern ?? "";
        LimitBox.Text = Rule.Limit.ToString();
        DurationBox.SelectedValue = Rule.BlockDuration;
        EnabledSwitch.IsChecked = Rule.Enabled;
        UpdateKind();
    }

    private bool IsEventLog => EventLogRadio.IsChecked == true;

    private void Kind_Checked(object sender, RoutedEventArgs e)
    {
        if (IsLoaded || EventLogPanel != null)
            UpdateKind();
    }

    private void UpdateKind()
    {
        if (EventLogPanel == null || LogFilePanel == null)
            return;
        EventLogPanel.Visibility = IsEventLog ? Visibility.Visible : Visibility.Collapsed;
        LogFilePanel.Visibility = IsEventLog ? Visibility.Collapsed : Visibility.Visible;
        PatternLabel.Text = IsEventLog
            ? "Pattern (optional regex on the event text with a named group (?<ip>…), optionally (?<user>…); empty uses the first IP in the event)"
            : "Pattern (regex with a named group (?<ip>…), optionally (?<user>…); each matching line is one failed attempt)";
        Test();
    }

    private void Test_Changed(object sender, System.Windows.Controls.TextChangedEventArgs e) => Test();

    private void Test()
    {
        if (TestResult == null)
            return;
        var error = LogParsers.ValidatePattern(PatternBox.Text, !IsEventLog);
        if (error != null)
        {
            TestResult.Text = error;
            return;
        }
        if (SampleBox.Text.Length == 0)
        {
            TestResult.Text = "";
            return;
        }
        Hit? hit;
        if (string.IsNullOrWhiteSpace(PatternBox.Text))
            hit = IpUtil.FindIp(SampleBox.Text) is { } ip ? new Hit(ip) : null;
        else
            hit = LogParsers.ParseCustom(new Regex(PatternBox.Text, RegexOptions.IgnoreCase), SampleBox.Text);
        TestResult.Text = hit == null ? "No match." : $"Match: IP {hit.Ip}" + (hit.User != null ? $", user {hit.User}" : "");
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        string? Fail(string message)
        {
            MessageBox.Show(this, message, "ServerCloak", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }

        if (NameBox.Text.Trim().Length == 0)
        {
            Fail("Give the rule a name.");
            return;
        }
        if (!int.TryParse(LimitBox.Text, out var limit) || limit < 1 || limit > 999)
        {
            Fail("The limit must be between 1 and 999.");
            return;
        }
        if (LogParsers.ValidatePattern(PatternBox.Text, !IsEventLog) is { } patternError)
        {
            Fail(patternError);
            return;
        }
        if (IsEventLog)
        {
            if (!OsInfo.LogExists(LogNameBox.Text.Trim()))
            {
                if (MessageBox.Show(this, $"The event log '{LogNameBox.Text.Trim()}' was not found on this server. Save anyway?", "ServerCloak",
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                    return;
            }
            if (EventIdsBox.Text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries).Any(x => !int.TryParse(x, out _)))
            {
                Fail("Event IDs must be numbers separated by commas.");
                return;
            }
        }
        else if (FolderBox.Text.Trim().Length == 0)
        {
            Fail("Enter the folder that holds the log files.");
            return;
        }

        Rule.Name = NameBox.Text.Trim();
        Rule.Kind = IsEventLog ? CloakKind.EventLog : CloakKind.LogFile;
        Rule.EventLogName = IsEventLog ? LogNameBox.Text.Trim() : null;
        Rule.EventIds = IsEventLog ? EventIdsBox.Text.Trim() : null;
        Rule.LogPath = IsEventLog ? null : FolderBox.Text.Trim();
        Rule.FileFilter = IsEventLog ? null : (FilterBox.Text.Trim() is { Length: > 0 } f ? f : "*.log");
        Rule.Pattern = string.IsNullOrWhiteSpace(PatternBox.Text) ? null : PatternBox.Text;
        Rule.Limit = limit;
        Rule.BlockDuration = DurationBox.SelectedValue is BlockDurationEnum d ? d : BlockDurationEnum.Month3;
        Rule.Enabled = EnabledSwitch.IsChecked == true;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
