using System.Windows;
using Microsoft.Win32;
using ServerCloak.Core;

namespace ServerCloak.App;

public static class ThemeManager
{
    public static bool IsDark { get; private set; }

    public static event Action? Changed;

    /// <summary>Saved choice, or the Windows app theme when nothing is saved.</summary>
    public static bool Load()
    {
        var saved = CloakStore.GetSetting(CloakStore.KeyTheme);
        if (saved == "dark")
            return true;
        if (saved == "light")
            return false;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch { return false; }
    }

    public static void Apply(bool dark)
    {
        IsDark = dark;
        var dict = new ResourceDictionary { Source = new Uri($"Themes/{(dark ? "Dark" : "Light")}.xaml", UriKind.Relative) };
        Application.Current.Resources.MergedDictionaries[0] = dict;
        Changed?.Invoke();
    }

    public static void Toggle()
    {
        Apply(!IsDark);
        CloakStore.SetSetting(CloakStore.KeyTheme, IsDark ? "dark" : "light");
    }
}
