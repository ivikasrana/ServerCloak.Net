using System.Globalization;
using System.Windows.Data;

namespace ServerCloak.App;

/// <summary>Bar fraction (0..1) times the available width.</summary>
public class BarWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        => values is [double fraction, double width] && width > 0 ? Math.Max(4, fraction * width) : 0d;

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
