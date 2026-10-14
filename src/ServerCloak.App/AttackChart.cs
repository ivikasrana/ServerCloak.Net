using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using ServerCloak.Core;

namespace ServerCloak.App;

/// <summary>Bar chart of failed attempts (with the blocked share highlighted) over time.</summary>
public class AttackChart : FrameworkElement
{
    private IReadOnlyList<CloakStore.TimelinePoint> _points = [];
    private string _labelFormat = "HH:mm";
    private int _hover = -1;

    public AttackChart()
    {
        ThemeManager.Changed += InvalidateVisual;
        System.Windows.Controls.ToolTipService.SetInitialShowDelay(this, 0);
    }

    public void SetData(IReadOnlyList<CloakStore.TimelinePoint> points, string labelFormat)
    {
        _points = points;
        _labelFormat = labelFormat;
        InvalidateVisual();
    }

    private Brush Res(string key) => TryFindResource(key) as Brush ?? Brushes.Gray;

    private const double Left = 40, Bottom = 22, Top = 8;

    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(RenderSize));
        double w = ActualWidth - Left, h = ActualHeight - Bottom - Top;
        if (w <= 0 || h <= 0)
            return;

        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var label = Res("Secondary");
        var grid = Res("Separator");
        var face = new Typeface((FontFamily)FindResource("UiFont"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        FormattedText Text(string s) => new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, face, 11, label, dpi);

        int max = Math.Max(1, _points.Select(p => p.Attempts).DefaultIfEmpty(0).Max());
        int step = NiceStep(max);
        int top = (int)Math.Ceiling(max / (double)step) * step;

        var pen = new Pen(grid, 1);
        for (int v = 0; v <= top; v += step)
        {
            double y = Top + h - v / (double)top * h;
            dc.DrawLine(pen, new Point(Left, y), new Point(ActualWidth, y));
            var t = Text(v.ToString("N0"));
            dc.DrawText(t, new Point(Left - 8 - t.Width, y - t.Height / 2));
        }

        if (_points.Count == 0)
            return;

        var tint = Res("Tint");
        var accent = Res("Accent");
        var hover = Res("Purple");
        double slot = w / _points.Count;
        double bar = Math.Max(1, slot * 0.68);
        int labelEvery = Math.Max(1, (int)Math.Ceiling(_points.Count / Math.Max(1, w / 70)));

        for (int i = 0; i < _points.Count; i++)
        {
            var p = _points[i];
            double x = Left + i * slot + (slot - bar) / 2;
            double hAll = p.Attempts / (double)top * h;
            double hBlocked = p.Blocks / (double)top * h;
            if (hAll > 0)
                dc.DrawRoundedRectangle(i == _hover ? hover : tint, null, new Rect(x, Top + h - hAll, bar, hAll), Math.Min(3, bar / 2), Math.Min(3, bar / 2));
            if (hBlocked > 0)
                dc.DrawRectangle(accent, null, new Rect(x, Top + h - hBlocked, bar, hBlocked));
            if (i % labelEvery == 0)
            {
                var t = Text(p.Start.ToString(_labelFormat));
                dc.DrawText(t, new Point(Math.Min(ActualWidth - t.Width, Math.Max(Left, x + bar / 2 - t.Width / 2)), Top + h + 5));
            }
        }
    }

    private static int NiceStep(int max)
    {
        double raw = max / 4.0;
        double mag = Math.Pow(10, Math.Floor(Math.Log10(Math.Max(1, raw))));
        double n = raw / mag;
        double nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
        return Math.Max(1, (int)(nice * mag));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_points.Count == 0)
            return;
        double slot = (ActualWidth - Left) / _points.Count;
        int i = (int)((e.GetPosition(this).X - Left) / slot);
        i = i >= 0 && i < _points.Count ? i : -1;
        if (i == _hover)
            return;
        _hover = i;
        ToolTip = i < 0 ? null : $"{_points[i].Start.ToString(_labelFormat == "HH:mm" ? "dd MMM HH:mm" : "ddd dd MMM")}\n{_points[i].Attempts:N0} attempts, {_points[i].Blocks:N0} blocks";
        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        _hover = -1;
        InvalidateVisual();
    }
}
