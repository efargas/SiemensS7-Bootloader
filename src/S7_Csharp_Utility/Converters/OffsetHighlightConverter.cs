using System;
using System.Globalization;
using System.Collections.Generic;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Multi-value converter that returns a highlight brush when the first value (cell offset)
    /// equals the second value (SelectedOffset). Otherwise returns Transparent.
    /// </summary>
    public sealed class OffsetHighlightConverter : IMultiValueConverter
    {
        private static readonly IBrush Highlight = new SolidColorBrush(Color.FromRgb(0x4C, 0x51, 0xBF)); // Indigo-600
        private static readonly IBrush Transparent = Brushes.Transparent;

        public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
        {
            if (values == null || values.Count < 2)
                return Transparent;

            try
            {
                var cellOffset = ToLong(values[0]);
                var selected = ToLong(values[1]);
                if (cellOffset >= 0 && selected >= 0 && cellOffset == selected)
                {
                    return Highlight;
                }
            }
            catch
            {
                // ignore and return transparent
            }
            return Transparent;
        }

        private static long ToLong(object? v)
        {
            return v switch
            {
                null => -1,
                long l => l,
                int i => i,
                string s when long.TryParse(s, out var parsed) => parsed,
                _ => -1
            };
        }
    }
}
