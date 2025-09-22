using System;
using System.Globalization;
using System.Collections.Generic;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Multi-value converter that returns a highlight brush for selected bytes.
    /// Supports both single selection and range selection highlighting.
    /// </summary>
    public sealed class SelectionHighlightConverter : IMultiValueConverter
    {
        private static readonly IBrush PrimarySelection = new SolidColorBrush(Color.FromRgb(0x4C, 0x51, 0xBF)); // Indigo-600
        private static readonly IBrush RangeSelection = new SolidColorBrush(Color.FromRgb(0x6B, 0x73, 0xFF)); // Indigo-400
        private static readonly IBrush Transparent = Brushes.Transparent;

        public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
        {
            if (values == null || values.Count < 4)
                return Transparent;

            try
            {
                var cellOffset = ToLong(values[0]);
                var selectedOffset = ToLong(values[1]);
                var selectionStart = ToLong(values[2]);
                var selectionEnd = ToLong(values[3]);

                if (cellOffset < 0) return Transparent;

                // Check if this offset is within the selection range first
                if (selectionStart >= 0 && selectionEnd >= 0)
                {
                    var start = Math.Min(selectionStart, selectionEnd);
                    var end = Math.Max(selectionStart, selectionEnd);
                    if (cellOffset >= start && cellOffset <= end)
                    {
                        // If this is also the primary selected offset, use primary color
                        if (cellOffset == selectedOffset)
                        {
                            return PrimarySelection;
                        }
                        // Otherwise use range selection color
                        return RangeSelection;
                    }
                }

                // Check if this is the primary selected offset (but not in a range)
                if (cellOffset == selectedOffset)
                {
                    return PrimarySelection;
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