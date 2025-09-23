using System;
using System.Globalization;
using System.Collections.Generic;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace S7_Csharp_Utility.Converters
{
    public sealed class SearchResultHighlightConverter : IMultiValueConverter
    {
        private static readonly IBrush HighlightBrush = new SolidColorBrush(Colors.Yellow);
        private static readonly IBrush TransparentBrush = Brushes.Transparent;

        public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
        {
            if (values.Count < 3 || values[0] is not long offset || values[1] is not System.Collections.ObjectModel.ObservableCollection<Models.SearchResult> searchResults || values[2] is not int patternLength)
            {
                return TransparentBrush;
            }

            foreach (var result in searchResults)
            {
                if (offset >= result.Offset && offset < result.Offset + patternLength)
                {
                    return HighlightBrush;
                }
            }

            return TransparentBrush;
        }
    }
}
