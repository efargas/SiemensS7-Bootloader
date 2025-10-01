using Avalonia.Data.Converters;
using Avalonia.Media;
using System;
using System.Globalization;
using DiffPlex.DiffBuilder.Model;

namespace S7_Csharp_Utility.Converters
{
    public class DiffLineTypeToBrushConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is ChangeType changeType)
            {
                return changeType switch
                {
                    ChangeType.Inserted => Brushes.DarkGreen,
                    ChangeType.Deleted => Brushes.DarkRed,
                    _ => Brushes.Transparent,
                };
            }
            return Brushes.Transparent;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
