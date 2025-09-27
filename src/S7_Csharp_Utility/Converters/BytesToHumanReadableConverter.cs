using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Converts a byte value into a human-readable string (e.g., KB, MB, GB).
    /// </summary>
    public class BytesToHumanReadableConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                if (bytes < 1024) return $"{bytes} B";
                if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
                if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
                return $"{bytes / (1024.0 * 1024.0 * 1024.0):F1} GB";
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}