using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Converts a TimeSpan value into a formatted HH:MM:SS string.
    /// </summary>
    public class TimeSpanToHmsConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is TimeSpan timeSpan)
            {
                return $"{(int)timeSpan.TotalHours:D2}:{timeSpan.Minutes:D2}:{timeSpan.Seconds:D2}";
            }
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}