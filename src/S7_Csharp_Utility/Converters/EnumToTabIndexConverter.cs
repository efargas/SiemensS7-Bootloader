
using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace S7_Csharp_Utility.Converters
{
    public class EnumToTabIndexConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is Enum)
            {
                return (int)value;
            }
            return 0;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is int && targetType.IsEnum)
            {
                return Enum.ToObject(targetType, value);
            }
            return null;
        }
    }
}
