using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using S7_Csharp_Utility.Services;

namespace S7_Csharp_Utility.Converters
{
    public class LogCategoryToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is LogCategory category)
            {
                switch (category)
                {
                    case LogCategory.Info:
                        return Brushes.LightGreen;
                    case LogCategory.Warning:
                        return Brushes.Yellow;
                    case LogCategory.Error:
                        return Brushes.Red;
                    case LogCategory.Debug:
                        return Brushes.LightBlue;
                    default:
                        return Brushes.White;
                }
            }
            return Brushes.White;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
