using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using Avalonia.Data.Converters;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Converts validation errors to a boolean visibility value.
    /// Implements the Open/Closed Principle by being extensible for different visibility logic.
    /// Follows defensive programming by handling all edge cases gracefully.
    /// </summary>
    public sealed class ValidationErrorVisibilityConverter : IValueConverter
    {
        /// <summary>
        /// Converts validation errors to a boolean indicating whether errors should be visible.
        /// </summary>
        /// <param name="value">The validation errors collection</param>
        /// <param name="targetType">The target type (should be bool)</param>
        /// <param name="parameter">Optional parameter for inversion logic</param>
        /// <param name="culture">The culture for conversion</param>
        /// <returns>True if errors exist and should be shown, false otherwise</returns>
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool hasErrors = HasValidationErrors(value);
            
            // Support inversion through parameter
            bool invert = parameter?.ToString()?.ToLowerInvariant() == "invert";
            
            return invert ? !hasErrors : hasErrors;
        }

        /// <summary>
        /// Not implemented as this is a one-way converter.
        /// </summary>
        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotSupportedException("ValidationErrorVisibilityConverter is a one-way converter.");
        }

        /// <summary>
        /// Determines if the given value represents validation errors.
        /// Uses defensive programming to handle all possible input types safely.
        /// </summary>
        /// <param name="value">The value to check for errors</param>
        /// <returns>True if validation errors exist, false otherwise</returns>
        private static bool HasValidationErrors(object? value)
        {
            if (value == null)
                return false;

            // Handle boolean values
            if (value is bool boolValue)
                return boolValue;

            // Handle string values
            if (value is string stringValue)
                return !string.IsNullOrWhiteSpace(stringValue);

            // Handle integer values
            if (value is int intValue)
                return intValue > 0;

            // Handle enumerable collections
            if (value is IEnumerable enumerable)
            {
                try
                {
                    return enumerable.Cast<object>()
                        .Any(error => error != null && !string.IsNullOrWhiteSpace(error.ToString()));
                }
                catch
                {
                    // Defensive: if enumeration fails, assume no errors
                    return false;
                }
            }

            // For unknown types, check if it's not null
            return true;
        }
    }
}