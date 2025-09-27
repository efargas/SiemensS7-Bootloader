using System;
using System.Collections;
using System.Globalization;
using System.Linq;
using Avalonia.Data.Converters;

namespace S7_Csharp_Utility.Converters
{
    /// <summary>
    /// Converts validation errors to a user-friendly display format.
    /// Implements defensive programming principles to handle null/empty collections gracefully.
    /// Follows the Single Responsibility Principle by focusing solely on error message formatting.
    /// </summary>
    public sealed class ValidationErrorConverter : IValueConverter
    {
        /// <summary>
        /// Converts validation errors to a formatted error message string.
        /// </summary>
        /// <param name="value">The validation errors collection</param>
        /// <param name="targetType">The target type (should be string)</param>
        /// <param name="parameter">Optional parameter for formatting options</param>
        /// <param name="culture">The culture for formatting</param>
        /// <returns>A formatted error message or empty string if no errors</returns>
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            // Defensive programming: Handle null input gracefully
            if (value == null)
                return string.Empty;

            // Handle string values first (more specific)
            if (value is string errorString && !string.IsNullOrWhiteSpace(errorString))
            {
                return errorString;
            }

            // Handle enumerable collections
            if (value is IEnumerable enumerable)
            {
                var errors = enumerable.Cast<object>()
                    .Where(error => error != null)
                    .Select(error => error.ToString())
                    .Where(errorText => !string.IsNullOrWhiteSpace(errorText))
                    .ToList();

                if (!errors.Any())
                    return string.Empty;

                // Format based on parameter
                var formatOption = parameter?.ToString()?.ToLowerInvariant();
                return formatOption switch
                {
                    "first" => errors.First(),
                    "count" => $"{errors.Count} error(s)",
                    "all" => string.Join("; ", errors),
                    _ => errors.First() // Default: show first error
                };
            }

            return string.Empty;
        }

        /// <summary>
        /// Not implemented as this is a one-way converter.
        /// </summary>
        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            throw new NotSupportedException("ValidationErrorConverter is a one-way converter.");
        }
    }
}