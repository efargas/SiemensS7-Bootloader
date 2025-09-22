using System;
using System.Globalization;
using System.Resources;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for managing localized resources and messages.
    /// Provides centralized access to resource strings with fallback support.
    /// </summary>
    public sealed class ResourceManagerService
    {
        private readonly ResourceManager _logMessagesResourceManager;
        private readonly ResourceManager _errorMessagesResourceManager;

        /// <summary>
        /// Initializes a new instance of the <see cref="ResourceManagerService"/> class.
        /// </summary>
        public ResourceManagerService()
        {
            // Initialize resource managers for different resource types
            // These would typically point to .resx files in the project
            _logMessagesResourceManager = new ResourceManager("S7_Csharp_Utility.Resources.LogMessages", typeof(ResourceManagerService).Assembly);
            _errorMessagesResourceManager = new ResourceManager("S7_Csharp_Utility.Resources.ErrorMessages", typeof(ResourceManagerService).Assembly);
        }

        /// <summary>
        /// Gets a localized log message string by key.
        /// </summary>
        /// <param name="key">The resource key.</param>
        /// <param name="culture">The culture to use for localization. If null, uses current culture.</param>
        /// <returns>The localized message string, or the key if not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public string GetLogMessage(string key, CultureInfo? culture = null)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var message = _logMessagesResourceManager.GetString(key, culture ?? CultureInfo.CurrentCulture);
                return message ?? key; // Return key as fallback if resource not found
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to get log message for key '{key}': {ex.Message}");
                return key; // Return key as fallback on error
            }
        }

        /// <summary>
        /// Gets a localized error message string by key.
        /// </summary>
        /// <param name="key">The resource key.</param>
        /// <param name="culture">The culture to use for localization. If null, uses current culture.</param>
        /// <returns>The localized error message string, or the key if not found.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public string GetErrorMessage(string key, CultureInfo? culture = null)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var message = _errorMessagesResourceManager.GetString(key, culture ?? CultureInfo.CurrentCulture);
                return message ?? key; // Return key as fallback if resource not found
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to get error message for key '{key}': {ex.Message}");
                return key; // Return key as fallback on error
            }
        }

        /// <summary>
        /// Gets a formatted localized log message string by key with parameters.
        /// </summary>
        /// <param name="key">The resource key.</param>
        /// <param name="args">The format arguments.</param>
        /// <returns>The formatted localized message string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public string GetFormattedLogMessage(string key, params object[] args)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var template = GetLogMessage(key);
                return args.Length > 0 ? string.Format(template, args) : template;
            }
            catch (FormatException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to format log message for key '{key}': {ex.Message}");
                return $"{key} [{string.Join(", ", args)}]"; // Return key with args as fallback
            }
        }

        /// <summary>
        /// Gets a formatted localized error message string by key with parameters.
        /// </summary>
        /// <param name="key">The resource key.</param>
        /// <param name="args">The format arguments.</param>
        /// <returns>The formatted localized error message string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public string GetFormattedErrorMessage(string key, params object[] args)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var template = GetErrorMessage(key);
                return args.Length > 0 ? string.Format(template, args) : template;
            }
            catch (FormatException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to format error message for key '{key}': {ex.Message}");
                return $"{key} [{string.Join(", ", args)}]"; // Return key with args as fallback
            }
        }

        /// <summary>
        /// Checks if a resource key exists in the log messages.
        /// </summary>
        /// <param name="key">The resource key to check.</param>
        /// <param name="culture">The culture to check. If null, uses current culture.</param>
        /// <returns>True if the key exists, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public bool LogMessageExists(string key, CultureInfo? culture = null)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var message = _logMessagesResourceManager.GetString(key, culture ?? CultureInfo.CurrentCulture);
                return message != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a resource key exists in the error messages.
        /// </summary>
        /// <param name="key">The resource key to check.</param>
        /// <param name="culture">The culture to check. If null, uses current culture.</param>
        /// <returns>True if the key exists, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when key is null.</exception>
        public bool ErrorMessageExists(string key, CultureInfo? culture = null)
        {
            ArgumentNullException.ThrowIfNull(key);

            try
            {
                var message = _errorMessagesResourceManager.GetString(key, culture ?? CultureInfo.CurrentCulture);
                return message != null;
            }
            catch
            {
                return false;
            }
        }
    }
}