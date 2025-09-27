using System;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

namespace S7.Core.Abstractions.Validation
{
    /// <summary>
    /// Validates that a string represents a valid hexadecimal address.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
    public sealed class HexAddressAttribute : ValidationAttribute
    {
        private static readonly Regex HexAddressRegex = new(@"^0x[0-9a-fA-F]{1,8}$", RegexOptions.Compiled);

        /// <summary>
        /// Gets or sets whether the address can be null or empty.
        /// </summary>
        public bool AllowEmpty { get; set; }

        /// <summary>
        /// Gets or sets the minimum value for the hex address.
        /// </summary>
        public uint MinValue { get; set; }

        /// <summary>
        /// Gets or sets the maximum value for the hex address.
        /// </summary>
        public uint MaxValue { get; set; } = uint.MaxValue;

        /// <summary>
        /// Initializes a new instance of the <see cref="HexAddressAttribute"/> class.
        /// </summary>
        public HexAddressAttribute()
        {
            ErrorMessage = "The {0} field must be a valid hexadecimal address (e.g., 0x1000).";
        }

        /// <summary>
        /// Validates the specified value with respect to the current validation attribute.
        /// </summary>
        /// <param name="value">The value to validate.</param>
        /// <param name="validationContext">The context information about the validation operation.</param>
        /// <returns>An instance of the <see cref="System.ComponentModel.DataAnnotations.ValidationResult"/> class.</returns>
        protected override System.ComponentModel.DataAnnotations.ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null || (value is string str && string.IsNullOrWhiteSpace(str)))
            {
                return AllowEmpty ? System.ComponentModel.DataAnnotations.ValidationResult.Success : new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            if (value is not string hexString)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            if (!HexAddressRegex.IsMatch(hexString))
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            // Parse the hex value and check range
            if (uint.TryParse(hexString[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint hexValue))
            {
                if (hexValue < MinValue || hexValue > MaxValue)
                {
                    return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must be between 0x{MinValue:X} and 0x{MaxValue:X}.");
                }
            }
            else
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            return System.ComponentModel.DataAnnotations.ValidationResult.Success;
        }
    }

    /// <summary>
    /// Validates that a string represents a valid file path.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
    public sealed class FilePathAttribute : ValidationAttribute
    {
        /// <summary>
        /// Gets or sets whether the file must exist.
        /// </summary>
        public bool MustExist { get; set; } = true;

        /// <summary>
        /// Gets or sets whether directories are allowed.
        /// </summary>
        public bool AllowDirectories { get; set; }

        /// <summary>
        /// Gets or sets the allowed file extensions (without the dot).
        /// </summary>
        public string[]? AllowedExtensions { get; set; }

        /// <summary>
        /// Gets or sets whether the path can be null or empty.
        /// </summary>
        public bool AllowEmpty { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FilePathAttribute"/> class.
        /// </summary>
        public FilePathAttribute()
        {
            ErrorMessage = "The {0} field must be a valid file path.";
        }

        /// <summary>
        /// Validates the specified value with respect to the current validation attribute.
        /// </summary>
        /// <param name="value">The value to validate.</param>
        /// <param name="validationContext">The context information about the validation operation.</param>
        /// <returns>An instance of the <see cref="System.ComponentModel.DataAnnotations.ValidationResult"/> class.</returns>
        protected override System.ComponentModel.DataAnnotations.ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null || (value is string str && string.IsNullOrWhiteSpace(str)))
            {
                return AllowEmpty ? System.ComponentModel.DataAnnotations.ValidationResult.Success : new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            if (value is not string filePath)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            try
            {
                // Check if path is valid
                var fullPath = Path.GetFullPath(filePath);

                if (MustExist)
                {
                    bool exists = File.Exists(fullPath) || (AllowDirectories && Directory.Exists(fullPath));
                    if (!exists)
                    {
                        return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must specify an existing {(AllowDirectories ? "file or directory" : "file")}.");
                    }
                }

                // Check file extension if specified
                if (AllowedExtensions != null && AllowedExtensions.Length > 0)
                {
                    var extension = Path.GetExtension(fullPath).TrimStart('.');
                    bool hasValidExtension = false;
                    
                    foreach (var allowedExt in AllowedExtensions)
                    {
                        if (string.Equals(extension, allowedExt, StringComparison.OrdinalIgnoreCase))
                        {
                            hasValidExtension = true;
                            break;
                        }
                    }

                    if (!hasValidExtension)
                    {
                        return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must have one of the following extensions: {string.Join(", ", AllowedExtensions)}.");
                    }
                }

                return System.ComponentModel.DataAnnotations.ValidationResult.Success;
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field contains an invalid path: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Validates that a string represents a valid network endpoint (host:port).
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
    public sealed class NetworkEndpointAttribute : ValidationAttribute
    {
        /// <summary>
        /// Gets or sets the minimum allowed port number.
        /// </summary>
        public int MinPort { get; set; } = 1;

        /// <summary>
        /// Gets or sets the maximum allowed port number.
        /// </summary>
        public int MaxPort { get; set; } = 65535;

        /// <summary>
        /// Gets or sets whether IP addresses are allowed.
        /// </summary>
        public bool AllowIpAddresses { get; set; } = true;

        /// <summary>
        /// Gets or sets whether hostnames are allowed.
        /// </summary>
        public bool AllowHostnames { get; set; } = true;

        /// <summary>
        /// Gets or sets whether the endpoint can be null or empty.
        /// </summary>
        public bool AllowEmpty { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="NetworkEndpointAttribute"/> class.
        /// </summary>
        public NetworkEndpointAttribute()
        {
            ErrorMessage = "The {0} field must be a valid network endpoint (host:port).";
        }

        /// <summary>
        /// Validates the specified value with respect to the current validation attribute.
        /// </summary>
        /// <param name="value">The value to validate.</param>
        /// <param name="validationContext">The context information about the validation operation.</param>
        /// <returns>An instance of the <see cref="System.ComponentModel.DataAnnotations.ValidationResult"/> class.</returns>
        protected override System.ComponentModel.DataAnnotations.ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null || (value is string str && string.IsNullOrWhiteSpace(str)))
            {
                return AllowEmpty ? System.ComponentModel.DataAnnotations.ValidationResult.Success : new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            if (value is not string endpoint)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(FormatErrorMessage(validationContext.DisplayName));
            }

            var parts = endpoint.Split(':');
            if (parts.Length != 2)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must be in the format 'host:port'.");
            }

            var host = parts[0].Trim();
            var portString = parts[1].Trim();

            // Validate host
            if (string.IsNullOrWhiteSpace(host))
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must specify a valid host.");
            }

            bool isValidHost = false;

            // Check if it's an IP address
            if (AllowIpAddresses && IPAddress.TryParse(host, out _))
            {
                isValidHost = true;
            }
            // Check if it's a hostname
            else if (AllowHostnames && IsValidHostname(host))
            {
                isValidHost = true;
            }

            if (!isValidHost)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must specify a valid {(AllowIpAddresses && AllowHostnames ? "IP address or hostname" : AllowIpAddresses ? "IP address" : "hostname")}.");
            }

            // Validate port
            if (!int.TryParse(portString, out int port) || port < MinPort || port > MaxPort)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must specify a valid port number between {MinPort} and {MaxPort}.");
            }

            return System.ComponentModel.DataAnnotations.ValidationResult.Success;
        }

        private static bool IsValidHostname(string hostname)
        {
            if (string.IsNullOrWhiteSpace(hostname) || hostname.Length > 253)
                return false;

            // Basic hostname validation
            var hostnameRegex = new Regex(@"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", RegexOptions.Compiled);
            return hostnameRegex.IsMatch(hostname);
        }
    }

    /// <summary>
    /// Validates that a numeric value is within a specified range and optionally aligned to a boundary.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
    public sealed class NumericRangeAttribute : ValidationAttribute
    {
        /// <summary>
        /// Gets or sets the minimum value.
        /// </summary>
        public long MinValue { get; set; }

        /// <summary>
        /// Gets or sets the maximum value.
        /// </summary>
        public long MaxValue { get; set; }

        /// <summary>
        /// Gets or sets the alignment boundary (value must be divisible by this number).
        /// </summary>
        public long Alignment { get; set; } = 1;

        /// <summary>
        /// Initializes a new instance of the <see cref="NumericRangeAttribute"/> class.
        /// </summary>
        /// <param name="minValue">The minimum value.</param>
        /// <param name="maxValue">The maximum value.</param>
        public NumericRangeAttribute(long minValue, long maxValue)
        {
            MinValue = minValue;
            MaxValue = maxValue;
            ErrorMessage = "The {0} field must be between {1} and {2}.";
        }

        /// <summary>
        /// Validates the specified value with respect to the current validation attribute.
        /// </summary>
        /// <param name="value">The value to validate.</param>
        /// <param name="validationContext">The context information about the validation operation.</param>
        /// <returns>An instance of the <see cref="System.ComponentModel.DataAnnotations.ValidationResult"/> class.</returns>
        protected override System.ComponentModel.DataAnnotations.ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null)
            {
                return System.ComponentModel.DataAnnotations.ValidationResult.Success; // Let Required attribute handle null values
            }

            long numericValue;
            try
            {
                numericValue = Convert.ToInt64(value);
            }
            catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must be a valid number.");
            }

            if (numericValue < MinValue || numericValue > MaxValue)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(string.Format(CultureInfo.InvariantCulture, ErrorMessage ?? "The {0} field must be between {1} and {2}.", validationContext.DisplayName, MinValue, MaxValue));
            }

            if (Alignment > 1 && numericValue % Alignment != 0)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must be aligned to {Alignment} (divisible by {Alignment}).");
            }

            return System.ComponentModel.DataAnnotations.ValidationResult.Success;
        }
    }

    /// <summary>
    /// Validates that a string represents a valid timeout value.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
    public sealed class TimeoutAttribute : ValidationAttribute
    {
        /// <summary>
        /// Gets or sets the minimum timeout in milliseconds.
        /// </summary>
        public int MinTimeoutMs { get; set; } = 100;

        /// <summary>
        /// Gets or sets the maximum timeout in milliseconds.
        /// </summary>
        public int MaxTimeoutMs { get; set; } = 300000; // 5 minutes

        /// <summary>
        /// Initializes a new instance of the <see cref="TimeoutAttribute"/> class.
        /// </summary>
        public TimeoutAttribute()
        {
            ErrorMessage = "The {0} field must be a valid timeout between {1}ms and {2}ms.";
        }

        /// <summary>
        /// Validates the specified value with respect to the current validation attribute.
        /// </summary>
        /// <param name="value">The value to validate.</param>
        /// <param name="validationContext">The context information about the validation operation.</param>
        /// <returns>An instance of the <see cref="System.ComponentModel.DataAnnotations.ValidationResult"/> class.</returns>
        protected override System.ComponentModel.DataAnnotations.ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null)
            {
                return System.ComponentModel.DataAnnotations.ValidationResult.Success; // Let Required attribute handle null values
            }

            int timeoutMs;
            if (value is TimeSpan timeSpan)
            {
                timeoutMs = (int)timeSpan.TotalMilliseconds;
            }
            else
            {
                try
                {
                    timeoutMs = Convert.ToInt32(value);
                }
                catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
                {
                    return new System.ComponentModel.DataAnnotations.ValidationResult($"The {validationContext.DisplayName} field must be a valid timeout value.");
                }
            }

            if (timeoutMs < MinTimeoutMs || timeoutMs > MaxTimeoutMs)
            {
                return new System.ComponentModel.DataAnnotations.ValidationResult(string.Format(CultureInfo.InvariantCulture, ErrorMessage ?? "The {0} field must be a valid timeout between {1}ms and {2}ms.", validationContext.DisplayName, MinTimeoutMs, MaxTimeoutMs));
            }

            return System.ComponentModel.DataAnnotations.ValidationResult.Success;
        }
    }
}