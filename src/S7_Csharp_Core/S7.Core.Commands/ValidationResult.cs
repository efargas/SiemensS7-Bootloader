using System;
using System.Collections.Generic;
using System.Linq;

namespace S7.Core.Commands
{
    /// <summary>
    /// Represents the result of a validation operation.
    /// </summary>
    public class ValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the validation was successful.
        /// </summary>
        public bool IsValid { get; private set; }

        /// <summary>
        /// Gets the validation error message.
        /// </summary>
        public string? ErrorMessage { get; private set; }

        /// <summary>
        /// Gets the collection of validation errors.
        /// </summary>
        public IReadOnlyList<string> Errors { get; private set; } = Array.Empty<string>();

        private ValidationResult() { }

        /// <summary>
        /// Creates a successful validation result.
        /// </summary>
        /// <returns>A successful validation result</returns>
        public static ValidationResult Success()
        {
            return new ValidationResult
            {
                IsValid = true
            };
        }

        /// <summary>
        /// Creates a failed validation result with a single error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <returns>A failed validation result</returns>
        public static ValidationResult Failure(string errorMessage)
        {
            return new ValidationResult
            {
                IsValid = false,
                ErrorMessage = errorMessage ?? throw new ArgumentNullException(nameof(errorMessage)),
                Errors = new[] { errorMessage }.AsReadOnly()
            };
        }

        /// <summary>
        /// Creates a failed validation result with multiple error messages.
        /// </summary>
        /// <param name="errors">The collection of error messages</param>
        /// <returns>A failed validation result</returns>
        public static ValidationResult Failure(IEnumerable<string> errors)
        {
            var errorList = errors?.ToList() ?? throw new ArgumentNullException(nameof(errors));
            
            if (!errorList.Any())
                throw new ArgumentException("At least one error must be provided", nameof(errors));

            return new ValidationResult
            {
                IsValid = false,
                ErrorMessage = string.Join("; ", errorList),
                Errors = errorList.AsReadOnly()
            };
        }
    }
}