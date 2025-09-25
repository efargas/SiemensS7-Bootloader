using System.Collections.Generic;

namespace S7.Core.Abstractions.Validation
{
    /// <summary>
    /// Represents the result of a validation operation.
    /// </summary>
    public class ValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the validation was successful.
        /// </summary>
        public bool IsValid { get; init; }

        /// <summary>
        /// Gets the validation error messages.
        /// </summary>
        public IReadOnlyList<string> Errors { get; init; } = new List<string>();

        /// <summary>
        /// Gets the first error message, or null if validation was successful.
        /// </summary>
        public string? ErrorMessage => Errors.Count > 0 ? Errors[0] : null;

        /// <summary>
        /// Creates a successful validation result.
        /// </summary>
        /// <returns>A successful validation result</returns>
        public static ValidationResult Success()
        {
            return new ValidationResult { IsValid = true };
        }

        /// <summary>
        /// Creates a failed validation result with error messages.
        /// </summary>
        /// <param name="errors">The validation error messages</param>
        /// <returns>A failed validation result</returns>
        public static ValidationResult Failure(IEnumerable<string> errors)
        {
            return new ValidationResult 
            { 
                IsValid = false, 
                Errors = new List<string>(errors) 
            };
        }

        /// <summary>
        /// Creates a failed validation result with a single error message.
        /// </summary>
        /// <param name="error">The validation error message</param>
        /// <returns>A failed validation result</returns>
        public static ValidationResult Failure(string error)
        {
            return new ValidationResult 
            { 
                IsValid = false, 
                Errors = new List<string> { error } 
            };
        }
    }

    /// <summary>
    /// Defines a contract for validating objects of a specific type.
    /// </summary>
    /// <typeparam name="T">The type of object to validate</typeparam>
    public interface IValidator<in T>
    {
        /// <summary>
        /// Validates the specified object.
        /// </summary>
        /// <param name="instance">The object to validate</param>
        /// <returns>A validation result indicating success or failure</returns>
        ValidationResult Validate(T instance);
    }
}