#nullable enable
using System;
using System.ComponentModel;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Event arguments for validation state changes.
    /// </summary>
    public class ValidationStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the key of the validator that caused the state change.
        /// </summary>
        public string ValidatorKey { get; }

        /// <summary>
        /// Gets a value indicating whether the validator has validation errors.
        /// </summary>
        public bool HasErrors { get; }

        /// <summary>
        /// Gets the total number of validation errors across all validators.
        /// </summary>
        public int TotalErrorCount { get; }

        /// <summary>
        /// Gets the validation summary message.
        /// </summary>
        public string ValidationSummary { get; }

        /// <summary>
        /// Initializes a new instance of the ValidationStateChangedEventArgs class.
        /// </summary>
        /// <param name="validatorKey">The key of the validator that caused the state change.</param>
        /// <param name="hasErrors">True if the validator has validation errors.</param>
        /// <param name="totalErrorCount">The total number of validation errors across all validators.</param>
        /// <param name="validationSummary">The validation summary message.</param>
        public ValidationStateChangedEventArgs(string validatorKey, bool hasErrors, int totalErrorCount, string validationSummary)
        {
            ValidatorKey = validatorKey ?? throw new ArgumentNullException(nameof(validatorKey));
            HasErrors = hasErrors;
            TotalErrorCount = totalErrorCount;
            ValidationSummary = validationSummary ?? string.Empty;
        }
    }

    /// <summary>
    /// Service for coordinating validation across multiple ViewModels and providing
    /// centralized validation state management for the application.
    /// </summary>
    public interface IValidationCoordinatorService
    {
        /// <summary>
        /// Gets a value indicating whether any registered validator has validation errors.
        /// </summary>
        bool HasValidationErrors { get; }

        /// <summary>
        /// Gets a summary of all validation errors across registered validators.
        /// </summary>
        string ValidationSummary { get; }

        /// <summary>
        /// Gets the total number of validation errors across all registered validators.
        /// </summary>
        int TotalErrorCount { get; }

        /// <summary>
        /// Occurs when the validation state changes for any registered validator.
        /// </summary>
        event EventHandler<ValidationStateChangedEventArgs>? ValidationStateChanged;

        /// <summary>
        /// Registers a validator with the coordination service.
        /// The validator must implement INotifyDataErrorInfo to provide validation state.
        /// </summary>
        /// <param name="key">A unique key identifying the validator.</param>
        /// <param name="validator">The validator instance that implements INotifyDataErrorInfo.</param>
        /// <exception cref="ArgumentException">Thrown when key is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when validator is null.</exception>
        void RegisterValidator(string key, INotifyDataErrorInfo validator);

        /// <summary>
        /// Unregisters a previously registered validator from the coordination service.
        /// </summary>
        /// <param name="key">The unique key of the validator to unregister.</param>
        /// <exception cref="ArgumentException">Thrown when key is null or whitespace.</exception>
        void UnregisterValidator(string key);

        /// <summary>
        /// Refreshes the validation state by re-evaluating all registered validators.
        /// This method should be called when validation state may have changed
        /// but the ErrorsChanged event was not raised.
        /// </summary>
        void RefreshValidationState();

        /// <summary>
        /// Gets validation errors for a specific validator.
        /// </summary>
        /// <param name="validatorKey">The key of the validator.</param>
        /// <returns>A formatted string containing all validation errors for the validator, or empty string if no errors.</returns>
        string GetValidationErrors(string validatorKey);

        /// <summary>
        /// Gets a value indicating whether a specific validator has validation errors.
        /// </summary>
        /// <param name="validatorKey">The key of the validator.</param>
        /// <returns>True if the validator has errors; otherwise, false.</returns>
        bool HasValidationErrorsForValidator(string validatorKey);
    }
}