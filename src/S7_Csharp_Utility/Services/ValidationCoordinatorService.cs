#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Implementation of IValidationCoordinatorService that provides centralized validation
    /// coordination across multiple ViewModels. This service is thread-safe and designed
    /// to be used as a singleton.
    /// </summary>
    public class ValidationCoordinatorService : IValidationCoordinatorService
    {
        private readonly ILogger<ValidationCoordinatorService> _logger;
        private readonly ConcurrentDictionary<string, INotifyDataErrorInfo> _validators;
        private readonly ConcurrentDictionary<string, List<string>> _validationErrors;
        private readonly object _eventLock = new object();

        /// <summary>
        /// Initializes a new instance of the ValidationCoordinatorService class.
        /// </summary>
        /// <param name="logger">The logger instance for this service.</param>
        /// <exception cref="ArgumentNullException">Thrown when logger is null.</exception>
        public ValidationCoordinatorService(ILogger<ValidationCoordinatorService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _validators = new ConcurrentDictionary<string, INotifyDataErrorInfo>();
            _validationErrors = new ConcurrentDictionary<string, List<string>>();

            _logger.LogDebug("ValidationCoordinatorService initialized");
        }

        /// <inheritdoc />
        public bool HasValidationErrors => _validationErrors.Any(kvp => kvp.Value.Any());

        /// <inheritdoc />
        public string ValidationSummary
        {
            get
            {
                var allErrors = GetAllValidationErrors();
                if (!allErrors.Any())
                    return string.Empty;

                var errorCount = allErrors.Count;
                var summary = new StringBuilder();
                summary.Append($"⚠️ {errorCount} validation error(s): ");
                summary.Append(string.Join("; ", allErrors.Take(3))); // Show first 3 errors

                if (errorCount > 3)
                {
                    summary.Append($" and {errorCount - 3} more...");
                }

                return summary.ToString();
            }
        }

        /// <inheritdoc />
        public int TotalErrorCount => GetAllValidationErrors().Count;

        /// <inheritdoc />
        public event EventHandler<ValidationStateChangedEventArgs>? ValidationStateChanged;

        /// <inheritdoc />
        public void RegisterValidator(string key, INotifyDataErrorInfo validator)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            if (validator == null)
                throw new ArgumentNullException(nameof(validator));

            _logger.LogDebug("Registering validator: {Key}", key);

            // Unregister existing validator if present
            if (_validators.ContainsKey(key))
            {
                UnregisterValidator(key);
            }

            // Register the new validator
            _validators.TryAdd(key, validator);

            // Subscribe to validation events
            validator.ErrorsChanged += (sender, args) => OnValidatorErrorsChanged(key, args);

            // Initialize validation state
            UpdateValidationState(key, validator);

            _logger.LogDebug("Successfully registered validator: {Key}", key);
        }

        /// <inheritdoc />
        public void UnregisterValidator(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            _logger.LogDebug("Unregistering validator: {Key}", key);

            if (_validators.TryRemove(key, out var validator))
            {
                // Unsubscribe from validation events
                validator.ErrorsChanged -= (sender, args) => OnValidatorErrorsChanged(key, args);

                // Remove validation errors
                _validationErrors.TryRemove(key, out _);

                // Notify state change
                RaiseValidationStateChanged(key, false, TotalErrorCount, ValidationSummary);

                _logger.LogDebug("Successfully unregistered validator: {Key}", key);
            }
            else
            {
                _logger.LogWarning("Attempted to unregister non-existent validator: {Key}", key);
            }
        }

        /// <inheritdoc />
        public void RefreshValidationState()
        {
            _logger.LogDebug("Refreshing validation state for all validators");

            foreach (var kvp in _validators)
            {
                try
                {
                    UpdateValidationState(kvp.Key, kvp.Value);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error refreshing validation state for validator: {Key}", kvp.Key);
                }
            }

            _logger.LogDebug("Validation state refresh completed");
        }

        /// <inheritdoc />
        public string GetValidationErrors(string validatorKey)
        {
            if (string.IsNullOrWhiteSpace(validatorKey))
                return string.Empty;

            if (_validationErrors.TryGetValue(validatorKey, out var errors) && errors.Any())
            {
                return string.Join(Environment.NewLine, errors);
            }

            return string.Empty;
        }

        /// <inheritdoc />
        public bool HasValidationErrorsForValidator(string validatorKey)
        {
            if (string.IsNullOrWhiteSpace(validatorKey))
                return false;

            return _validationErrors.TryGetValue(validatorKey, out var errors) && errors.Any();
        }

        /// <summary>
        /// Handles the ErrorsChanged event from registered validators.
        /// </summary>
        /// <param name="validatorKey">The key of the validator that raised the event.</param>
        /// <param name="args">The event arguments.</param>
        private void OnValidatorErrorsChanged(string validatorKey, DataErrorsChangedEventArgs args)
        {
            try
            {
                if (_validators.TryGetValue(validatorKey, out var validator))
                {
                    UpdateValidationState(validatorKey, validator);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error handling validation errors changed for validator: {Key}", validatorKey);
            }
        }

        /// <summary>
        /// Updates the validation state for a specific validator.
        /// </summary>
        /// <param name="validatorKey">The key of the validator.</param>
        /// <param name="validator">The validator instance.</param>
        private void UpdateValidationState(string validatorKey, INotifyDataErrorInfo validator)
        {
            var errors = new List<string>();

            try
            {
                // Get all validation errors from the validator
                if (validator.HasErrors)
                {
                    // Try to get errors for all properties (pass null or empty string)
                    var allErrors = validator.GetErrors(null);
                    if (allErrors != null)
                    {
                        foreach (var error in allErrors)
                        {
                            if (error != null)
                            {
                                errors.Add(error.ToString() ?? string.Empty);
                            }
                        }
                    }

                    // Also try to get errors for specific properties if the validator supports it
                    // This is a best-effort approach since we don't know the property names
                    if (!errors.Any())
                    {
                        // If no errors found with null, the validator might require property names
                        // In this case, we'll just indicate that errors exist
                        errors.Add("Validation errors exist");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving validation errors from validator: {Key}", validatorKey);
                errors.Add($"Error retrieving validation state: {ex.Message}");
            }

            // Update the errors collection
            _validationErrors.AddOrUpdate(validatorKey, errors, (key, oldErrors) => errors);

            // Raise state changed event
            var hasErrors = errors.Any();
            RaiseValidationStateChanged(validatorKey, hasErrors, TotalErrorCount, ValidationSummary);

            _logger.LogDebug("Updated validation state for {Key}: {ErrorCount} errors", validatorKey, errors.Count);
        }

        /// <summary>
        /// Gets all validation errors from all registered validators.
        /// </summary>
        /// <returns>A list of all validation error messages.</returns>
        private List<string> GetAllValidationErrors()
        {
            var allErrors = new List<string>();

            foreach (var kvp in _validationErrors)
            {
                allErrors.AddRange(kvp.Value);
            }

            return allErrors;
        }

        /// <summary>
        /// Raises the ValidationStateChanged event in a thread-safe manner.
        /// </summary>
        /// <param name="validatorKey">The key of the validator that caused the state change.</param>
        /// <param name="hasErrors">True if the validator has validation errors.</param>
        /// <param name="totalErrorCount">The total number of validation errors across all validators.</param>
        /// <param name="validationSummary">The validation summary message.</param>
        private void RaiseValidationStateChanged(string validatorKey, bool hasErrors, int totalErrorCount, string validationSummary)
        {
            try
            {
                lock (_eventLock)
                {
                    var args = new ValidationStateChangedEventArgs(
                        validatorKey,
                        hasErrors,
                        totalErrorCount,
                        validationSummary);

                    ValidationStateChanged?.Invoke(this, args);

                    _logger.LogDebug("Validation state changed event raised for validator: {Key}, HasErrors: {HasErrors}, TotalErrors: {TotalErrors}",
                        validatorKey, hasErrors, totalErrorCount);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error raising ValidationStateChanged event for validator: {Key}", validatorKey);
            }
        }
    }
}